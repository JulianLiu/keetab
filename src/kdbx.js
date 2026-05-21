// KDBX decryption + entry walking + reference processing.
// Adapted from Tusk/services/keepassService.js and keepassReference.js
// (kdbxweb-based; works for KDBX3 and KDBX4 once Argon2 is wired).

import { ensureArgon2Wired } from './argon2-loader.js';

function camel(str) {
  return str
    .replace(/(?:^\w|[A-Z]|\b\w)/g, (letter, index) =>
      index === 0 ? letter.toLowerCase() : letter.toUpperCase()
    )
    .replace(/\s+/g, '');
}

function uuidToHex(uuidObj) {
  if (!uuidObj || !uuidObj.bytes) return '';
  const bytes = new Uint8Array(uuidObj.bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join('');
}

// Recursively walk groups -> entry list. Mirrors parseKdbxDb in
// Tusk/services/keepassService.js:173.
function flattenGroups(groups, breadcrumbs = []) {
  const results = [];
  for (const group of groups) {
    const path = breadcrumbs.concat([group.name]);
    if (group.groups && group.groups.length) {
      results.push(...flattenGroups(group.groups, path));
    }
    if (group.enableSearching === false) continue;
    for (const dbEntry of group.entries || []) {
      const entry = {
        id: uuidToHex(dbEntry.uuid),
        groupName: group.name,
        groupPath: path.join(' / '),
        keys: ['groupName', 'groupPath'],
        protectedData: {},
      };
      if (dbEntry.icon != null) entry.iconId = dbEntry.icon;
      if (dbEntry.tags && dbEntry.tags.length) {
        entry.tags = dbEntry.tags.join(',');
        entry.keys.push('tags');
      }
      if (dbEntry.fields) {
        for (const [key, field] of dbEntry.fields) {
          const ck = camel(key);
          if (field && typeof field === 'object' && typeof field.getText === 'function') {
            // ProtectedValue — keep as ProtectedValue instance
            entry.protectedData[ck] = field;
            entry.keys.push(ck); // expose the key so search can include it
          } else {
            entry[ck] = field;
            entry.keys.push(ck);
          }
        }
      }
      if (dbEntry.times && dbEntry.times.expires) {
        entry.expiry = dbEntry.times.expiryTime ? dbEntry.times.expiryTime.toISOString() : '';
        entry.is_expired = entry.expiry ? Date.parse(entry.expiry) < Date.now() : false;
        entry.keys.push('expiry');
      }
      results.push(entry);
    }
  }
  return results;
}

// Returns plaintext for a field, transparent over ProtectedValue.
export function readField(entry, fieldName) {
  if (entry.protectedData && fieldName in entry.protectedData) {
    return entry.protectedData[fieldName].getText();
  }
  return entry[fieldName] || '';
}

// ---- {REF:...} resolution (port of keepassReference.js) ---------------------

const FIELD_CODE = { T: 'title', U: 'userName', P: 'password', A: 'url', N: 'notes', I: 'id', O: '*' };

function hasRefs(value) {
  return !!value && /\{.+\}/.test(value);
}

function resolveReference(refText, currentEntry, allEntries) {
  const local = /^\{([a-zA-Z]+)\}$/.exec(refText);
  if (local) {
    switch (local[1].toUpperCase()) {
      case 'TITLE':    return readField(currentEntry, 'title');
      case 'USERNAME': return readField(currentEntry, 'userName');
      case 'URL':      return readField(currentEntry, 'url');
      case 'NOTES':    return readField(currentEntry, 'notes');
      case 'PASSWORD': return readField(currentEntry, 'password');
    }
  }
  const custom = /^\{S:([a-zA-Z0-9_ -]+)\}$/.exec(refText);
  if (custom) {
    return readField(currentEntry, camel(custom[1]));
  }
  const refMatch = /^\{REF:(T|U|P|A|N|I)@(T|U|P|A|N|I|O):(.+)\}$/.exec(refText);
  if (refMatch) {
    const wanted = FIELD_CODE[refMatch[1]];
    const searchIn = FIELD_CODE[refMatch[2]];
    const text = refMatch[3];
    const matches = allEntries.filter((e) => {
      if (searchIn === '*') {
        return e.keys.some((k) => String(readField(e, k) || '').indexOf(text) !== -1);
      } else if (searchIn === 'id') {
        return String(e.id).toLowerCase() === text.toLowerCase();
      } else {
        return String(readField(e, searchIn) || '').indexOf(text) !== -1;
      }
    });
    if (matches.length) return readField(matches[0], wanted);
  }
  return refText;
}

// References are resolved on-demand so plaintext never lingers in the entry.
export function resolveValue(entry, fieldName, allEntries) {
  let value = readField(entry, fieldName);
  if (!hasRefs(value)) return value;
  const re = /(\{[^{}]+\})/g;
  let m, last = 0, out = '';
  while ((m = re.exec(value)) !== null) {
    out += value.substring(last, m.index);
    out += resolveReference(m[1], entry, allEntries);
    last = m.index + m[1].length;
  }
  out += value.substring(last);
  return out;
}

// ---- Decrypt ----------------------------------------------------------------

export async function decryptKdbx(buffer, masterPassword) {
  const kdbxweb = globalThis.kdbxweb;
  if (!kdbxweb) throw new Error('kdbxweb not loaded');
  await ensureArgon2Wired();
  const creds = new kdbxweb.Credentials(
    kdbxweb.ProtectedValue.fromString(masterPassword || ''),
    null
  );
  await creds.ready;
  const db = await kdbxweb.Kdbx.load(buffer, creds);
  const entries = flattenGroups(db.groups);
  const versionMajor = db.header && db.header.versionMajor;
  const meta = {
    name: (db.meta && db.meta.name) || '',
    versionMajor,
  };
  return { entries, meta };
}

// ---- Serialize / deserialize for the AES cache -----------------------------
//
// After Argon2 unlock, we want to re-wrap the in-memory entries in AES-GCM
// so that other tabs (including strict-CSP ones where the Argon2 worker
// can't spawn) can adopt the unlocked state quickly.
//
// ProtectedValue instances need to be flattened to plaintext for JSON
// serialization, then rebuilt as ProtectedValue on the other side so that
// the rest of the codebase (readField, resolveValue, etc.) keeps working.

export function serializeEntries(entries) {
  return entries.map((entry) => {
    const out = { ...entry };
    delete out._idx; // transient field added by the panel
    if (entry.protectedData) {
      const pd = {};
      for (const [k, v] of Object.entries(entry.protectedData)) {
        if (v && typeof v.getText === 'function') {
          pd[k] = { __pv: 1, text: v.getText() };
        } else {
          pd[k] = v;
        }
      }
      out.protectedData = pd;
    }
    return out;
  });
}

export function deserializeEntries(arr) {
  const kdbxweb = globalThis.kdbxweb;
  if (!kdbxweb) throw new Error('kdbxweb not loaded');
  return arr.map((entry) => {
    const out = { ...entry };
    if (entry.protectedData) {
      const pd = {};
      for (const [k, v] of Object.entries(entry.protectedData)) {
        if (v && v.__pv === 1) {
          pd[k] = kdbxweb.ProtectedValue.fromString(v.text || '');
        } else {
          pd[k] = v;
        }
      }
      out.protectedData = pd;
    }
    return out;
  });
}
