// Thin wrappers around GM_* storage. Falls back to localStorage when GM_* is missing
// (e.g. dev preview without Tampermonkey).

const PREFIX = 'kpro.';

function gmGet(key, def) {
  if (typeof GM_getValue === 'function') return GM_getValue(PREFIX + key, def);
  const raw = localStorage.getItem(PREFIX + key);
  if (raw === null) return def;
  try { return JSON.parse(raw); } catch { return raw; }
}

function gmSet(key, val) {
  if (typeof GM_setValue === 'function') return GM_setValue(PREFIX + key, val);
  localStorage.setItem(PREFIX + key, typeof val === 'string' ? val : JSON.stringify(val));
}

function gmDel(key) {
  if (typeof GM_deleteValue === 'function') return GM_deleteValue(PREFIX + key);
  localStorage.removeItem(PREFIX + key);
}

// Cross-tab change notifications. GM_addValueChangeListener fires across all
// tabs (and origins) sharing the same userscript, which is exactly what we
// need for cross-origin session sync. Falls back to a localStorage 'storage'
// event listener for dev preview.
export function onValueChange(key, fn) {
  if (typeof GM_addValueChangeListener === 'function') {
    const id = GM_addValueChangeListener(PREFIX + key, (_name, oldVal, newVal, remote) => {
      fn(newVal, oldVal, remote);
    });
    return () => {
      try { GM_removeValueChangeListener(id); } catch { /* ignore */ }
    };
  }
  const handler = (e) => {
    if (e.key !== PREFIX + key) return;
    let nv = e.newValue;
    let ov = e.oldValue;
    try { nv = JSON.parse(nv); } catch { /* keep raw */ }
    try { ov = JSON.parse(ov); } catch { /* keep raw */ }
    fn(nv, ov, true);
  };
  window.addEventListener('storage', handler);
  return () => window.removeEventListener('storage', handler);
}

const DEFAULTS = {
  'cfg.url': '',
  'cfg.pollMinutes': 30,
  'cfg.idleLockMinutes': 15,
  'cfg.hotkey': 'Ctrl+Shift+K',
  'cfg.urlMatchMode': 'host',          // origin | host | hostname
  'cfg.clipboardClearSeconds': 20,
  'cfg.showFloatingButton': false,
  'cfg.basicUser': '',                 // HTTP Basic auth username (e.g. Nextcloud share token)
  'cfg.basicPassword': '',             // HTTP Basic auth password (empty if unprotected)
  'cache.kdbxBase64': '',
  'cache.etag': '',
  'cache.lastModified': '',
  'cache.fetchedAt': 0,
  'cache.sha256': '',
  'cache.sha256Notification': null,
  'cache.aesEntries': null,            // { v, salt, iv, ct, sourceSha256, meta } — entries re-wrapped in AES-GCM
  'session.masterPassword': '',
  'session.unlockedAt': 0,
  'session.lastActivity': 0,
  'leader.heartbeats': null,
};

export const config = {
  get(key) { return gmGet(key, DEFAULTS[key]); },
  set(key, value) { gmSet(key, value); },
  del(key) { gmDel(key); },
  all() {
    const o = {};
    for (const k of Object.keys(DEFAULTS)) o[k] = gmGet(k, DEFAULTS[k]);
    return o;
  },
  reset() {
    for (const k of Object.keys(DEFAULTS)) gmDel(k);
  },
};

// ---- Cache helpers ----------------------------------------------------------

export function getCachedKdbx() {
  const b64 = config.get('cache.kdbxBase64');
  if (!b64) return null;
  return base64ToArrayBuffer(b64);
}

export function setCachedKdbx(buf, headers, sha256) {
  config.set('cache.kdbxBase64', arrayBufferToBase64(buf));
  config.set('cache.etag', headers.etag || '');
  config.set('cache.lastModified', headers.lastModified || '');
  config.set('cache.fetchedAt', Date.now());
  config.set('cache.sha256', sha256 || '');
}

export function getCacheMeta() {
  return {
    etag: config.get('cache.etag'),
    lastModified: config.get('cache.lastModified'),
    fetchedAt: config.get('cache.fetchedAt'),
    sha256: config.get('cache.sha256'),
  };
}

// ---- base64 helpers ---------------------------------------------------------

export function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export async function sha256Hex(buf) {
  const digest = await crypto.subtle.digest('SHA-256', buf);
  const arr = Array.from(new Uint8Array(digest));
  return arr.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---- AES-GCM cache for decrypted entries -----------------------------------
//
// After the heavy Argon2 KDBX unlock, we re-wrap the decrypted entry list
// with AES-GCM and cache it. AES-GCM via Web Crypto's SubtleCrypto API is
// available everywhere (no `unsafe-eval` / Trusted Types CSP gate), so other
// tabs — including those on strict-CSP sites where Argon2 can't run — can
// adopt the unlocked state by AES-decrypting this cache instead of running
// Argon2 themselves.
//
// The AES key is derived from the master password via PBKDF2 (SHA-256, 200k
// iterations, ~50–150 ms in WebCrypto). The master password is already held
// in GM_setValue for cross-tab session sync, so deriving from it doesn't
// add new exposure; it does keep the cache format self-contained.

const AES_PBKDF2_ITERATIONS = 200_000;

async function deriveAesKey(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(password || ''), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: AES_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function aesEncryptString(plainText, password) {
  if (typeof plainText !== 'string') throw new Error('aesEncryptString: plainText must be string');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(password, salt);
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plainText));
  return {
    v: 1,
    salt: arrayBufferToBase64(salt.buffer),
    iv: arrayBufferToBase64(iv.buffer),
    ct: arrayBufferToBase64(ct),
  };
}

export async function aesDecryptString(blob, password) {
  if (!blob || typeof blob !== 'object') throw new Error('aesDecryptString: blob missing');
  const salt = new Uint8Array(base64ToArrayBuffer(blob.salt));
  const iv = new Uint8Array(base64ToArrayBuffer(blob.iv));
  const ct = base64ToArrayBuffer(blob.ct);
  const key = await deriveAesKey(password, salt);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}
