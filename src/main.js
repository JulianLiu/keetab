// Userscript entrypoint. Wires storage, sync, session and UI together.

import { config, getCachedKdbx, base64ToArrayBuffer, aesEncryptString, aesDecryptString } from './storage.js';
import * as session from './session.js';
import { syncOnce, looksLikeKdbx, bufferPreview } from './sync.js';
import { decryptKdbx, serializeEntries, deserializeEntries } from './kdbx.js';
import * as panel from './ui/panel.js';

function gmNotify(text, title) {
  if (typeof GM_notification === 'function') {
    try { GM_notification({ text, title: title || 'KeePass', timeout: 5000 }); return; } catch {}
  }
  console.log('[KeePass]', title || '', text);
}

// ---- AES cache management ---------------------------------------------------
//
// After a successful Argon2 unlock, we re-wrap the entries in AES-GCM so any
// tab — including strict-CSP ones — can adopt the unlocked state without
// running Argon2. The cache is keyed to the SHA-256 of the source KDBX, so
// it's automatically invalidated when sync brings new bytes.

async function populateAesCache(entries, meta, password) {
  try {
    const sourceSha256 = String(config.get('cache.sha256') || '');
    if (!sourceSha256) return;
    const serialized = serializeEntries(entries);
    const blob = await aesEncryptString(JSON.stringify(serialized), password);
    blob.sourceSha256 = sourceSha256;
    blob.meta = meta;
    config.set('cache.aesEntries', blob);
  } catch (e) {
    console.warn('[KeePass] populateAesCache failed', e);
  }
}

async function tryAesCacheAdoption(password) {
  const blob = config.get('cache.aesEntries');
  if (!blob || typeof blob !== 'object') return null;
  const currentSha = String(config.get('cache.sha256') || '');
  if (!blob.sourceSha256 || blob.sourceSha256 !== currentSha) return null;
  try {
    const json = await aesDecryptString(blob, password);
    const arr = JSON.parse(json);
    const entries = deserializeEntries(arr);
    const meta = blob.meta || { name: '', versionMajor: 4 };
    return { entries, meta };
  } catch (e) {
    // Wrong password (different from the one that populated the cache),
    // tampered blob, or stale format — fall back to the slow path.
    console.warn('[KeePass] AES cache decrypt failed; falling back to argon2', e);
    return null;
  }
}

function clearAesCache() {
  config.set('cache.aesEntries', null);
}

// ---- Unlock flow ------------------------------------------------------------

async function unlockWithPassword(masterPassword) {
  let buffer = getCachedKdbx();
  // If the cached bytes don't even look like a KDBX file (e.g. an older cache
  // that stored an HTML login page), force a fresh download.
  if (buffer && !looksLikeKdbx(buffer)) {
    console.warn('[KeePass] cached bytes are not KDBX; refetching. Preview:',
      bufferPreview(buffer));
    buffer = null;
  }
  if (!buffer) {
    // No cache yet: download first.
    const r = await syncOnce({ force: true });
    if (r.status === 'first' || r.status === 'updated') buffer = r.buffer;
    else buffer = getCachedKdbx();
    if (!buffer) throw new Error('Failed to download database');
  }
  if (!looksLikeKdbx(buffer)) {
    throw new Error('Cached file is not a KDBX. Preview: ' + bufferPreview(buffer));
  }
  const { entries, meta } = await decryptKdbx(buffer, masterPassword);
  session.setUnlocked({ masterPassword, entries, meta });
  // Populate the AES cache so other tabs (including strict-CSP ones) can
  // adopt the unlocked state without running Argon2. Fire-and-forget.
  populateAesCache(entries, meta, masterPassword);
}

// Decrypt using a password we already trust (shared from another tab) and
// silently transition to unlocked state. Distinct from `unlockWithPassword`
// in that we do NOT re-publish the shared password (avoiding a self-trigger
// loop on the value-change listener).
//
// Fast path: if a valid AES cache exists, we decrypt that with the shared
// password using only Web Crypto AES-GCM (no Argon2, no CSP issues).
// Slow path: full Argon2 KDBX unlock — only works on pages where the Argon2
// Worker can be spawned (most pages, but not strict-CSP ones).
async function adoptAndDecrypt(pwd) {
  if (!pwd) throw new Error('No shared password');
  if (session.isUnlocked() && session.getState().masterPassword === pwd) return;

  // Try AES cache first (no Argon2 needed).
  const cached = await tryAesCacheAdoption(pwd);
  if (cached) {
    session.setUnlocked({
      masterPassword: pwd,
      entries: cached.entries,
      meta: cached.meta,
      share: false,
    });
    return;
  }

  // Slow path: full Argon2 unlock.
  let buffer = getCachedKdbx();
  if (buffer && !looksLikeKdbx(buffer)) buffer = null;
  if (!buffer) {
    const r = await syncOnce({ force: true });
    if (r.status === 'first' || r.status === 'updated') buffer = r.buffer;
    else buffer = getCachedKdbx();
    if (!buffer) throw new Error('Failed to download database');
  }
  if (!looksLikeKdbx(buffer)) {
    throw new Error('Cached file is not a KDBX. Preview: ' + bufferPreview(buffer));
  }
  const { entries, meta } = await decryptKdbx(buffer, pwd);
  session.setUnlocked({ masterPassword: pwd, entries, meta, share: false });
  // Refresh AES cache so the next adoption (this tab or any other) is fast.
  populateAesCache(entries, meta, pwd);
}

// Re-decrypt cached KDBX after a sync — only if this tab actually has the
// entries decrypted in memory. Tabs that were lazy-locked (shared password
// only, no decryption yet) skip this; the next openPanel will decrypt with
// the new bytes naturally.
async function redecryptIfUnlocked() {
  if (!session.isUnlocked()) return;
  const buffer = getCachedKdbx();
  if (!buffer) return;
  const pwd = session.getState().masterPassword;
  try {
    const { entries, meta } = await decryptKdbx(buffer, pwd);
    session.setUnlocked({
      masterPassword: pwd,
      entries,
      meta,
      share: false, // already shared
    });
    // Refresh AES cache for new bytes.
    populateAesCache(entries, meta, pwd);
  } catch (e) {
    gmNotify('Re-decrypt failed after sync: ' + e.message);
  }
}

// ---- Manual sync (any tab) --------------------------------------------------

async function manualSync() {
  try {
    const r = await syncOnce({ force: false });
    if (r.status === 'unchanged') return r;
    // New bytes: AES cache (keyed to old sha256) is now stale.
    clearAesCache();
    session.notifyDbUpdated(r.sha256);
    await redecryptIfUnlocked();
    return r;
  } catch (e) {
    gmNotify('Sync failed: ' + e.message);
    throw e;
  }
}

// ---- Periodic sync (leader only) -------------------------------------------

let pollTimer = null;
function reschedulePolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  if (!session.isThisLeader()) return;
  const minutes = +config.get('cfg.pollMinutes') || 0;
  if (minutes <= 0) return;
  pollTimer = setInterval(async () => {
    try {
      const r = await syncOnce({ force: false });
      if (r.status !== 'unchanged') {
        clearAesCache();
        session.notifyDbUpdated(r.sha256);
        await redecryptIfUnlocked();
        gmNotify('KeePass database updated');
      }
    } catch (e) {
      console.warn('[KeePass] poll failed', e);
    }
  }, minutes * 60_000);
}

session.on(async (ev) => {
  if (ev.type === 'leader-change') reschedulePolling();
  if (ev.type === 'db-updated') {
    // Another tab fetched a new DB. Re-decrypt locally.
    await redecryptIfUnlocked();
  }
});

// ---- Hotkey -----------------------------------------------------------------

function parseHotkey(s) {
  if (!s) return null;
  const parts = s.split('+').map((p) => p.trim().toLowerCase());
  const key = parts.pop();
  return {
    ctrl: parts.includes('ctrl') || parts.includes('control'),
    shift: parts.includes('shift'),
    alt: parts.includes('alt'),
    meta: parts.includes('meta') || parts.includes('cmd') || parts.includes('command'),
    key,
  };
}

function installHotkey() {
  const desc = parseHotkey(config.get('cfg.hotkey'));
  if (!desc) return;
  window.addEventListener('keydown', (e) => {
    if (!!desc.ctrl !== !!e.ctrlKey) return;
    if (!!desc.shift !== !!e.shiftKey) return;
    if (!!desc.alt !== !!e.altKey) return;
    if (!!desc.meta !== !!e.metaKey) return;
    if ((e.key || '').toLowerCase() !== desc.key) return;
    e.preventDefault();
    e.stopPropagation();
    panel.togglePanel();
  }, true);
}

// ---- Menu commands ----------------------------------------------------------

function installMenu() {
  if (typeof GM_registerMenuCommand !== 'function') return;
  GM_registerMenuCommand('Open KeePass', () => panel.openPanel());
  GM_registerMenuCommand('Sync now', async () => {
    try {
      gmNotify('Syncing…');
      const r = await manualSync();
      gmNotify(r.status === 'unchanged' ? 'KeePass: up to date' : 'KeePass: updated');
    } catch (e) { /* notification already issued */ }
  });
  GM_registerMenuCommand('Lock', () => session.lockLocal());
  GM_registerMenuCommand('Settings', () => panel.openPanel({ view: 'settings' }));
}

// ---- Bootstrap --------------------------------------------------------------

(async function bootstrap() {
  // Wait for DOM if needed (we use @run-at document-idle so this is normally fine).
  if (document.readyState === 'loading') {
    await new Promise((r) => document.addEventListener('DOMContentLoaded', r, { once: true }));
  }
  if (!globalThis.kdbxweb) {
    console.warn('[KeePass] kdbxweb global not present — @require may have failed');
  }
  panel.configure({
    onUnlock: unlockWithPassword,
    onAdopt: adoptAndDecrypt,
    onSync: manualSync,
  });
  session.initSession();
  installMenu();
  installHotkey();
  // NOTE: no eager decrypt on bootstrap. Argon2 KDBX4 unlocks are expensive
  // (0.5–3 s + ~64 MB) and this script runs on every page. We only decrypt
  // when the user actually opens the panel.
  reschedulePolling();
})();
