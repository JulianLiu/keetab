// Cross-tab/cross-origin session backed by GM_setValue.
//
// The master password is persisted in `session.masterPassword` so that any
// tab on any origin running this userscript can adopt the unlocked state.
// This is disk-backed (Tampermonkey persists GM_setValue), so the password
// can be cleared explicitly (Lock, idle timeout) but does survive a tab
// reload. The cleartext password is held in GM_setValue; treat the threat
// model accordingly (anyone who can read your Tampermonkey storage gets it).
//
// Cross-tab sync is handled by GM_addValueChangeListener, which fires across
// all origins for the same userscript — unlike BroadcastChannel which is
// same-origin only.

import { config, onValueChange } from './storage.js';

// In-memory unlocked state for *this* tab.
const state = {
  unlocked: false,
  masterPassword: null,   // string, kept only in heap of this tab
  entries: null,          // array of decrypted entries (with ProtectedValue refs)
  meta: null,             // { name, versionMajor }
  unlockedAt: 0,
};

let lastActivity = Date.now();
const listeners = new Set();
let valueWatcherStop = null;

// ---- helpers ----------------------------------------------------------------

function emit(ev) {
  for (const fn of listeners) {
    try { fn(ev); } catch (e) { console.error('[KeePass] listener', e); }
  }
}

export function on(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// ---- public state API -------------------------------------------------------

export function getState() { return state; }
export function isUnlocked() { return state.unlocked; }
export function touchActivity() {
  lastActivity = Date.now();
  if (state.unlocked) {
    config.set('session.lastActivity', lastActivity);
  }
}

// Mark this tab unlocked (after a successful decrypt) and write the master
// password to GM_setValue so other tabs can adopt it.
export function setUnlocked({ masterPassword, entries, meta, share = true }) {
  state.unlocked = true;
  state.masterPassword = masterPassword;
  state.entries = entries;
  state.meta = meta;
  state.unlockedAt = Date.now();
  lastActivity = Date.now();
  if (share) {
    // Persist for cross-tab adoption. Other tabs see this via the
    // value-change listener and decrypt locally.
    config.set('session.masterPassword', masterPassword);
    config.set('session.unlockedAt', state.unlockedAt);
    config.set('session.lastActivity', lastActivity);
  }
  emit({ type: 'unlocked' });
}

// Lock this tab. If `propagate`, also wipe the shared GM session so that all
// other tabs lock through their value-change listeners.
export function lockLocal({ propagate = true } = {}) {
  state.unlocked = false;
  state.masterPassword = null;
  state.entries = null;
  state.meta = null;
  emit({ type: 'locked' });
  if (propagate) {
    config.set('session.masterPassword', '');
    config.set('session.unlockedAt', 0);
    config.set('session.lastActivity', 0);
  }
}

// Read the persisted master password, if any. Returns '' when locked.
export function getSharedPassword() {
  return String(config.get('session.masterPassword') || '');
}

// Notify other tabs that the cached KDBX changed (a successful sync).
export function notifyDbUpdated(sha256) {
  config.set('cache.sha256Notification', { sha256, ts: Date.now() });
}

// ---- leader election (for periodic sync) ------------------------------------
//
// Each tab writes a heartbeat with its tabId + ts every HEARTBEAT_MS.
// The leader is the tab with the lowest id whose heartbeat is recent.
// This is best-effort; a brief overlap of two leaders is harmless because
// each tab's poll just hits the server with conditional GET.

const HEARTBEAT_MS = 15_000;
const LEADER_TIMEOUT_MS = 45_000;

const TAB_ID = (crypto.randomUUID && crypto.randomUUID()) ||
  (Math.random().toString(36).slice(2) + Date.now().toString(36));

let isLeader = false;

function readHeartbeats() {
  const raw = config.get('leader.heartbeats');
  if (!raw || typeof raw !== 'object') return {};
  return raw;
}

function writeHeartbeat() {
  const beats = readHeartbeats();
  const now = Date.now();
  const cutoff = now - LEADER_TIMEOUT_MS;
  for (const k of Object.keys(beats)) if (!beats[k] || beats[k] < cutoff) delete beats[k];
  beats[TAB_ID] = now;
  config.set('leader.heartbeats', beats);
  let lowest = TAB_ID;
  for (const k of Object.keys(beats)) if (k < lowest) lowest = k;
  const newLeader = lowest === TAB_ID;
  if (newLeader !== isLeader) {
    isLeader = newLeader;
    emit({ type: 'leader-change', isLeader });
  }
}

function removeHeartbeat() {
  try {
    const beats = readHeartbeats();
    delete beats[TAB_ID];
    config.set('leader.heartbeats', beats);
  } catch { /* ignore */ }
}

export function isThisLeader() { return isLeader; }
export const tabId = TAB_ID;

// ---- bootstrap --------------------------------------------------------------

function startActivityTracking() {
  ['mousemove', 'keydown', 'scroll', 'click'].forEach((ev) =>
    window.addEventListener(ev, touchActivity, { passive: true, capture: true })
  );
}

function startIdleWatcher() {
  // Each tab independently checks the SHARED last-activity timestamp.
  // Whichever tab notices idle expiry first clears the GM session, which
  // notifies every other tab via the value-change listener.
  setInterval(() => {
    const minutes = +config.get('cfg.idleLockMinutes') || 0;
    if (minutes <= 0) return;
    const sharedLast = +config.get('session.lastActivity') || 0;
    const sharedPwd = String(config.get('session.masterPassword') || '');
    if (!sharedPwd) return;
    if (Date.now() - sharedLast >= minutes * 60_000) {
      lockLocal({ propagate: true });
    }
  }, 30_000);
}

function startValueWatcher() {
  // session.masterPassword: cleared -> all tabs lock; set -> tabs note that a
  // shared password is available but DO NOT eagerly decrypt (decryption is
  // expensive — Argon2 may take 0.5–3s. We only decrypt when the user
  // actually opens the panel).
  if (valueWatcherStop) valueWatcherStop();
  valueWatcherStop = onValueChange('session.masterPassword', (newVal) => {
    const pwd = String(newVal || '');
    if (!pwd) {
      if (state.unlocked) lockLocal({ propagate: false });
      emit({ type: 'shared-password-cleared' });
      return;
    }
    if (state.unlocked && state.masterPassword === pwd) return;
    emit({ type: 'shared-password-available', password: pwd });
  });
}

export function initSession() {
  startActivityTracking();
  startIdleWatcher();
  startValueWatcher();
  writeHeartbeat();
  setInterval(writeHeartbeat, HEARTBEAT_MS);
  window.addEventListener('beforeunload', removeHeartbeat);
}

export function hasSharedPassword() {
  return !!getSharedPassword();
}

// Probe at startup whether another tab has already unlocked.
export function adoptSharedPasswordIfAny() {
  const pwd = getSharedPassword();
  if (!pwd) return null;
  const minutes = +config.get('cfg.idleLockMinutes') || 0;
  if (minutes > 0) {
    const last = +config.get('session.lastActivity') || 0;
    if (last && Date.now() - last >= minutes * 60_000) {
      // Stale shared session; clear it.
      config.set('session.masterPassword', '');
      config.set('session.unlockedAt', 0);
      config.set('session.lastActivity', 0);
      return null;
    }
  }
  return pwd;
}
