// Shadow-DOM panel.

import stylesCss from './styles.css';
import { config } from '../storage.js';
import * as session from '../session.js';
import { resolveValue } from '../kdbx.js';
import { rankEntries, filterByText, sortEntries, parseUrl } from '../matcher.js';
import { makeOtp } from '../otp.js';
import { syncOnce } from '../sync.js';

let host = null;
let shadow = null;
let viewState = {
  view: 'list', // 'unlock' | 'unlocking' | 'list' | 'detail' | 'settings'
  selectedIndex: 0,
  query: '',
  detailEntryIndex: -1,
  unlockingError: '',
};
let unlockHandler = null; // injected from main.js to actually unlock
let adoptHandler = null;  // injected from main.js to silently decrypt with shared pwd
let onSyncRequested = null;

export function configure({ onUnlock, onAdopt, onSync }) {
  unlockHandler = onUnlock;
  adoptHandler = onAdopt;
  onSyncRequested = onSync;
}

function ensureHost() {
  if (host) return;
  host = document.createElement('div');
  host.style.all = 'initial';
  host.style.position = 'fixed';
  host.style.inset = '0';
  host.style.zIndex = '2147483647';
  host.id = 'keepass-userscript-root';
  shadow = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = stylesCss;
  shadow.appendChild(style);
  document.body.appendChild(host);
  // Listen for session changes
  session.on((ev) => {
    if (!isOpen()) return;
    if (ev.type === 'unlocked') {
      if (viewState.view === 'unlock' || viewState.view === 'unlocking') {
        viewState.view = 'list';
        viewState.query = '';
        viewState.selectedIndex = 0;
      }
      render();
    } else if (ev.type === 'locked' || ev.type === 'shared-password-cleared') {
      if (viewState.view === 'list' || viewState.view === 'detail' || viewState.view === 'unlocking') {
        viewState.view = 'unlock';
      }
      render();
    } else if (ev.type === 'shared-password-available') {
      if (viewState.view === 'unlock') {
        // Auto-promote to unlocking — user already typed the password elsewhere.
        startAdoption(ev.password);
      }
    } else if (ev.type === 'db-updated') {
      render();
    }
  });
}

let isPanelOpen = false;

export function isOpen() { return isPanelOpen; }

export function openPanel({ view } = {}) {
  ensureHost();
  isPanelOpen = true;
  if (view) {
    viewState.view = view;
  } else if (session.isUnlocked()) {
    viewState.view = 'list';
  } else if (session.hasSharedPassword()) {
    // Lazy-decrypt: a peer tab already unlocked. Decrypt now (Argon2 takes
    // 0.5–3s) and show a spinner in the meantime instead of the password
    // prompt.
    startAdoption(session.getSharedPassword());
  } else {
    viewState.view = 'unlock';
  }
  render();
}

let adoptInFlight = false;
function startAdoption(pwd) {
  viewState.view = 'unlocking';
  viewState.unlockingError = '';
  if (adoptInFlight) return;
  adoptInFlight = true;
  Promise.resolve()
    .then(() => adoptHandler && adoptHandler(pwd))
    .catch((e) => {
      viewState.unlockingError = (e && e.message) || String(e);
      viewState.view = 'unlock';
      if (isOpen()) render();
    })
    .finally(() => { adoptInFlight = false; });
}

export function closePanel() {
  if (!host) return;
  isPanelOpen = false;
  // Clear panel DOM (but keep host + style)
  for (const child of Array.from(shadow.children)) {
    if (child.tagName !== 'STYLE') child.remove();
  }
}

export function togglePanel() {
  if (isPanelOpen) closePanel();
  else openPanel();
}

function render() {
  ensureHost();
  // Remove old non-style nodes
  for (const child of Array.from(shadow.children)) {
    if (child.tagName !== 'STYLE') child.remove();
  }
  if (!isPanelOpen) return;

  const backdrop = el('div', { class: 'backdrop' });
  backdrop.addEventListener('click', closePanel);

  const panel = el('div', { class: 'panel' });
  panel.appendChild(renderHeader());

  const body = el('div', { class: 'body' });
  if (viewState.view === 'unlock') body.appendChild(renderUnlock());
  else if (viewState.view === 'unlocking') body.appendChild(renderUnlocking());
  else if (viewState.view === 'settings') body.appendChild(renderSettings());
  else if (viewState.view === 'detail') body.appendChild(renderDetail());
  else body.appendChild(renderList());
  panel.appendChild(body);

  shadow.appendChild(backdrop);
  shadow.appendChild(panel);

  // focus
  setTimeout(() => {
    const f = shadow.querySelector('input[autofocus]');
    if (f) f.focus();
  }, 0);
}

// ---- views ------------------------------------------------------------------

function renderHeader() {
  const meta = session.getState().meta;
  const url = config.get('cfg.url');
  const fetchedAt = +config.get('cache.fetchedAt') || 0;
  let syncStatus = 'never synced';
  if (fetchedAt) {
    const ageMin = Math.round((Date.now() - fetchedAt) / 60_000);
    syncStatus = ageMin < 1 ? 'synced just now' : `synced ${ageMin}m ago`;
  }
  const header = el('div', { class: 'header' });
  const title = el('div', { class: 'title' }, meta?.name || (url ? hostnameOf(url) : 'KeePass'));
  const status = el('div', { class: 'sync-status' }, syncStatus);
  header.append(title, status);

  if (session.isUnlocked()) {
    const sync = el('button', { class: 'icon', title: 'Sync now' }, '⟳');
    sync.addEventListener('click', async () => {
      try {
        toast('Syncing…');
        const r = await onSyncRequested();
        toast(r.status === 'unchanged' ? 'Up to date' : 'Updated');
        render();
      } catch (e) { toast('Sync failed: ' + e.message); }
    });
    const lock = el('button', { class: 'icon', title: 'Lock' }, '🔒');
    lock.addEventListener('click', () => session.lockLocal());
    header.append(sync, lock);
  }

  const settings = el('button', { class: 'icon', title: 'Settings' }, '⚙');
  settings.addEventListener('click', () => { viewState.view = 'settings'; render(); });
  const close = el('button', { class: 'icon', title: 'Close' }, '✕');
  close.addEventListener('click', closePanel);
  header.append(settings, close);
  return header;
}

function renderUnlock() {
  const url = config.get('cfg.url');
  const wrap = el('div', { class: 'unlock' });
  if (!url) {
    wrap.append(
      el('div', { class: 'info' }, 'No KDBX URL configured. Open Settings to add one.'),
      el('button', { class: 'primary' }, 'Open settings')
    );
    wrap.lastChild.addEventListener('click', () => { viewState.view = 'settings'; render(); });
    return wrap;
  }

  const fetchedAt = +config.get('cache.fetchedAt') || 0;
  const cacheNote = fetchedAt
    ? `Cached database (${new Date(fetchedAt).toLocaleString()}).`
    : 'No cached database — will download on unlock.';

  wrap.append(
    el('div', { class: 'info' }, cacheNote),
    el('label', {}, 'Master password'),
  );
  const input = el('input', { type: 'password', autofocus: 'true' });
  const errorBox = el('div', { class: 'error', style: 'display:none' });
  if (viewState.unlockingError) {
    errorBox.textContent = 'Adoption failed: ' + viewState.unlockingError;
    errorBox.style.display = 'block';
    viewState.unlockingError = '';
  }
  const btn = el('button', { class: 'primary' }, 'Unlock');

  async function go() {
    btn.disabled = true;
    btn.textContent = 'Unlocking…';
    errorBox.style.display = 'none';
    try {
      await unlockHandler(input.value);
      input.value = '';
      viewState.view = 'list';
      viewState.query = '';
      viewState.selectedIndex = 0;
      render();
    } catch (e) {
      errorBox.textContent = 'Failed: ' + (e.message || e);
      errorBox.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Unlock';
    }
  }
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  btn.addEventListener('click', go);

  wrap.append(input, errorBox, btn);
  return wrap;
}

function renderUnlocking() {
  const wrap = el('div', { class: 'unlock' });
  wrap.append(
    el('div', { class: 'info' }, 'Adopting unlocked session from another tab…'),
    el('div', { class: 'info', style: 'opacity:0.6;font-size:11px' },
      'Decrypting (Argon2 may take 1–3 seconds).'),
  );
  const cancel = el('button', { class: 'secondary' }, 'Cancel and unlock manually');
  cancel.addEventListener('click', () => {
    viewState.view = 'unlock';
    render();
  });
  wrap.append(cancel);
  return wrap;
}

function renderList() {
  const wrap = el('div', { style: 'display:flex;flex-direction:column;flex:1;min-height:0' });
  const search = el('div', { class: 'search' });
  const input = el('input', {
    type: 'text',
    placeholder: 'Search entries…',
    value: viewState.query,
    autofocus: 'true',
  });
  search.appendChild(input);
  wrap.appendChild(search);

  const entries = visibleEntries();
  const list = el('div', { class: 'list' });
  if (!entries.length) {
    list.appendChild(el('div', { class: 'empty' }, 'No matching entries.'));
  } else {
    entries.forEach((entry, i) => {
      const node = el('div', { class: 'entry' + (i === viewState.selectedIndex ? ' active' : '') });
      const meta = el('div', { class: 'meta' });
      const t = resolveValue(entry, 'title', session.getState().entries) || '(no title)';
      const u = resolveValue(entry, 'userName', session.getState().entries) || '';
      meta.append(
        el('div', { class: 'title' }, t),
        el('div', { class: 'sub' }, [u, entry.groupPath].filter(Boolean).join(' · '))
      );
      node.appendChild(meta);
      const rank = entry.matchRank || 0;
      if (rank >= 100) node.appendChild(el('span', { class: 'badge' }, 'match'));
      else if (rank >= 10) node.appendChild(el('span', { class: 'badge warn' }, 'host'));
      else if (rank < 0) node.appendChild(el('span', { class: 'badge danger' }, 'phish?'));
      node.addEventListener('click', () => {
        viewState.selectedIndex = i;
        viewState.detailEntryIndex = entry._idx;
        viewState.view = 'detail';
        render();
      });
      list.appendChild(node);
    });
  }
  wrap.appendChild(list);

  input.addEventListener('input', () => {
    viewState.query = input.value;
    viewState.selectedIndex = 0;
    // partial re-render: replace list area
    const ents = visibleEntries();
    list.innerHTML = '';
    if (!ents.length) {
      list.appendChild(el('div', { class: 'empty' }, 'No matching entries.'));
      return;
    }
    ents.forEach((entry, i) => {
      const node = el('div', { class: 'entry' + (i === 0 ? ' active' : '') });
      const meta = el('div', { class: 'meta' });
      const t = resolveValue(entry, 'title', session.getState().entries) || '(no title)';
      const u = resolveValue(entry, 'userName', session.getState().entries) || '';
      meta.append(
        el('div', { class: 'title' }, t),
        el('div', { class: 'sub' }, [u, entry.groupPath].filter(Boolean).join(' · '))
      );
      node.appendChild(meta);
      const rank = entry.matchRank || 0;
      if (rank >= 100) node.appendChild(el('span', { class: 'badge' }, 'match'));
      else if (rank >= 10) node.appendChild(el('span', { class: 'badge warn' }, 'host'));
      else if (rank < 0) node.appendChild(el('span', { class: 'badge danger' }, 'phish?'));
      node.addEventListener('click', () => {
        viewState.selectedIndex = i;
        viewState.detailEntryIndex = entry._idx;
        viewState.view = 'detail';
        render();
      });
      list.appendChild(node);
    });
  });

  input.addEventListener('keydown', (e) => {
    const ents = visibleEntries();
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      viewState.selectedIndex = Math.min(viewState.selectedIndex + 1, ents.length - 1);
      render();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      viewState.selectedIndex = Math.max(viewState.selectedIndex - 1, 0);
      render();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const entry = ents[viewState.selectedIndex];
      if (entry) {
        viewState.detailEntryIndex = entry._idx;
        viewState.view = 'detail';
        render();
      }
    } else if (e.key === 'Escape') {
      closePanel();
    }
  });

  return wrap;
}

function renderDetail() {
  const all = session.getState().entries || [];
  const entry = all[viewState.detailEntryIndex];
  const wrap = el('div', { class: 'detail' });
  if (!entry) {
    wrap.appendChild(el('div', {}, 'Entry not found.'));
    return wrap;
  }
  const back = el('button', { class: 'secondary' }, '← Back');
  back.addEventListener('click', () => { viewState.view = 'list'; render(); });
  wrap.appendChild(back);

  const title = resolveValue(entry, 'title', all);
  wrap.appendChild(el('h3', {}, title || '(no title)'));
  if (entry.groupPath) wrap.appendChild(el('div', { class: 'sub', style: 'font-size:12px;opacity:0.6' }, entry.groupPath));

  // Username
  const userName = resolveValue(entry, 'userName', all);
  if (userName) wrap.appendChild(makeRow('Username', userName, () => copyAndClear('Username', userName)));

  // Password
  const password = resolveValue(entry, 'password', all);
  if (password) {
    const row = el('div', { class: 'row' });
    const label = el('label', {}, 'Password');
    const value = el('div', { class: 'value' }, '•'.repeat(Math.min(20, password.length)));
    let revealed = false;
    const reveal = el('button', { class: 'secondary' }, '👁');
    reveal.addEventListener('click', () => {
      revealed = !revealed;
      value.textContent = revealed ? password : '•'.repeat(Math.min(20, password.length));
    });
    const copy = el('button', { class: 'primary' }, 'Copy');
    copy.addEventListener('click', () => copyAndClear('Password', password));
    const actions = el('div', { class: 'actions' }, [reveal, copy]);
    row.append(label, value, actions);
    wrap.appendChild(row);
  }

  // URL
  const url = resolveValue(entry, 'url', all);
  if (url) {
    const row = el('div', { class: 'row' });
    const label = el('label', {}, 'URL');
    const value = el('div', { class: 'value' }, url);
    const open = el('button', { class: 'secondary' }, 'Open');
    open.addEventListener('click', () => window.open(url, '_blank', 'noopener'));
    const copy = el('button', { class: 'secondary' }, 'Copy');
    copy.addEventListener('click', () => copyAndClear('URL', url));
    row.append(label, value, el('div', { class: 'actions' }, [open, copy]));
    wrap.appendChild(row);
  }

  // OTP
  const otpField = resolveValue(entry, 'otp', all);
  if (otpField) {
    try {
      const otp = makeOtp(otpField);
      if (otp) wrap.appendChild(makeOtpRow(otp));
    } catch (e) {
      wrap.appendChild(el('div', { class: 'sub' }, 'OTP error: ' + e.message));
    }
  }

  // Notes
  const notes = resolveValue(entry, 'notes', all);
  if (notes) {
    const row = el('div', { class: 'row', style: 'flex-direction:column;align-items:stretch' });
    row.append(
      el('label', {}, 'Notes'),
      el('div', { class: 'value', style: 'white-space:pre-wrap' }, notes)
    );
    wrap.appendChild(row);
  }

  // Other custom fields
  const standard = new Set(['title', 'userName', 'password', 'url', 'notes', 'otp', 'groupName', 'groupPath', 'tags', 'expiry', 'tuskUrls']);
  for (const k of entry.keys || []) {
    if (standard.has(k)) continue;
    const v = resolveValue(entry, k, all);
    if (!v) continue;
    wrap.appendChild(makeRow(k, v, () => copyAndClear(k, v)));
  }

  if (entry.is_expired) {
    wrap.appendChild(el('div', { class: 'sub', style: 'color:#ef4444' }, 'This entry has expired.'));
  }

  return wrap;
}

function renderSettings() {
  const wrap = el('div', { class: 'settings-form' });

  const fields = [
    ['cfg.url', 'KDBX URL', 'text', 'https://example.com/passwords.kdbx'],
    ['cfg.basicUser', 'HTTP Basic auth username (Nextcloud share token, etc.)', 'text', ''],
    ['cfg.basicPassword', 'HTTP Basic auth password (empty if not set)', 'password', ''],
    ['cfg.pollMinutes', 'Poll interval (minutes, 0 disables)', 'number', '30'],
    ['cfg.idleLockMinutes', 'Idle auto-lock (minutes, 0 disables)', 'number', '15'],
    ['cfg.hotkey', 'Hotkey (e.g. Ctrl+Shift+K)', 'text', 'Ctrl+Shift+K'],
    ['cfg.clipboardClearSeconds', 'Clipboard clear (seconds, 0 disables)', 'number', '20'],
    ['cfg.urlMatchMode', 'URL match strictness (origin/host/hostname)', 'text', 'host'],
  ];

  const inputs = {};
  for (const [key, label, type, ph] of fields) {
    const f = el('div', { class: 'field' });
    f.append(el('label', {}, label));
    const input = el('input', { type, value: String(config.get(key) ?? ''), placeholder: ph });
    inputs[key] = input;
    f.append(input);
    wrap.append(f);
  }

  const actions = el('div', { class: 'row-actions' });
  const cancel = el('button', { class: 'secondary' }, 'Cancel');
  cancel.addEventListener('click', () => { viewState.view = session.isUnlocked() ? 'list' : 'unlock'; render(); });
  const save = el('button', { class: 'primary' }, 'Save');
  save.addEventListener('click', () => {
    for (const [key, , type] of fields) {
      let v = inputs[key].value;
      if (type === 'number') v = Number(v) || 0;
      config.set(key, v);
    }
    toast('Saved');
    viewState.view = session.isUnlocked() ? 'list' : 'unlock';
    render();
  });
  actions.append(cancel, save);
  wrap.append(actions);

  const reset = el('button', { class: 'secondary' }, 'Reset all (clear cache & config)');
  reset.addEventListener('click', () => {
    if (confirm('Clear all cached data and configuration?')) {
      config.reset();
      session.lockLocal();
      toast('Reset');
      render();
    }
  });
  const clearCache = el('button', { class: 'secondary' }, 'Clear cached database (keep settings)');
  clearCache.addEventListener('click', () => {
    config.set('cache.kdbxBase64', '');
    config.set('cache.etag', '');
    config.set('cache.lastModified', '');
    config.set('cache.fetchedAt', 0);
    config.set('cache.sha256', '');
    config.set('cache.aesEntries', null);
    session.lockLocal();
    toast('Cache cleared');
    render();
  });
  wrap.append(clearCache, reset);
  return wrap;
}

// ---- helpers ----------------------------------------------------------------

function visibleEntries() {
  const all = session.getState().entries || [];
  // attach _idx so detail view can find back
  all.forEach((e, i) => { e._idx = i; });
  // rank
  const siteUrl = parseUrl(window.location.href);
  rankEntries(all, siteUrl, document.title, all);
  let list = filterByText(all, viewState.query, all);
  list = sortEntries(list, all);
  return list;
}

function makeRow(label, value, onCopy) {
  const row = el('div', { class: 'row' });
  row.append(
    el('label', {}, label),
    el('div', { class: 'value' }, value)
  );
  if (onCopy) {
    const copy = el('button', { class: 'primary' }, 'Copy');
    copy.addEventListener('click', onCopy);
    row.append(el('div', { class: 'actions' }, [copy]));
  }
  return row;
}

function makeOtpRow(otp) {
  const row = el('div', { class: 'row totp' });
  const label = el('label', {}, 'TOTP');
  const ring = el('div', { class: 'ring' });
  const code = el('div', { class: 'code value' }, '------');
  const copy = el('button', { class: 'primary' }, 'Copy');

  let stopped = false;
  let lastCode = '';
  async function tick() {
    if (stopped) return;
    try {
      const r = await otp.next();
      lastCode = r.code;
      code.textContent = r.code;
      const pct = 100 - (r.timeLeft / r.period) * 100;
      ring.style.setProperty('--p', pct.toFixed(1) + '%');
    } catch (e) { code.textContent = 'err'; }
  }
  copy.addEventListener('click', () => copyAndClear('TOTP', lastCode));
  tick();
  const iv = setInterval(tick, 1000);
  row.append(label, ring, code, el('div', { class: 'actions' }, [copy]));
  // stop ticking when row is removed
  const obs = new MutationObserver(() => {
    if (!row.isConnected) { stopped = true; clearInterval(iv); obs.disconnect(); }
  });
  obs.observe(shadow, { childList: true, subtree: true });
  return row;
}

function copyAndClear(label, value) {
  if (typeof GM_setClipboard === 'function') GM_setClipboard(value);
  else navigator.clipboard.writeText(value).catch(() => {});
  toast(`${label} copied`);
  const seconds = +config.get('cfg.clipboardClearSeconds') || 0;
  if (seconds > 0) {
    setTimeout(() => {
      // Best-effort clear: only clear if the clipboard *still* matches `value`.
      // We can't reliably read the clipboard in many browsers; just overwrite.
      if (typeof GM_setClipboard === 'function') GM_setClipboard('');
      else navigator.clipboard.writeText('').catch(() => {});
    }, seconds * 1000);
  }
}

let toastTimer = null;
function toast(msg) {
  if (!shadow) return;
  let node = shadow.querySelector('.toast');
  if (!node) {
    node = el('div', { class: 'toast' });
    shadow.appendChild(node);
  }
  node.textContent = msg;
  node.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove('show'), 1800);
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  if (Array.isArray(children)) {
    for (const c of children) node.append(c);
  } else if (children != null) {
    node.append(children);
  }
  return node;
}

function hostnameOf(url) {
  try { return new URL(url).hostname; } catch { return url; }
}
