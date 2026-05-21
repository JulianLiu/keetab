// Sync engine. Fetches the configured KDBX URL via GM_xmlhttpRequest with a
// conditional GET (If-None-Match / If-Modified-Since). Leader election is
// handled by session.js; this file only exposes pure functions.

import { config, getCacheMeta, setCachedKdbx, sha256Hex } from './storage.js';

function gmRequest(opts) {
  return new Promise((resolve, reject) => {
    if (typeof GM_xmlhttpRequest !== 'function') {
      reject(new Error('GM_xmlhttpRequest is not available; install via Tampermonkey'));
      return;
    }
    const req = {
      method: opts.method || 'GET',
      url: opts.url,
      headers: opts.headers || {},
      responseType: opts.responseType || undefined,
      timeout: opts.timeout || 60000,
      onload: (res) => resolve(res),
      onerror: (err) => reject(new Error('Network error: ' + ((err && err.error) || 'unknown'))),
      ontimeout: () => reject(new Error('Request timed out')),
      onabort: () => reject(new Error('Request aborted')),
    };
    if (opts.user) req.user = opts.user;
    if (opts.password != null) req.password = opts.password;
    GM_xmlhttpRequest(req);
  });
}

function parseHeaders(headerStr) {
  const out = {};
  if (!headerStr) return out;
  for (const line of headerStr.split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    out[name] = value;
  }
  return out;
}

// Detect a Nextcloud public-share URL and pull the share token from the path,
// because Nextcloud's public WebDAV requires Basic auth with token=username.
//
// Recognised shapes:
//   https://host/public.php/dav/files/<token>            (current Nextcloud)
//   https://host/public.php/dav/files/<token>/<path...>
//   https://host/public.php/webdav                       (older Nextcloud — token in subpath via ?path)
//   https://host/s/<token>/download                      (no auth needed; left alone)
function detectNextcloudAuth(url) {
  try {
    const u = new URL(url);
    const m = u.pathname.match(/\/public\.php\/dav\/files\/([^/?#]+)/);
    if (m) return { user: m[1], password: '' };
    if (u.pathname.endsWith('/public.php/webdav') || u.pathname.endsWith('/public.php/webdav/')) {
      // No way to recover the token from the URL itself in this case. Caller
      // must rely on cfg.basicUser / cfg.basicPassword.
    }
  } catch { /* ignore */ }
  return null;
}

function buildAuth(url) {
  // Explicit user override always wins.
  const user = config.get('cfg.basicUser') || '';
  const password = config.get('cfg.basicPassword') || '';
  if (user) return { user, password };
  const auto = detectNextcloudAuth(url);
  if (auto) return auto;
  return null;
}

// Hex preview of the first N bytes of a buffer — handy for diagnosis when a
// server returns HTML / JSON instead of the KDBX file.
export function bufferPreview(buffer, n = 32) {
  if (!buffer) return '(empty)';
  const bytes = new Uint8Array(buffer.slice(0, n));
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join(' ');
  let ascii = '';
  for (const b of bytes) ascii += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
  return `${hex}  |${ascii}|`;
}

// KDBX magic: 03 D9 A2 9A (LE uint32 0x9AA2D903).
export function looksLikeKdbx(buffer) {
  if (!buffer || buffer.byteLength < 4) return false;
  const b = new Uint8Array(buffer, 0, 4);
  return b[0] === 0x03 && b[1] === 0xD9 && b[2] === 0xA2 && b[3] === 0x9A;
}

// Fetches the KDBX. Returns:
//   { status: 'unchanged' }                                — 304 or hash unchanged
//   { status: 'updated', buffer, headers, sha256 }         — new bytes available + cached
//   { status: 'first',   buffer, headers, sha256 }         — no prior cache, first download
export async function syncOnce({ force = false } = {}) {
  const url = config.get('cfg.url');
  if (!url) throw new Error('No KDBX URL configured');
  const meta = getCacheMeta();
  const headers = { Accept: '*/*' };
  if (!force && meta.etag) headers['If-None-Match'] = meta.etag;
  if (!force && meta.lastModified) headers['If-Modified-Since'] = meta.lastModified;

  const auth = buildAuth(url);

  const res = await gmRequest({
    method: 'GET',
    url,
    headers,
    responseType: 'arraybuffer',
    user: auth ? auth.user : undefined,
    password: auth ? auth.password : undefined,
  });

  if (res.status === 304) {
    return { status: 'unchanged' };
  }
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`HTTP ${res.status} fetching KDBX${auth ? ' (basic auth used)' : ''}`);
  }
  const buffer = res.response instanceof ArrayBuffer
    ? res.response
    : new Uint8Array(res.response).buffer;
  if (!buffer || buffer.byteLength < 16) throw new Error('Empty/invalid KDBX response');

  const respHeaders = parseHeaders(res.responseHeaders);

  if (!looksLikeKdbx(buffer)) {
    const ct = respHeaders['content-type'] || '(no content-type)';
    const preview = bufferPreview(buffer, 48);
    throw new Error(
      `Server returned non-KDBX content (Content-Type: ${ct}). ` +
      `First bytes: ${preview}. ` +
      (auth
        ? 'Tried Basic auth — check share token / password.'
        : 'If this is a Nextcloud / WebDAV URL, configure Basic auth in Settings.')
    );
  }

  const newMeta = {
    etag: respHeaders['etag'] || '',
    lastModified: respHeaders['last-modified'] || '',
  };
  const hash = await sha256Hex(buffer);
  const wasFirst = !meta.sha256;
  if (!wasFirst && hash === meta.sha256) {
    // Bytes identical even though server didn't return 304 — refresh headers only.
    setCachedKdbx(buffer, newMeta, hash);
    return { status: 'unchanged' };
  }
  setCachedKdbx(buffer, newMeta, hash);
  return {
    status: wasFirst ? 'first' : 'updated',
    buffer,
    headers: newMeta,
    sha256: hash,
  };
}
