// Argon2 loader using a dedicated Worker.
//
// Loading the argon2-browser UMD via runtime `eval` / `new Function` is
// blocked on sites with strict CSP (`unsafe-eval`) or Trusted Types
// (e.g. github.com, google.com). Tampermonkey's userscript sandbox does NOT
// reliably escape those policies on Chromium.
//
// Workers run with their own CSP context, and `Worker(blob:URL)` is the
// canonical escape hatch. We:
//   * Embed the argon2 UMD source as a string at build time.
//   * Build a Worker source that = argon2 UMD + a postMessage hash handler.
//   * Spawn it via Blob → URL.createObjectURL → Worker.
//   * If the page enforces Trusted Types, we register a tiny TT policy that
//     vouches for the blob: URL.
//
// The argon2 UMD detects the worker context via `typeof importScripts` and
// falls through to `A.argon2 = I()` where `A = this = self` (the worker
// global), so `self.argon2` becomes available.

// __ARGON2_BUNDLED_JS__ is replaced at build time with a JSON-encoded string
// of the entire vendor/argon2-bundled.min.js file.
const ARGON2_BUNDLED_JS = '__ARGON2_BUNDLED_JS__';

let workerInfoPromise = null;

function getTrustedTypePolicy() {
  if (getTrustedTypePolicy._cached !== undefined) return getTrustedTypePolicy._cached;
  const tt = (typeof globalThis !== 'undefined' && globalThis.trustedTypes) ||
    (typeof window !== 'undefined' && window.trustedTypes);
  if (!tt || typeof tt.createPolicy !== 'function') {
    getTrustedTypePolicy._cached = null;
    return null;
  }
  try {
    const policy = tt.createPolicy('keepass-userscript-argon2', {
      createScriptURL: (url) => url,
    });
    getTrustedTypePolicy._cached = policy;
    return policy;
  } catch (e) {
    // Policy creation may be disallowed by the document, or the name may
    // already be taken. Either way, fall back to the raw URL.
    console.warn('[KeePass] Trusted Types policy creation failed', e);
    getTrustedTypePolicy._cached = null;
    return null;
  }
}

function startWorker() {
  // Worker source: argon2 UMD (sets self.argon2) + message router.
  const handler =
    ';self.addEventListener("message",function(e){' +
    'var d=e.data;' +
    'if(!d||d.type!=="hash")return;' +
    'try{' +
    'self.argon2.hash(d.params).then(function(r){' +
    'self.postMessage({id:d.id,hash:r.hash});' +
    '}).catch(function(err){' +
    'self.postMessage({id:d.id,error:String((err&&err.message)||err)});' +
    '});' +
    '}catch(err){' +
    'self.postMessage({id:d.id,error:String((err&&err.message)||err)});' +
    '}' +
    '});';

  const wrapperSrc = ARGON2_BUNDLED_JS + handler;
  const blob = new Blob([wrapperSrc], { type: 'application/javascript' });
  const url = URL.createObjectURL(blob);
  const tt = getTrustedTypePolicy();
  let safeUrl;
  try {
    safeUrl = tt ? tt.createScriptURL(url) : url;
  } catch (e) {
    safeUrl = url;
  }

  let worker;
  try {
    worker = new Worker(safeUrl);
  } catch (e) {
    URL.revokeObjectURL(url);
    throw new Error(
      'Cannot start Argon2 Worker. Page CSP likely forbids worker-src blob: ' +
      'or Trusted Types blocks blob: script URLs. (' + (e && e.message || e) + ')'
    );
  }

  const pending = new Map();
  let nextId = 1;
  let workerDead = false;
  let workerError = null;

  worker.addEventListener('message', (e) => {
    const { id, hash, error } = e.data || {};
    const cb = pending.get(id);
    if (!cb) return;
    pending.delete(id);
    if (error) cb.reject(new Error('Argon2: ' + error));
    else cb.resolve(hash instanceof Uint8Array ? hash : new Uint8Array(hash));
  });
  worker.addEventListener('error', (e) => {
    workerDead = true;
    workerError = e.message || 'Argon2 worker crashed';
    console.error('[KeePass] argon2 worker error', e);
    for (const cb of pending.values()) cb.reject(new Error(workerError));
    pending.clear();
  });
  // Errors on the worker context (TypeError thrown inside) come as
  // 'messageerror' too in some implementations.
  worker.addEventListener('messageerror', (e) => {
    console.error('[KeePass] argon2 messageerror', e);
  });

  function post(params) {
    if (workerDead) return Promise.reject(new Error(workerError || 'Argon2 worker dead'));
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      try {
        worker.postMessage({ type: 'hash', id, params });
      } catch (e) {
        pending.delete(id);
        reject(e);
      }
    });
  }

  return { worker, post };
}

function ensureWorker() {
  if (workerInfoPromise) return workerInfoPromise;
  workerInfoPromise = new Promise((resolve, reject) => {
    try { resolve(startWorker()); }
    catch (e) { workerInfoPromise = null; reject(e); }
  });
  return workerInfoPromise;
}

// Wire kdbxweb -> argon2 worker. Mirrors Tusk/services/keepassService.js:11.
export async function ensureArgon2Wired() {
  const kdbxweb = globalThis.kdbxweb;
  if (!kdbxweb) throw new Error('kdbxweb not loaded');
  if (ensureArgon2Wired._wired) return;
  // Spawn the worker now so CSP failures surface at unlock time with a
  // specific error rather than failing later inside kdbxweb.Kdbx.load.
  const info = await ensureWorker();
  kdbxweb.CryptoEngine.setArgon2Impl(
    (password, salt, memory, iterations, length, parallelism, type, version) => {
      return info.post({
        pass: new Uint8Array(password),
        salt: new Uint8Array(salt),
        time: iterations,
        mem: memory,
        hashLen: length,
        parallelism,
        type,
        version,
      });
    }
  );
  ensureArgon2Wired._wired = true;
}
