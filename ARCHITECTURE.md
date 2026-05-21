# Architecture

This document describes how the userscript is structured internally, what
each module owns, and how data flows between them. Pair it with
`DECISIONS.md`, which records *why* the architecture is the way it is.

## High-level overview

The userscript is a single self-contained file (`dist/keepass.user.js`)
built from a small number of ES modules in `src/`. It runs on every page
(`@match *://*/*`) but most of the time only registers menu commands and a
hotkey listener and does nothing else. Heavy work (Argon2 KDBX decryption)
is deferred until the user opens the panel.

Three storage tiers:

| Tier              | Backed by                              | Holds                                  | Lifetime                        |
| ----------------- | -------------------------------------- | -------------------------------------- | ------------------------------- |
| **Disk (cache)**  | `GM_setValue('kpro.cache.kdbxBase64')` | Encrypted KDBX bytes                   | Until Reset / Clear cache       |
| **Disk (cache)**  | `GM_setValue('kpro.cache.aesEntries')` | AES-GCM-wrapped entry list             | Until KDBX bytes change / Reset |
| **Disk (session)**| `GM_setValue('kpro.session.*')`        | Master password, lastActivity          | Until Lock / idle / Reset       |
| **Tab memory**    | JS heap (closure in `session.js`)      | Decrypted entries with `ProtectedValue`| Until tab close / Lock          |

Cross-tab synchronisation rides on `GM_addValueChangeListener`, which is
delivered to every tab/origin running this userscript.

## Module map

```
              ┌────────────────────────────────────────┐
              │              src/main.js                │
              │  (bootstrap, menu, hotkey, AES wrap,    │
              │   adopt/unlock orchestration, polling)  │
              └─┬─────────────┬──────────┬──────────┬─┬─┘
                │             │          │          │ │
   ┌────────────▼──┐  ┌───────▼──┐  ┌────▼──────┐ ┌─▼─▼──────────┐
   │ src/sync.js   │  │session.js│  │ kdbx.js   │ │ ui/panel.js  │
   │ GM xhr +      │  │GM_set    │  │decrypt,   │ │Shadow-DOM    │
   │ conditional   │  │Value +   │  │serialize, │ │views,        │
   │ GET, auth     │  │change    │  │references │ │matcher use   │
   │ detection     │  │listener  │  │           │ │              │
   └──────┬────────┘  └─┬────────┘  └─┬─────────┘ └─┬────────────┘
          │             │             │             │
          ▼             ▼             ▼             ▼
  ┌──────────────────────────────────────────────────────┐
  │                  src/storage.js                       │
  │  GM_* wrappers · config defaults · base64 · sha256 ·  │
  │  AES-GCM via crypto.subtle · onValueChange()          │
  └──────────────────────────────────────────────────────┘
                            │
                            ▼
            ┌─────────────────────────────────┐
            │   src/argon2-loader.js          │
            │   Worker(blob:) + Trusted Types │
            │   wires kdbxweb crypto engine   │
            └─────────────────────────────────┘
                            │
                            ▼
                  ┌──────────────────┐
                  │ vendor/argon2-   │
                  │ bundled.min.js   │
                  │ (inlined string) │
                  └──────────────────┘

Externals:
  globalThis.kdbxweb        (loaded via @require, see metadata.txt)
  GM_xmlhttpRequest         (network)
  GM_setValue/GM_getValue   (persistent storage, cross-origin)
  GM_addValueChangeListener (cross-tab change events)
  GM_setClipboard           (copy username/password/TOTP)
  GM_notification           (sync results)
  GM_registerMenuCommand    (Tampermonkey menu items)
```

## Module responsibilities

### `src/main.js`

The orchestrator. Owns:

- Bootstrap sequence: wait for DOM idle, configure the panel, init the
  session, install menu + hotkey, schedule polling.
- AES cache lifecycle: `populateAesCache`, `tryAesCacheAdoption`,
  `clearAesCache`.
- Three decrypt entry points:
  - `unlockWithPassword(pwd)` — user typed a password in the panel.
  - `adoptAndDecrypt(pwd)` — silent decrypt using a shared password from
    another tab; tries AES first, then Argon2.
  - `redecryptIfUnlocked()` — runs after sync brings new bytes; only acts
    on tabs that already have decrypted entries in memory.
- Sync wrappers: `manualSync` (button / menu) and the leader's periodic
  poll. Both clear the AES cache when they detect new bytes.
- Hotkey parser (`Ctrl+Shift+K` style strings → keyboard event matcher).

### `src/storage.js`

All persistent-storage and crypto-helper concerns. Exports:

- `config.get/set/del/all/reset` — typed access to all persisted keys with
  defaults.
- `getCachedKdbx`, `setCachedKdbx`, `getCacheMeta` — KDBX byte cache + ETag
  / Last-Modified / sha256 metadata.
- `arrayBufferToBase64`, `base64ToArrayBuffer`, `sha256Hex` — helpers used
  by sync, AES, and storage.
- `aesEncryptString(plain, password)`, `aesDecryptString(blob, password)`
  — PBKDF2-SHA256 (200 000 iterations) → AES-GCM-256. Salt + IV are
  generated per call and stored alongside the ciphertext.
- `onValueChange(key, fn)` — wraps `GM_addValueChangeListener` with a
  `localStorage` fallback for non-Tampermonkey dev preview.

`DEFAULTS` is the canonical list of all `GM_setValue` keys this script
uses; `config.reset()` iterates it.

### `src/sync.js`

Pure HTTP. Exports:

- `syncOnce({force})` — performs a conditional GET with cached
  `If-None-Match` / `If-Modified-Since`, validates the response is KDBX
  (magic bytes `03 D9 A2 9A`), updates the cache. Returns one of
  `{status: 'unchanged' | 'first' | 'updated', buffer?, headers?, sha256?}`.
- `looksLikeKdbx(buffer)`, `bufferPreview(buffer, n)` — used by `main.js`
  for self-healing (refetch if the cached blob isn't a KDBX) and by the
  unlock view's error messages.
- `detectNextcloudAuth(url)` — recognises
  `…/public.php/dav/files/<token>` and produces `{user: token, password: ''}`
  for HTTP Basic auth. Combined with `cfg.basicUser` / `cfg.basicPassword`
  in `buildAuth(url)`.

`GM_xmlhttpRequest` is the only network call site in the entire codebase.

### `src/session.js`

Cross-tab session management plus per-tab in-memory state. Exports:

- In-memory state accessors: `getState`, `isUnlocked`, `setUnlocked`,
  `lockLocal`, `touchActivity`.
- Cross-tab session: `getSharedPassword`, `hasSharedPassword`,
  `adoptSharedPasswordIfAny`. The shared session is just three GM keys
  (`session.masterPassword`, `session.unlockedAt`, `session.lastActivity`).
- Events: `on(fn)` registers a listener for
  `unlocked` / `locked` / `shared-password-available` /
  `shared-password-cleared` / `db-updated` / `leader-change`.
- Leader election: `isThisLeader`, with a `GM_setValue('leader.heartbeats')`
  map of `tabId → timestamp`. The lowest tabId with a recent heartbeat
  (within 45 s) wins.
- `initSession()` starts the activity tracker, idle watcher, value watcher
  and heartbeat loop.

### `src/argon2-loader.js`

Spawns the Argon2 Worker, registers a Trusted Types policy if needed, and
wires `kdbxweb.CryptoEngine.setArgon2Impl` to a `postMessage`-based hash
function. Exports a single function:

- `ensureArgon2Wired()` — idempotent. First call spawns the worker and
  installs the impl; later calls are no-ops.

The Argon2 UMD source is inlined as a JSON-encoded string at build time
via the `__ARGON2_BUNDLED_JS__` placeholder.

### `src/kdbx.js`

KDBX decryption + reference resolution + AES-cache serialization. Exports:

- `decryptKdbx(buffer, password)` — runs Argon2 (via `ensureArgon2Wired`),
  loads the database with `kdbxweb`, walks groups recursively, returns
  `{entries, meta}`.
- `readField(entry, fieldName)` — transparent over `ProtectedValue`.
- `resolveValue(entry, fieldName, allEntries)` — full `{REF:...}` /
  `{TITLE}` / `{S:Custom}` resolution, ported from Tusk.
- `serializeEntries(entries)` — flattens `ProtectedValue` instances to
  plaintext under `{__pv: 1, text}` so JSON round-tripping works.
- `deserializeEntries(arr)` — rebuilds `ProtectedValue` instances so the
  rest of the codebase keeps working unchanged.

### `src/matcher.js`

Direct port of Tusk's URL-ranking and tokenization logic. Exports
`parseUrl`, `getValidTokens`, `rankEntries`, `filterByText`, `sortEntries`.
The ranking algorithm is documented inline; key reference is
`Tusk/services/keepassService.js:94`.

### `src/otp.js`

TOTP / HOTP / Steam guard. Self-contained — uses only Web Crypto. Public
API: `makeOtp(value)` (accepts `otpauth://` URLs, KeePass `key=...&period=...`
strings, or bare base32 secrets) and `isOtpSecret(s)`. Returns an `Otp`
instance with a single async method `next()` returning `{code, timeLeft, period}`.

### `src/ui/panel.js`

A single closed-shadow-DOM panel with five views:

- `unlock` — password prompt.
- `unlocking` — "Adopting…" spinner shown while AES adoption or Argon2
  decrypt runs.
- `list` — searchable, ranked entry list with keyboard nav.
- `detail` — entry view with copy buttons, reveal toggle, TOTP countdown.
- `settings` — config editor, clear-cache, reset.

Configured via `panel.configure({onUnlock, onAdopt, onSync})`. Listens on
`session.on(...)` to auto-transition between `unlock` ↔ `unlocking` ↔ `list`
when the cross-tab state changes.

### `src/ui/styles.css`

Loaded by `panel.js` as a string (esbuild text loader) and inlined into the
shadow root. No `GM_addStyle` — styles must not leak to the host page.

## Storage keys

All keys are namespaced under `kpro.` in `GM_setValue`. Listed in
`DEFAULTS` in `src/storage.js`.

| Key                          | Type                                          | Purpose                                    |
| ---------------------------- | --------------------------------------------- | ------------------------------------------ |
| `cfg.url`                    | string                                        | KDBX URL (the only network endpoint)       |
| `cfg.pollMinutes`            | number                                        | Periodic sync interval (0 disables)        |
| `cfg.idleLockMinutes`        | number                                        | Auto-lock after N minutes of inactivity    |
| `cfg.hotkey`                 | string                                        | e.g. `Ctrl+Shift+K`                        |
| `cfg.urlMatchMode`           | `origin`/`host`/`hostname`                    | Reserved (not currently used by ranking)   |
| `cfg.clipboardClearSeconds`  | number                                        | Auto-clear copied secrets after N seconds  |
| `cfg.showFloatingButton`     | boolean                                       | Reserved (no floating button yet)          |
| `cfg.basicUser`              | string                                        | HTTP Basic auth username                   |
| `cfg.basicPassword`          | string                                        | HTTP Basic auth password                   |
| `cache.kdbxBase64`           | base64                                        | Encrypted KDBX bytes                       |
| `cache.etag`                 | string                                        | ETag for conditional GET                   |
| `cache.lastModified`         | string                                        | Last-Modified for conditional GET          |
| `cache.fetchedAt`            | number (ms)                                   | When the cache was last refreshed          |
| `cache.sha256`               | hex                                           | Hash of cached KDBX bytes                  |
| `cache.sha256Notification`   | `{sha256, ts}` \| null                        | Cross-tab notification of new sync         |
| `cache.aesEntries`           | `{v, salt, iv, ct, sourceSha256, meta}`\|null | AES-wrapped decrypted entries              |
| `session.masterPassword`     | string                                        | Cross-tab master password (cleared on Lock)|
| `session.unlockedAt`         | number (ms)                                   | When the shared session started            |
| `session.lastActivity`       | number (ms)                                   | Bumped on user activity in any tab         |
| `leader.heartbeats`          | `{tabId: ts}`                                 | Leader election heartbeats                 |

## Data flow: unlock paths

### Path A — first unlock anywhere (Argon2)

```
[panel.js]   user types password, clicks Unlock
   │
   ▼
[main.js]    unlockWithPassword(pwd)
   │
   ├── getCachedKdbx() ── if missing/non-KDBX ──▶ syncOnce({force:true})
   │
   ▼
[kdbx.js]    decryptKdbx(buffer, pwd)
   │  └── ensureArgon2Wired()  →  spawns Worker if first time
   │  └── kdbxweb.Kdbx.load(buffer, creds)  →  ~1–3 s
   │
   ▼
[session.js] setUnlocked({masterPassword, entries, meta, share:true})
   │
   ├── writes session.masterPassword + lastActivity to GM_setValue
   │   (other tabs receive 'shared-password-available' via
   │    GM_addValueChangeListener)
   │
   ▼
[main.js]    populateAesCache(entries, meta, pwd)
             ── PBKDF2 derives AES key, AES-GCM encrypts JSON,
                stores cache.aesEntries with sourceSha256 = cache.sha256
```

### Path B — cross-tab adoption (AES, no Argon2)

```
[panel.js]   user opens panel; session.hasSharedPassword() == true
   │
   ▼
[panel.js]   startAdoption(sharedPwd)  →  view = 'unlocking'
   │
   ▼
[main.js]    adoptAndDecrypt(pwd)
   │
   ├── tryAesCacheAdoption(pwd):
   │      reads cache.aesEntries
   │      validates blob.sourceSha256 == cache.sha256
   │      PBKDF2 → AES-GCM decrypt → JSON.parse → deserializeEntries()
   │      → returns {entries, meta}            (~50–150 ms, no Argon2)
   │
   ├── if AES path returned null ▶ falls through to Argon2 (Path A body)
   │
   ▼
[session.js] setUnlocked({..., share:false})  ← we adopted, don't re-share
   │
   ▼
[panel.js]   view = 'list', auto-rendered via session 'unlocked' event
```

### Path C — sync brings new bytes

```
Leader tab fires its setInterval, or any tab clicks Sync now
   │
   ▼
[sync.js]    syncOnce()  →  HTTP GET, conditional headers
   │  └── if 304 or sha256 unchanged ▶ status:'unchanged' (stop)
   │  └── else ▶ status:'updated' or 'first', cache.kdbxBase64
   │           and cache.sha256 are written
   ▼
[main.js]    clearAesCache()         ← cache.aesEntries := null
   │
   ├── session.notifyDbUpdated(sha256)
   │   (writes cache.sha256Notification, all tabs see it via
   │    GM_addValueChangeListener and emit 'db-updated' locally)
   │
   ▼
[main.js]    redecryptIfUnlocked()
   │  └── only acts on tabs whose state.entries is non-null
   │  └── runs decryptKdbx(newBuffer, masterPwd)  →  Argon2
   │  └── populateAesCache(...)  →  refreshes cache.aesEntries
   │
   ▼
   Other tabs that adopt later use the freshly-populated AES cache.
```

## Bundling

`build.mjs` is the single build script. It:

1. Reads `vendor/argon2-bundled.min.js` (the UMD file with embedded WASM).
2. Reads `src/metadata.txt` (the userscript header).
3. Runs esbuild on `src/main.js` with `format: 'iife'`, browser target,
   `loader: { '.css': 'text' }`, no minification.
4. Replaces the placeholder `"__ARGON2_BUNDLED_JS__"` (or single-quoted)
   in the bundled output with `JSON.stringify(<argon2 source>)`.
5. Prepends `metadata.txt` to produce `dist/keepass.user.js`.

esbuild is currently the only npm dev dependency.

## Threat model snapshot

- **Network attacker** can serve a malicious KDBX. They cannot decrypt it
  (only the user knows the master password). KDBX magic check rejects
  non-KDBX responses early so the user gets an error, not a confusing
  crypto failure.
- **Local attacker with read access to Tampermonkey storage** can recover
  the master password and the AES cache while the database is unlocked,
  giving them all entries. This is documented and accepted.
- **Hostile page scripts** cannot read the panel (closed shadow root) and
  do not receive credential injection (clipboard-only by design). They can
  observe the clipboard if they are listening when the user copies — same
  caveat as any password manager.
- **Phishing / lookalike domains** are downgraded by the URL ranker
  (different host on the same hostname → rank −100, shown with a danger
  badge).

## Constraints and gotchas

- The userscript runs on every page; keep the bootstrap path light. No
  blocking work, no eager Argon2.
- `BroadcastChannel` is same-origin only. We use `GM_addValueChangeListener`
  for cross-origin events; do not regress this.
- Argon2 needs a Web Worker spawned from a `blob:` URL. Strict-CSP sites
  may forbid this; that's why the AES cache exists.
- Trusted Types policy name is `keepass-userscript-argon2`. Two userscripts
  trying to register the same policy name would conflict; if you ever
  rename, update both `argon2-loader.js` and any docs that mention it.
- `kdbxweb` is the only `@require`'d external. Its UMD bundle attaches to
  `globalThis.kdbxweb` synchronously when the userscript loads.
- The OTP `MutationObserver` in `panel.js` is attached to the entire shadow
  root with `subtree:true` to detect when the OTP row is removed (so we can
  stop the per-second tick). When refactoring the panel, remember to keep
  this lifecycle correct.

## Common pitfalls when extending

- **Don't add new `eval` / `new Function` / `setTimeout(string, …)`.**
  Strict-CSP sites will break. Use Workers if you need code-from-string.
- **Don't store decrypted plaintext outside the AES cache.** All long-lived
  storage of decrypted entries should go through `populateAesCache`.
- **Don't re-decrypt eagerly on `shared-password-available`.** That was
  fixed once; see `DECISIONS.md`.
- **Don't forget to clear `cache.aesEntries` when KDBX bytes change.**
  Helpers exist (`clearAesCache`); use them in any new sync entry point.
- **Adding new GM keys?** Put them in `DEFAULTS` in `src/storage.js` so
  `config.reset()` clears them.
