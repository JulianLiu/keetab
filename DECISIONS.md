# Design decisions

A chronological log of the non-obvious architectural / security decisions
made for this userscript, with the alternatives that were considered and
the reason each was chosen. Read `ARCHITECTURE.md` for *what* the system
looks like; this file is *why*.

When you change one of these, leave the old entry and append a new one
referencing it. Future agents and humans will thank you.

---

## D-001 — Single self-contained userscript over WebExtension

**Choice.** Ship as one Tampermonkey userscript file rather than a real
browser extension.

**Alternatives.**

- Repackage / fork Tusk as a Chrome extension.
- Custom WebExtension built from scratch.

**Reasons.**

- The original brief explicitly asked for a Tampermonkey userscript.
- Userscripts are simpler to install, share, and audit (one file).
- Tampermonkey grants (`GM_xmlhttpRequest`, `GM_setValue`, etc.) cover
  every network and storage need.

---

## D-002 — KDBX3 + KDBX4 with Argon2 (instead of KDBX3-only)

**Choice.** Support both KDBX3 (AES-KDF) and KDBX4 (Argon2 KDF). Argon2 is
mandatory for any modern KeePass database.

**Alternatives.**

- KDBX3-only (smaller bundle, no WASM).
- Pure-JS Argon2 (slow, no WASM gate).

**Reasons.**

- Modern KeePass defaults to KDBX4 with Argon2; KDBX3-only would alienate
  most users.
- Pure-JS Argon2 is 5–10× slower; the UX cost was unacceptable.
- WASM is universally supported in target browsers.

**Implementation.** `argon2-browser` 1.18.0 (UMD with embedded base64
WASM) is inlined at build time. See D-007 for the runtime loading
mechanism.

---

## D-003 — Inlined argon2 (instead of CDN @require)

**Choice.** Embed `vendor/argon2-bundled.min.js` (45 KB) into the final
userscript at build time.

**Alternatives.**

- `@require https://cdn.jsdelivr.net/npm/argon2-browser@…` — relies on a
  CDN at install time.
- `@resource` + `GM_getResourceText` — same CDN dependency.

**Reasons.**

- Self-host requirement from the original brief: minimise runtime
  third-party dependencies.
- One file is easier to audit and pin.
- Tampermonkey caches `@require` content after install anyway, so the
  install-time-only CDN dependency was the only thing being avoided.

**Trade-off.** kdbxweb is *still* `@require`'d from jsdelivr because the
user explicitly approved that. If we ever bundle it too, update
`metadata.txt` and `build.mjs` and remove the `@require` line.

---

## D-004 — Clipboard-only credential delivery

**Choice.** Use `GM_setClipboard` exclusively. No DOM injection of
credentials into form fields.

**Alternatives.**

- Tusk-style autofill via `inject.js` and identifyPasswordFields().
- Hybrid (clipboard + opt-in autofill button).

**Reasons.**

- Smaller attack surface: no script ever runs in the host page's main
  world.
- Phishing risk is reduced (we never type into a page that pretends to be
  another).
- Trade-off: slightly less convenient than autofill.

**Trade-off.** `cfg.clipboardClearSeconds` (default 20s) overwrites the
clipboard to mitigate exposure.

---

## D-005 — Cross-tab session: GM_setValue (not BroadcastChannel)

**Choice.** Persist the master password in `GM_setValue` and notify other
tabs via `GM_addValueChangeListener`. The original implementation used
`BroadcastChannel`.

**Why we changed.** `BroadcastChannel` is **same-origin only**. With the
userscript matching `*://*/*`, virtually every browsing session involves
multiple origins, so unlocking on tab A (origin X) didn't propagate to
tab B (origin Y). Users got prompted again on every new origin — bad UX.

`GM_addValueChangeListener` is delivered to every tab/origin running the
same userscript. This is the only mechanism we found that is genuinely
cross-origin within a userscript context.

**Trade-off.** `GM_setValue` is disk-backed, so the master password sits
on disk while unlocked. Mitigated by:

- Idle auto-lock (`cfg.idleLockMinutes`, default 15).
- Manual Lock button + menu command.
- Reset button clears everything.
- Two-stage AES wrap means an attacker still needs the master password
  *and* the AES blob, both of which are in GM storage; this is *not* a
  meaningful security win against a local attacker but is a clean format.

The user explicitly accepted this trade-off. If reverting, see
`session.js` git history for the BroadcastChannel-only variant.

**Files.** `src/session.js`, `src/storage.js` (`onValueChange`),
`src/metadata.txt` (added `GM_addValueChangeListener` /
`GM_removeValueChangeListener` grants).

---

## D-006 — Lazy decryption (Argon2 only on user-initiated unlock)

**Choice.** Tabs do not run Argon2 at page load. Decryption happens only
when the user actually opens the panel.

**Why we changed.** The first cross-tab implementation eagerly adopted
the shared password on bootstrap, calling Argon2 on every tab open.
Argon2 KDBX4 unlocks take 0.5–3 s of single-threaded CPU plus ~64 MB
allocation. Doing this on every page load (the userscript runs on
`*://*/*`) caused visible jank, battery drain, and tons of pointless work
for tabs that never use KeePass.

**Implementation.** `session.js` no longer takes an
`onSharedPasswordChange` callback. The value-change listener emits a
`shared-password-available` event but does not decrypt. `panel.openPanel()`
inspects the state on user invocation:

- Already unlocked in this tab → list view.
- Shared password exists but no entries here → `unlocking` view, kicks
  off `adoptAndDecrypt()`.
- No shared password → unlock prompt.

Combined with D-009 below, the panel-open path is now `~50–150 ms` of
PBKDF2 + AES-GCM in steady state.

---

## D-007 — Argon2 in a Web Worker (not eval / new Function)

**Choice.** Spawn the Argon2 UMD bundle in a dedicated Web Worker via
`Worker(URL.createObjectURL(new Blob([src])))`. Register a Trusted Types
policy named `keepass-userscript-argon2` to vouch for the blob URL.

**Why we changed.** Earlier iterations used `(0, eval)(argon2Source)` and
later `new Function(...)` to evaluate the UMD inside the userscript
sandbox. Both forms require `unsafe-eval` in the page CSP. Strict sites
(github.com, google.com, …) block this:

> Adoption failed: Evaluating a string as JavaScript violates the
> following Content Security Policy directive because 'unsafe-eval' is
> not an allowed source of script.

Some sites also enforce Trusted Types, which gates the Worker URL
parameter as a `TrustedScriptURL` sink.

Workers run with their own CSP context (worker-src + the worker's own
inherited CSP for blob:), so they sidestep `unsafe-eval`. The TT policy
covers the URL pass-through.

**Failure mode.** Sites that disallow `worker-src blob:` *and* TT can
neither eval nor spawn the worker. The error message names this; users
must perform the first unlock on a permissive site, after which the AES
cache (D-009) covers strict-CSP sites.

**Files.** `src/argon2-loader.js`.

**Open question.** If we ever encounter a site that also forbids
WebAssembly via `wasm-unsafe-eval`, even the Worker fallback fails. No
fix is currently planned; document and accept.

---

## D-008 — Inline base64 WASM, no runtime fetch

The argon2 UMD detects environment (`typeof importScripts === 'function'`
in workers) and falls through to `A.argon2 = I()`. Inside the worker
that's `self.argon2`. The bundled UMD has the WASM embedded as base64
and uses it as `Module.wasmBinary`, so it does not attempt a runtime
`fetch('argon2.wasm')`. We verified this empirically; in Node it failed
because the bundle takes the CommonJS branch and tries `fs.readFileSync`,
but in a real browser worker it succeeds.

This means we need *zero* network requests at runtime for crypto, which
is what makes operation on strict-CSP / offline pages possible (after
the initial unlock).

---

## D-009 — Two-stage decryption: Argon2 → re-wrap with AES-GCM cache

**Choice.** After the first successful Argon2 unlock anywhere, serialize
the decrypted entries to JSON and AES-GCM-encrypt them with a
PBKDF2-derived key (from the master password). Store this blob in
`cache.aesEntries`. Subsequent unlocks on any tab try the AES cache first
(Web Crypto only, ~50–150 ms, no CSP issues). Argon2 is the fallback.

**Why.** The user proposed it after observing that Argon2 fails on
strict-CSP sites (D-007). Two benefits:

1. **CSP compatibility.** AES-GCM via `crypto.subtle` is universally
   available. No `unsafe-eval`, no Trusted Types, no Worker required.
2. **Performance.** PBKDF2 (~50–150 ms) + AES-GCM (~1 ms) is an order of
   magnitude faster than Argon2 (1–3 s).

**Cache invalidation.** The AES blob stores `sourceSha256` of the KDBX
bytes that produced it. On adoption, we verify
`blob.sourceSha256 === cache.sha256`. Sync paths (`manualSync`, periodic
poll) call `clearAesCache()` whenever new bytes arrive. Self-healing:
the next Argon2 unlock anywhere repopulates the cache.

**Key derivation note.** Using the master password as the PBKDF2 input
means an attacker reading `GM_setValue` already has the password (D-005)
and trivially derives the AES key. The AES wrap is therefore *not* a
security boundary against that attacker; it is a format-cleanliness /
defense-in-depth measure. If we ever change D-005 to *not* persist the
master password, the AES key derivation should change too (random key
in GM, password used only to release it).

**Files.** `src/storage.js` (AES helpers, `cache.aesEntries` default),
`src/kdbx.js` (`serializeEntries` / `deserializeEntries`),
`src/main.js` (`populateAesCache`, `tryAesCacheAdoption`,
`clearAesCache`, all decrypt entry points wired).

---

## D-010 — Closed shadow DOM for the panel (not regular DOM)

**Choice.** `host.attachShadow({mode: 'closed'})`, with styles inlined as
a `<style>` inside the shadow root.

**Alternatives.**

- Regular DOM in document body.
- `mode: 'open'` shadow.
- iframe with `srcdoc`.

**Reasons.**

- Page CSS cannot leak into the panel (no surprise styling collisions).
- Page scripts cannot read panel contents via DOM traversal (closed
  shadow returns null from `host.shadowRoot`).
- iframe was overkill and would not solve scripted DOM-traversal attacks
  (they could observe the iframe's events).

**Note.** `GM_addStyle` is *not* used because it injects styles into the
host page's stylesheet, which would leak our class names. Styles are
loaded as text via esbuild's `text` loader and inserted into the shadow.

---

## D-011 — Single configured database, no keyfile

**Choice.** One KDBX URL at a time, password-only unlock.

**Alternatives.**

- Multiple databases (Tusk-style ManageDatabases).
- Keyfile support.

**Reasons.**

- Original brief: "single database URL", "no keyfile".
- The architecture has many places that assume one database (storage
  keys, AES cache scope, leader-elected polling, sha256 invalidation).
  Multi-database would require namespacing all of those.

**If you want to add multi-DB.** Promote every `cache.*` and
`session.*` key to `db:<id>:cache.*` etc., and pick the active id from
the panel. The session protocol becomes per-database. Probably 1–2 days
of careful work.

---

## D-012 — `@match *://*/*` with menu commands as the canonical entry point

**Choice.** Run on every page, but do nothing visible until the user
invokes the panel through the Tampermonkey menu or hotkey.

**Alternatives.**

- Allowlist matched domains.
- Single-page panel hosted at a known URL.

**Reasons.**

- Convenience: KeePass should be available everywhere without per-site
  setup.
- The lazy-decrypt design (D-006) keeps the cost of running on every
  page near zero.
- A single-page panel would prevent in-context URL ranking
  (which uses `window.location` to score entries).

**Trade-off.** Tampermonkey shows the script in its menu on every site;
this is mildly noisy but unavoidable.

---

## D-013 — Auto Basic auth for Nextcloud public-share URLs

**Choice.** Detect URLs of the form `…/public.php/dav/files/<token>` and
inject `Authorization: Basic base64(<token>:)`.

**Why.** Without this, Nextcloud public WebDAV returns an HTML login
page. The first failure user actually hit was on a Nextcloud share. The
detection is unambiguous (no false positives for non-Nextcloud URLs).

**Files.** `src/sync.js` (`detectNextcloudAuth`, `buildAuth`).

**User-facing.** Settings has explicit `cfg.basicUser` / `cfg.basicPassword`
fields that override auto-detection — useful for password-protected
shares or unrelated WebDAV hosts.

---

## D-014 — Self-healing cache for non-KDBX responses

**Choice.** `looksLikeKdbx(buffer)` (magic bytes `03 D9 A2 9A`) is checked:

- After every sync (rejects HTML/JSON responses with a clear error).
- Before every decrypt (forces a re-fetch if the cached blob isn't a
  KDBX, e.g. left over from a pre-fix download of an HTML login page).

Plus `bufferPreview(buffer, 48)` shows hex+ASCII of the first 48 bytes in
error messages.

This was added after diagnosing a `BadSignature` error during the
Nextcloud incident.

---

## D-015 — Worker-based Argon2 also wraps `kdbxweb.CryptoEngine.setArgon2Impl`

The worker's `argon2.hash(params)` is exposed via a `postMessage` round-
trip in `argon2-loader.js` and wired into kdbxweb. Returns a `Uint8Array`
which is structured-cloned (a copy) when posted back to the main thread —
the main thread never has access to the worker's heap.

The `setArgon2Impl` shape is preserved exactly as in
`Tusk/services/keepassService.js:11` so kdbxweb's expectations are met.

---

## D-016 — One AES policy: PBKDF2 200 000 iterations, AES-GCM-256

**Numbers.**

- PBKDF2: SHA-256, 200 000 iterations, 16-byte random salt per encryption.
- AES: AES-GCM-256, 12-byte random IV per encryption.

**Reasons.** OWASP 2023 minimum recommendation for PBKDF2-SHA256 is
600 000, but in our environment the key is derived per panel-open and
takes ~50–150 ms; raising iterations would push that to ~500 ms+ and
hurt UX. The threat model does not benefit from more iterations because
the password is already in `GM_setValue` (D-005); the PBKDF2 work factor
exists to slow down dictionary attacks against an offline copy of the
AES blob, which is not the primary risk.

If D-005 ever flips back to no-persist, raise iterations to 600 000.

---

## D-017 — Leader election via GM_setValue heartbeats

**Choice.** Each tab writes `{tabId, ts}` into `leader.heartbeats` every
15 s. Leader = lowest tabId with a heartbeat in the last 45 s.

**Why.** Periodic sync should run in only one tab to avoid hammering the
KDBX URL. Leader election needs to be cross-origin, so
`BroadcastChannel`-based election was unworkable (D-005 reasoning).

**Failure mode.** Brief overlaps of two leaders (during election churn)
cause the server to receive 2 conditional GETs instead of 1 — harmless;
both will be 304 in the common case.
