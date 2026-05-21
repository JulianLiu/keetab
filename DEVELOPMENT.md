# Development guide

A short orientation for anyone (human or agent) picking up this codebase.
Pair with `ARCHITECTURE.md` and `DECISIONS.md`.

## Quick start

```bash
npm install
npm run build       # → dist/keepass.user.js
node --check dist/keepass.user.js   # syntax sanity
```

Open `dist/keepass.user.js` in a browser with Tampermonkey installed and
accept the install prompt. To re-test after a change, click *update* in
the Tampermonkey dashboard.

There is no test suite yet (see "Things to add" below).

## Editing the source

The build is non-minified, so the produced file is grep-able. After any
edit:

1. `npm run build`
2. Tampermonkey dashboard → click the script → *Edit* tab → paste the
   new contents (or use Tampermonkey's auto-update on the local file
   path if you prefer).
3. Reload the page where you're testing.

Source modules are under `src/`. The bundler entry point is `src/main.js`.
CSS is loaded via esbuild's `text` loader; importing a `.css` file gives
you the file contents as a string.

## When to load a skill

If you're modifying:

- **Tampermonkey grants, `@require`s, or any other userscript header
  field** — these live in `src/metadata.txt` and are prepended verbatim
  by `build.mjs`. Make sure new GM functions you call have a matching
  `@grant`.
- **CSP / Trusted Types-sensitive code** — re-read D-007 and D-009 in
  `DECISIONS.md` before introducing any string→code path.

## Common tasks

### Add a new persisted setting

1. Add a default in `DEFAULTS` in `src/storage.js`.
2. Add an input row in `renderSettings()` in `src/ui/panel.js` (the
   `fields` array drives the UI).
3. Read it via `config.get('cfg.yourKey')` wherever you need it.
4. `npm run build`.

### Add a new menu command

`src/main.js → installMenu()`. Use `GM_registerMenuCommand`. Don't forget
the corresponding `@grant` in `src/metadata.txt` if you reach for any
new GM API.

### Add a new view to the panel

1. Add a render function (`renderFoo`) following the pattern in
   `src/ui/panel.js`.
2. Add a branch in `render()` for `viewState.view === 'foo'`.
3. Set `viewState.view = 'foo'` from wherever the user enters the view.
4. If you add session events the view should react to, extend the
   `session.on(...)` callback near the top of the file.

### Touch the Argon2 path

You probably don't have to. But if you do:

- Test on a strict-CSP site (github.com is convenient) — see D-007.
- Worker spawn errors should produce a user-facing message naming the
  CSP / TT problem rather than a generic "decrypt failed".
- The Worker source is built by string concatenation:
  `argon2 UMD source + ;self.addEventListener('message', …)`. If you
  rearrange, double-check that `self.argon2` is defined before the
  message listener runs (the UMD assigns synchronously, so this is
  currently safe).

### Touch the AES cache format

If you change the shape of `cache.aesEntries`:

- Bump the `v` field in `aesEncryptString()`.
- Either add migration in `tryAesCacheAdoption()` or treat any blob
  without your new `v` as invalid (the fallback to Argon2 will
  repopulate it correctly).
- Update `ARCHITECTURE.md` "Storage keys" table.

### Debug "BadSignature" or fetch problems

- Check `cache.aesEntries` and `cache.kdbxBase64` in the Tampermonkey
  storage tab.
- The "Clear cached database (keep settings)" button in Settings is the
  fastest reset.
- `bufferPreview()` and `looksLikeKdbx()` are exported from `sync.js`
  for diagnostics; the panel's unlock error already includes them when
  the signature fails.
- Network: open devtools, look for the GM_xmlhttpRequest going out
  (Tampermonkey shows it in the *Network* tab when running with verbose
  logging).

## Threat-model checklist before merging changes

Before merging anything that touches storage, decryption, or the panel:

- [ ] Does this introduce any `eval`, `new Function`, `setTimeout(string, …)`,
      `Function.prototype.constructor`, or similar? → Reject.
      (Strict-CSP sites will break — see D-007.)
- [ ] Does this leak decrypted plaintext into any storage that isn't the
      AES-wrapped cache? → Reject.
- [ ] Does this introduce a network call to anywhere other than the
      configured KDBX URL? → Reject.
- [ ] Does this introduce DOM injection of credentials into the host
      page? → Discuss before merging (clipboard-only is intentional —
      D-004).
- [ ] Does this add a new persisted GM key? → Add it to `DEFAULTS` so
      `Reset all` clears it.
- [ ] Does this assume same-origin for cross-tab signalling
      (BroadcastChannel, sessionStorage)? → Almost certainly wrong.
      See D-005.

## File map (≤1 minute orientation)

```
src/main.js          ~270 lines  glue everything together; the orchestrator
src/storage.js       ~190 lines  GM_*, AES helpers, defaults
src/sync.js          ~160 lines  HTTP, conditional GET, magic-byte check
src/session.js       ~220 lines  cross-tab session + leader election
src/argon2-loader.js ~165 lines  Worker(blob:) + Trusted Types
src/kdbx.js          ~200 lines  decrypt + serialize for AES cache
src/matcher.js       ~95  lines  URL ranking (port from Tusk)
src/otp.js           ~125 lines  TOTP/HOTP/Steam (port from Tusk)
src/ui/panel.js      ~625 lines  shadow-DOM panel and views
src/ui/styles.css    ~250 lines  inlined styles
build.mjs            ~57  lines  esbuild + argon2 inline + header prepend
```

Most code is direct, no clever metaprogramming. Reading top-to-bottom
should be enough.

## What to do if you get stuck

- Read `DECISIONS.md` for the *why* behind each choice; many "obvious"
  refactors were tried and rejected for documented reasons.
- Read the Tusk reference in `Tusk/services/keepassService.js` for KDBX
  parsing details.
- The kdbxweb library docs are at https://github.com/keeweb/kdbxweb.
- The argon2-browser library docs are at https://github.com/antelle/argon2-browser
  (we only consume the bundled UMD version 1.18.0 from
  `vendor/argon2-bundled.min.js`).

## Things to add later

Open improvements that have come up but aren't done. Pick any of these
freely:

- **Tests.** No test harness exists. A vitest setup that mocks the
  `GM_*` globals would cover storage, AES round-trips, OTP, and the
  matcher cleanly. The Argon2 worker path needs a browser, not Node.
- **Floating button** (`cfg.showFloatingButton` is in DEFAULTS but the UI
  doesn't render one yet). Likely a small <40-line addition in
  `panel.js`.
- **Multi-database.** See D-011 for what it would take.
- **Keyfile support.** Mostly mechanical; add a file picker in Settings,
  store the keyfile bytes via `GM_setValue`, pass them through to
  `kdbxweb.Credentials`.
- **WebDAV browse.** Currently only a single direct file URL works. A
  thin WebDAV PROPFIND would let users pick from a directory listing.
- **OPFS-backed cache** instead of `GM_setValue` for the encrypted KDBX
  bytes — would scale better for >5 MB databases. Tampermonkey's
  `GM_setValue` is fine for typical KDBX sizes (low-MB).
- **Smaller bundle.** Inlining argon2 + kdbxweb pushes the file toward
  ~500 KB. If we ever inline kdbxweb too, run a minifier pass —
  currently disabled to keep the file grep-able.
- **Stronger cache crypto.** If D-005 ever changes to no-persist of the
  master password, see D-016 for the parameters that need to be revisited.
