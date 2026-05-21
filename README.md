# KeeTab

A Tampermonkey userscript that turns a publicly-hosted `.kdbx` file into a
read-only password manager available on every page you visit. Inspired by the
[Tusk](./Tusk) Chrome extension and reuses its KDBX parsing, URL ranking and
TOTP algorithms.

## Documentation

- `README.md` (this file) — install, configure, day-to-day use.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — internal design, module map,
  storage keys, data flow diagrams.
- [`DECISIONS.md`](./DECISIONS.md) — chronological log of design
  decisions (why we chose Workers over `eval`, why GM_setValue over
  BroadcastChannel, etc.). Read this before doing major refactors.
- [`DEVELOPMENT.md`](./DEVELOPMENT.md) — onboarding for contributors:
  how to build, test, and what to watch out for.

## Features

- Fetches a single KDBX file from any public URL via `GM_xmlhttpRequest` (no
  CORS issues). Auto-detects Nextcloud `public.php/dav/files/<token>` URLs
  and supplies HTTP Basic auth from the share token.
- Caches encrypted bytes in `GM_setValue`; conditional GETs with
  `If-None-Match` / `If-Modified-Since` so re-syncs are cheap.
- KDBX3 + KDBX4 supported. Argon2 runs inside a dedicated Web Worker spawned
  from a `blob:` URL, with a Trusted Types policy for strict-CSP sites. The
  WASM blob is inlined at build time — no runtime CDN fetch beyond the
  Tampermonkey install.
- **Two-stage decryption.** The first unlock anywhere runs Argon2 on the
  KDBX (heavy work, requires a Web Worker which strict-CSP sites may block).
  After success, the in-memory entries are re-wrapped with AES-GCM (key
  derived from the master password via PBKDF2) and cached in `GM_setValue`.
  Subsequent unlocks — including on strict-CSP sites where Argon2 cannot
  run — adopt the cache via plain Web Crypto (`crypto.subtle`), which is
  available everywhere with no `unsafe-eval` / Trusted Types issues. The
  cache is invalidated automatically when sync brings new KDBX bytes
  (sha256 mismatch).
- **Cross-tab unlocked state via `GM_setValue` + `GM_addValueChangeListener`,**
  so unlocking once makes the database available on every origin where the
  userscript runs. **Trade-off:** the master password is held in
  Tampermonkey's value storage (which is disk-backed) until you Lock,
  hit the idle timeout, or click Reset. Avoid this build if your threat
  model includes someone reading your Tampermonkey database.
- **Lazy decryption.** Tabs do not run Argon2 at page load. Decryption only
  happens when the user opens the panel (and only via the AES fast path on
  most tabs).
- Idle auto-lock (configurable minutes; clears the shared session for all
  tabs).
- Periodic background sync (leader-elected so only one tab polls).
- Shadow-DOM overlay panel with search, keyboard navigation, copy-to-clipboard
  for username / password / TOTP, TOTP countdown ring, and a settings view.
- Clipboard auto-clears after a configurable delay.
- URL match ranking ported from Tusk so entries that match the current site
  bubble to the top automatically.

## Build

Requirements: Node 18+.

```bash
npm install
npm run build
```

Output: `dist/keepass.user.js` (~110 KB, includes inlined Argon2 WASM).

## Install

1. Install [Tampermonkey](https://www.tampermonkey.net/).
2. Open `dist/keepass.user.js` in your browser; Tampermonkey should offer to
   install it. Or copy-paste the file contents into a new Tampermonkey
   userscript.
3. Open any HTTP(S) page and use the Tampermonkey menu:
   - **Open KeePass** — opens the panel
   - **Sync now** — manual fetch
   - **Lock** — drops in-memory keys
   - **Settings** — configure URL, poll interval, etc.

## First-run setup

1. Open the **Settings** view.
2. Set **KDBX URL** to a public direct download link to your `.kdbx`. Dropbox,
   Google Drive direct links, GitHub raw URLs, etc. all work.
3. Save.
4. Use **Open KeePass** → enter master password → unlock. The first unlock
   triggers a download; subsequent unlocks reuse the cached encrypted bytes.

## Hotkey

Default: `Ctrl+Shift+K`. Change in Settings (e.g. `Ctrl+Alt+P`,
`Meta+Shift+K`). Trigger to open/close the panel on the current page.

## How matching works

When the panel opens, entries are scored against `window.location` using the
algorithm from `Tusk/services/keepassService.js:94`:

- exact `origin` match → +100
- `host` match → +10
- `hostname` match (different port/proto) → -100 (potential phishing)
- title equality, hostname-token overlap, etc. add fractional points.

Entries also honour Tusk's `tuskUrls` extra-field convention, so if you've
already tagged entries for Tusk, they work here too.

## TOTP

If an entry has an `otp` field — either an `otpauth://` URL, a raw base32
secret, or KeePass's `key=...&period=...` format — the detail view shows a
live 6-digit code with a countdown ring. Steam guard codes are detected via
`issuer=Steam` in the URL.

## Security notes

- The encrypted KDBX is cached in `GM_setValue`. Bytes are already encrypted
  by KeePass; their on-disk presence is no worse than the source URL itself.
- The master password is **persisted in `GM_setValue`** while unlocked so
  that any tab on any origin can adopt the unlocked state. It is cleared on
  Lock, on idle timeout (`cfg.idleLockMinutes`), and on Reset. Tampermonkey
  stores GM values on disk, so anyone with read access to your Tampermonkey
  storage can recover the password while the database is unlocked. If this
  is unacceptable, set `cfg.idleLockMinutes` to a small value, or fork the
  script and revert `src/session.js` to the BroadcastChannel-only variant
  in git history.
- Decrypted secrets remain wrapped as `kdbxweb.ProtectedValue` until you
  explicitly request copy or reveal.
- Clipboard is overwritten after `clipboardClearSeconds` (default 20s).
- The panel renders inside a closed `ShadowRoot`; page scripts cannot read it.
- No DOM injection of credentials into the host page (clipboard-only by
  design).

## Limitations / non-goals

- **Read only.** Write/modify of the KDBX is not supported.
- **No keyfile support.** Password-only unlock.
- **One database** at a time (the configured URL).
- **Strict-CSP sites need a permissive site for the first unlock.** Argon2
  runs in a Web Worker spawned from a `blob:` URL. Sites whose CSP forbids
  `worker-src blob:` (or whose Trusted Types refuse blob: script URLs)
  cannot perform the first decrypt. Once any tab has done it, the AES cache
  takes over and strict-CSP sites work fine.
- Fetch is `GM_xmlhttpRequest` and uses the network freely; it's your
  responsibility to host the KDBX somewhere reasonable (private gist, S3
  signed URL, etc.).

## Project layout

```
src/
  metadata.txt              Userscript header (@name, @grant, @require, ...)
  main.js                   Entrypoint: wires storage/sync/session/UI; AES cache logic
  storage.js                GM_* wrappers, config, base64, sha256, AES-GCM helpers
  sync.js                   Conditional GET via GM_xmlhttpRequest; KDBX magic check
  session.js                Cross-tab session via GM_setValue + change listener;
                            leader election; idle watcher
  argon2-loader.js          Spawns argon2 in a Web Worker (blob: + Trusted Types)
                            and wires kdbxweb.CryptoEngine.setArgon2Impl
  kdbx.js                   decryptKdbx, group walk, {REF:...} resolution,
                            entry serialize/deserialize for AES cache
  matcher.js                parseUrl, getValidTokens, rankEntries (from Tusk)
  otp.js                    TOTP / HOTP / Steam (from Tusk)
  ui/
    panel.js                Shadow-DOM panel and views (unlock / unlocking /
                            list / detail / settings)
    styles.css              Inlined styles
vendor/
  argon2-bundled.min.js     argon2-browser 1.18.0 (UMD with embedded WASM)
build.mjs                   esbuild bundler + argon2 inline + header prepend
dist/keepass.user.js        Final installable userscript
ARCHITECTURE.md             Internal architecture and data flow
DECISIONS.md                Chronological design decisions / ADRs
```

See `ARCHITECTURE.md` and `DECISIONS.md` for implementation details and the
rationale behind the various security and UX trade-offs.

## License

MIT.
