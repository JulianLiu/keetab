// Build script: bundles src/ into dist/keepass.user.js as an IIFE,
// inlines vendor/argon2-bundled.min.js into argon2-loader.js, and prepends
// the userscript metadata header.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = __dirname;

const argon2Js = readFileSync(resolve(root, 'vendor/argon2-bundled.min.js'), 'utf8');
const metadata = readFileSync(resolve(root, 'src/metadata.txt'), 'utf8');

const ARGON2_PLACEHOLDER_RE = /"__ARGON2_BUNDLED_JS__"|'__ARGON2_BUNDLED_JS__'/;
const argon2Literal = JSON.stringify(argon2Js);

const result = await build({
  entryPoints: [resolve(root, 'src/main.js')],
  bundle: true,
  format: 'iife',
  target: ['chrome100', 'firefox100', 'safari16'],
  platform: 'browser',
  write: false,
  loader: { '.css': 'text' },
  legalComments: 'none',
  minify: false,
  sourcemap: false,
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  banner: { js: '/* eslint-disable */' },
});

if (result.outputFiles.length !== 1) {
  console.error('Unexpected output count', result.outputFiles.length);
  process.exit(1);
}

let bundled = result.outputFiles[0].text;

if (!ARGON2_PLACEHOLDER_RE.test(bundled)) {
  console.error('Argon2 placeholder not found in bundled output. Check src/argon2-loader.js.');
  process.exit(1);
}
bundled = bundled.replace(ARGON2_PLACEHOLDER_RE, () => argon2Literal);

const final = metadata.trim() + '\n\n' + bundled;
mkdirSync(resolve(root, 'dist'), { recursive: true });
writeFileSync(resolve(root, 'dist/keepass.user.js'), final);

console.log(
  'Built dist/keepass.user.js (' +
  Math.round(final.length / 1024) + ' KB; argon2 inline: ' +
  Math.round(argon2Js.length / 1024) + ' KB)'
);
