import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const readme = readFileSync(join(root, 'README.md'), 'utf8');

test('package metadata points at files that exist', () => {
  assert.equal(pkg.name, 'purifytrace');
  assert.ok(pkg.version.match(/^\d+\.\d+\.\d+$/));
  assert.equal(pkg.license, 'Apache-2.0');
  assert.equal(pkg.type, 'module');

  for (const target of [pkg.main, pkg.types, ...Object.values(pkg.exports).map((entry) => entry.default), ...Object.values(pkg.exports).map((entry) => entry.types)]) {
    assert.ok(existsSync(join(root, target)), `missing ${target}`);
  }
});

test('the bin entry exists and is the CLI the README documents', () => {
  assert.equal(pkg.bin.purifytrace, './bin/purifytrace.js');
  const cli = readFileSync(join(root, 'bin/purifytrace.js'), 'utf8');
  assert.match(cli, /^#!\/usr\/bin\/env node/, 'CLI needs a shebang to run via npx');
  assert.match(cli, /process\.exit\(2\)/, 'CLI must have a usage-error exit path');
});

test('license and attribution files are present and non-empty', () => {
  for (const file of ['LICENSE', 'NOTICE']) {
    const full = join(root, file);
    assert.ok(existsSync(full), `missing ${file}`);
    assert.ok(readFileSync(full, 'utf8').length > 200, `${file} looks empty`);
  }
  assert.match(readFileSync(join(root, 'LICENSE'), 'utf8'), /Apache License/);
  assert.match(readFileSync(join(root, 'NOTICE'), 'utf8'), /DOMPurify/);
});

test('every npm script referenced in the README exists', () => {
  const referenced = new Set();
  for (const match of readme.matchAll(/npm run ([a-z:]+)/g)) referenced.add(match[1]);
  assert.ok(referenced.size >= 4, `only found ${[...referenced].join(', ')}`);
  for (const name of referenced) {
    assert.ok(pkg.scripts[name], `README mentions "npm run ${name}" but package.json has no such script`);
  }
});

test('every CLI flag documented in the README is accepted by the CLI', () => {
  const flags = new Set();
  for (const match of readme.matchAll(/`(--[a-z-]+)/g)) flags.add(match[1]);
  assert.ok(flags.size >= 6, `only found ${[...flags].join(', ')}`);
  const cli = readFileSync(join(root, 'bin/purifytrace.js'), 'utf8');
  for (const flag of flags) {
    assert.ok(cli.includes(`'${flag}'`), `README documents ${flag} but the CLI never handles it`);
  }
});

test('files field covers everything the package needs at runtime', () => {
  for (const needed of ['src', 'bin', 'types', 'LICENSE', 'NOTICE', 'README.md']) {
    assert.ok(pkg.files.includes(needed), `files[] is missing ${needed}`);
  }
});

test('dompurify is a peer dependency, not a bundled runtime dependency', () => {
  assert.ok(pkg.peerDependencies.dompurify, 'dompurify must be declared as a peer dependency');
  assert.equal(pkg.dependencies, undefined, 'purifytrace must not ship runtime dependencies');
});

test('the README does not contain leftover placeholders', () => {
  assert.equal(/TODO|FIXME|TBD|lorem ipsum/i.test(readme), false);
  assert.equal(/<your-|xxx/i.test(readme), false);
});
