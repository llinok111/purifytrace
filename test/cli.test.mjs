import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, '..', 'bin', 'purifytrace.js');
const corpus = join(here, '..', 'corpus');

async function cliRun(args) {
  try {
    const { stdout, stderr } = await run(process.execPath, [cli, ...args], { cwd: join(here, '..') });
    return { code: 0, stdout, stderr };
  } catch (error) {
    return { code: error.code ?? 1, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

test('CLI audits a file and exits 0 on a clean payload', async () => {
  const result = await cliRun([join(corpus, '28-benign-article.html')]);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /purifytrace 0\.1\.0/);
  assert.match(result.stdout, /BOOKKEEPING/);
  assert.match(result.stdout, /RISK SCAN/);
});

test('CLI exits 1 when a high-severity sink survives the policy', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'purifytrace-'));
  const file = join(dir, 'x.html');
  // A permissive URI regexp lets the javascript: URL through DOMPurify; the
  // independent risk scan is what catches it.
  writeFileSync(file, '<a href="javascript:alert(1)">x</a>');
  const config = join(dir, 'config.json');
  writeFileSync(config, JSON.stringify({ ALLOWED_URI_REGEXP: '/.*/' }));
  const result = await cliRun([file, '--config', config]);
  assert.equal(result.code, 1);
  assert.match(result.stdout, /HIGH\s+url-scheme/);
});

test('CLI exits 0 for a low-severity finding unless --strict-exit is given', async () => {
  const result = await cliRun([join(corpus, '15-style-attribute.html')]);
  assert.equal(result.code, 0, 'CSS url(javascript:) is a legacy-only risk, not high');
  assert.match(result.stdout, /LOW\s+css-sink/);

  const strict = await cliRun([join(corpus, '15-style-attribute.html'), '--strict-exit']);
  assert.equal(strict.code, 1, '--strict-exit turns any finding into a failure');
});

test('CLI exits 2 on a missing file instead of pretending to pass', async () => {
  const result = await cliRun(['/definitely/not/here.html']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /no such file/);
});

test('CLI exits 2 on an unknown option', async () => {
  const result = await cliRun(['--nope']);
  assert.equal(result.code, 2);
  assert.match(result.stdout, /unknown option/);
});

test('CLI --format json emits valid JSON', async () => {
  const result = await cliRun([join(corpus, '03-event-handler.html'), '--format', 'json']);
  assert.equal(result.code, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.dompurify.startsWith('3.'), true);
  assert.equal(parsed.events.length, 1);
  assert.equal(parsed.events[0].target, 'onerror');
});

test('CLI --format sarif emits SARIF 2.1.0', async () => {
  const result = await cliRun([join(corpus, '15-style-attribute.html'), '--format', 'sarif']);
  assert.equal(result.code, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.version, '2.1.0');
  assert.equal(parsed.runs[0].tool.driver.name, 'purifytrace');
  assert.ok(parsed.runs[0].results.length >= 1);
});

test('CLI --corpus summarizes every file', async () => {
  const result = await cliRun(['--corpus', corpus]);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /files 32/);
  assert.match(result.stdout, /upstream mismatches 0/);
});

test('CLI --diff compares two policies', async () => {
  const result = await cliRun(['--diff', 'default', 'strict', join(corpus, '28-benign-article.html')]);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /policy diff/);
  assert.match(result.stdout, /NEWLY DROPPED|NEWLY KEPT/);
});

test('CLI --presets lists the built-in presets', async () => {
  const result = await cliRun(['--presets']);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /strict/);
  assert.match(result.stdout, /svgProfile/);
});
