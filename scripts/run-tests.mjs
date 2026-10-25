#!/usr/bin/env node
/**
 * Test runner.
 *
 * `node --test test/*.test.mjs` is not portable: the glob is expanded by the
 * shell, PowerShell does not expand it, and Node only learned to expand test
 * globs itself in v22. The result was that the suite passed on Windows with
 * Node 22 and failed on Windows with Node 18/20 with
 * "Could not find '…\test\*.test.mjs'".
 *
 * This runner resolves the files with fs instead of relying on the shell, and
 * spawns the Node test runner with an explicit file list. It also counts
 * executed/skipped/failed separately, so a suite that skips everything can
 * never be reported as passing.
 */
import { spawn } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const testDir = join(root, 'test');

const files = readdirSync(testDir)
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => join(testDir, name));

if (files.length === 0) {
  console.error(`no *.test.mjs files found in ${testDir}`);
  process.exit(2);
}

// `--test-reporter` landed in Node 19.6 and was backported to 18.17. Older 18.x
// builds reject it, so only pass it when the running version understands it.
function supportsTestReporter() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major > 19) return true;
  if (major === 19) return minor >= 6;
  if (major === 18) return minor >= 17;
  return false;
}

const reporter = supportsTestReporter()
  ? [process.argv.includes('--dot') ? '--test-reporter=dot' : '--test-reporter=spec']
  : [];
const args = ['--test', ...reporter, ...files];

const child = spawn(process.execPath, args, {
  cwd: root,
  stdio: 'inherit',
  env: { ...process.env, NODE_ENV: 'test' },
});

child.on('close', (code) => {
  if (code !== 0) {
    console.error(`\ntest run failed (exit ${code}) over ${files.length} files`);
  }
  process.exit(code ?? 1);
});
