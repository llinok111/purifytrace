import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeSanitizer } from '../testing/factory.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const corpusDir = join(here, '..', 'corpus');
const sanitizer = makeSanitizer();

const files = readdirSync(corpusDir)
  .filter((name) => /\.(html?|svg|txt)$/i.test(name))
  .sort();

test('corpus contains the expected payload families', () => {
  assert.ok(files.length >= 30, `only ${files.length} corpus files`);
  const names = files.join(' ');
  for (const needed of ['inline-script', 'event-handler', 'javascript-href', 'mxss', 'template', 'style-tag', 'benign']) {
    assert.ok(names.includes(needed), `corpus is missing a ${needed} case`);
  }
});

test('no corpus payload leaves an executable event handler in the output', () => {
  for (const file of files) {
    const input = readFileSync(join(corpusDir, file), 'utf8');
    const { output } = sanitizer.audit(input);
    assert.equal(/\son[a-z]+\s*=/i.test(output), false, `${file} kept an event handler: ${output}`);
  }
});

test('no corpus payload leaves a javascript: URL in a URL attribute', () => {
  // DOMPurify does not sanitize CSS, so `style="background:url(javascript:...)"`
  // legitimately survives. That case is covered by the risk scan instead —
  // see the dedicated test below.
  for (const file of files) {
    const input = readFileSync(join(corpusDir, file), 'utf8');
    const { output } = sanitizer.audit(input);
    const withoutStyle = output.replace(/\sstyle="[^"]*"/gi, '');
    const cleaned = withoutStyle.replace(/[\u0000-\u0020]/g, '');
    assert.equal(/javascript:/i.test(cleaned), false, `${file} kept a javascript: URL: ${output}`);
  }
});

test('the CSS javascript: URL that DOMPurify keeps is reported by the risk scan', () => {
  // DOMPurify does not touch CSS at all (documented behaviour), so this is the
  // clearest case where DOMPurify.removed stays empty while the payload is
  // still worth a human decision.
  const input = readFileSync(join(corpusDir, '15-style-attribute.html'), 'utf8');
  const { trail } = sanitizer.audit(input);
  assert.equal(trail.bookkeeping.upstreamRecords, 0, 'upstream reports nothing');
  assert.equal(trail.events.length, 0, 'no policy decision was made');
  const finding = trail.findings.find((item) => item.code === 'css-sink');
  assert.ok(finding, 'the risk scan must flag it');
  assert.equal(finding.severity, 'low', 'CSS url(javascript:) only executes on legacy engines');
});

test('the audit agrees with DOMPurify.removed on every corpus file', () => {
  for (const file of files) {
    const input = readFileSync(join(corpusDir, file), 'utf8');
    const { trail } = sanitizer.audit(input);
    const unexplained =
      trail.bookkeeping.upstreamOnly.filter((item) => !item.explained).length +
      trail.bookkeeping.auditOnly.length +
      trail.bookkeeping.upstreamOnlyAttributes.length +
      trail.bookkeeping.auditOnlyAttributes.length;
    assert.equal(unexplained, 0, `${file} disagrees with upstream bookkeeping`);
  }
});

test('benign payloads are reported as untouched', () => {
  for (const file of files.filter((name) => name.includes('benign'))) {
    const input = readFileSync(join(corpusDir, file), 'utf8');
    const { trail } = sanitizer.audit(input);
    assert.equal(trail.events.length, 0, `${file} reported ${JSON.stringify(trail.events)}`);
    assert.equal(trail.findings.length, 0, `${file} reported findings`);
  }
});

test('the leading-script payload is invisible to upstream but visible to the audit', () => {
  const input = readFileSync(join(corpusDir, '02-leading-script.html'), 'utf8');
  const { trail } = sanitizer.audit(input);
  assert.equal(trail.bookkeeping.upstreamRecords, 0);
  assert.ok(trail.prewalk.headIgnored.some((entry) => entry.tag === 'script'));
});
