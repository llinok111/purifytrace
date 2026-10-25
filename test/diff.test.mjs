import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeSanitizer } from '../testing/factory.mjs';
import { diffTrails } from '../src/report.js';

const sanitizer = makeSanitizer();

test('diff reports a newly kept element when the policy widens', () => {
  const input = '<iframe src="https://example.com/frame"></iframe><p>text</p>';
  const before = sanitizer.audit(input, {}).trail;
  const after = sanitizer.audit(input, { ADD_TAGS: ['iframe'] }).trail;
  const diff = diffTrails(before, after);

  assert.equal(diff.outputChanged, true);
  assert.equal(diff.added.length, 0);
  assert.deepEqual(diff.removed.map((event) => event.target), ['iframe']);
  assert.equal(diff.findings.deltaHigh, 1, 'allowing iframe must raise the risk count');
});

test('diff reports a newly dropped element when the policy narrows', () => {
  const input = '<p>hello</p><b>world</b>';
  const before = sanitizer.audit(input, {}).trail;
  const after = sanitizer.audit(input, { ALLOWED_TAGS: ['p'] }).trail;
  const diff = diffTrails(before, after);
  assert.deepEqual(diff.added.map((event) => event.target), ['b']);
  assert.equal(diff.removed.length, 0);
});

test('paths are stable across configs, so the same node diffs cleanly', () => {
  // Regression: DOMPurify detaches <body> under a narrow allow-list, which made
  // the recorded path change between configs and turned one node into an
  // added+removed pair with identical identity.
  const input = '<div><svg><script>alert(1)</script></svg></div>';
  const before = sanitizer.audit(input, {}).trail;
  const after = sanitizer.audit(input, { USE_PROFILES: { svg: true } }).trail;
  const beforeScript = before.events.find((event) => event.target === 'script');
  const afterScript = after.events.find((event) => event.target === 'script');
  assert.ok(beforeScript && afterScript);
  assert.equal(beforeScript.path, afterScript.path);

  const diff = diffTrails(before, after);
  // The SVG profile drops HTML support, so <div> genuinely becomes a new drop.
  assert.deepEqual(diff.added.map((event) => event.target), ['div']);
  assert.equal(diff.removed.length, 0);
});

test('diff explains a reason change on an attribute', () => {
  const input = '<a href="javascript:alert(1)">x</a>';
  const before = sanitizer.audit(input, {}).trail;
  const after = sanitizer.audit(input, { ALLOWED_URI_REGEXP: /^(?:javascript|https?):/i }).trail;
  const diff = diffTrails(before, after);
  assert.equal(diff.removed.length, 1, 'href is now kept');
  assert.equal(after.findings.some((finding) => finding.code === 'url-scheme'), true);
});

test('diff of identical policies reports no change', () => {
  const input = '<p onclick="x">y</p>';
  const diff = diffTrails(sanitizer.audit(input, {}).trail, sanitizer.audit(input, {}).trail);
  assert.equal(diff.outputChanged, false);
  assert.equal(diff.added.length + diff.removed.length + diff.changed.length, 0);
});
