import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { createAuditedSanitizer } from '../src/index.js';
import { makeSanitizer, plainPurifier, loadFactory, window } from '../testing/factory.mjs';

const sanitizer = makeSanitizer();

test('empty input produces an empty trail, not a crash', () => {
  const { trail } = sanitizer.audit('');
  assert.equal(trail.output, '');
  assert.deepEqual(trail.events, []);
  assert.equal(trail.stats.elementsSeen, 0);
});

test('malformed markup is audited without throwing', () => {
  const { trail } = sanitizer.audit('<div><p><b>unclosed<span onmouseover=alert(1)>');
  assert.equal(trail.findings.some((finding) => finding.code === 'event-handler-attribute'), false);
  assert.ok(trail.events.some((event) => event.target === 'onmouseover'));
});

test('unicode content survives byte-for-byte', () => {
  const input = '<p>中文 · emoji 🧪 · ünïcode</p>';
  const { trail } = sanitizer.audit(input);
  assert.equal(trail.output, input);
  assert.equal(trail.prewalk.textChanged, false);
});

test('IN_PLACE + RETURN_DOM is supported', () => {
  const dom = new JSDOM('<div id="host"><p onclick="x">keep</p><script>alert(1)</script></div>');
  const w = dom.window;
  const local = createAuditedSanitizer({ createDOMPurify: loadFactory(), window: w });
  const host = w.document.getElementById('host');
  const { output, trail } = local.audit(host, { IN_PLACE: true, RETURN_DOM: true });
  assert.equal(output, host, 'returns the same node in place');
  assert.ok(trail.events.some((event) => event.target === 'onclick'));
  assert.equal(host.innerHTML.includes('onclick'), false);
});

test('a window without DOM support fails loudly instead of returning an empty trail', () => {
  const fakeFactory = () => ({ isSupported: false, sanitize: (x) => x, addHook() {}, removed: [] });
  assert.throws(
    () => createAuditedSanitizer({ createDOMPurify: fakeFactory, window }),
    /isSupported=false/
  );
});

test('missing factory or window is a TypeError', () => {
  assert.throws(() => createAuditedSanitizer({}), TypeError);
  assert.throws(() => createAuditedSanitizer({ createDOMPurify: () => ({}) }), TypeError);
});

test('sanitize() is a drop-in replacement for the wrapped instance', () => {
  const payloads = ['<p onclick="x">a</p>', '<img src=x onerror=alert(1)>', '<b>ok</b>'];
  const baseline = plainPurifier();
  for (const payload of payloads) {
    assert.equal(sanitizer.sanitize(payload), baseline.sanitize(payload));
  }
});

test('a hook-less caller can still use the raw instance', () => {
  assert.equal(typeof sanitizer.instance.sanitize, 'function');
  assert.equal(sanitizer.instance.sanitize('<p onclick=x>y</p>'), '<p>y</p>');
});

test('nested template content is recorded, not missed', () => {
  const { trail } = sanitizer.audit('<div><template><img src=x onerror=alert(1)></template></div>');
  assert.ok(trail.events.some((event) => event.target === 'onerror'), JSON.stringify(trail.events));
});

test('1000-node document is audited within a sane time budget', () => {
  const input = `<div>${'<p class="x">line</p>'.repeat(1000)}</div>`;
  const started = process.hrtime.bigint();
  const { trail } = sanitizer.audit(input);
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  assert.equal(trail.stats.elementsSeen, 1001);
  assert.ok(ms < 3000, `audit took ${ms.toFixed(0)} ms`);
});

test('audit is deterministic for the same input', () => {
  const input = '<div onclick="a"><svg><script>x</script></svg></div>';
  const first = JSON.stringify(sanitizer.audit(input).trail);
  const second = JSON.stringify(sanitizer.audit(input).trail);
  assert.equal(first, second);
});
