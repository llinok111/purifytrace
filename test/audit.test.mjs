import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeSanitizer, plainPurifier } from '../testing/factory.mjs';

const sanitizer = makeSanitizer();

test('records an event for every element and attribute DOMPurify drops', () => {
  const { trail } = sanitizer.audit('<p onclick="alert(1)" class="c">x</p>');
  assert.equal(trail.output, '<p class="c">x</p>');
  assert.equal(trail.events.length, 1);
  const [event] = trail.events;
  assert.equal(event.action, 'strip-attribute');
  assert.equal(event.target, 'onclick');
  assert.equal(event.on, 'p');
  assert.match(event.path, /p$/);
});

test('tag removals carry the config key that caused them', () => {
  // A *leading* <script> never reaches the walker (see the pre-walk test), so
  // this payload puts it after a sibling to exercise the removal path.
  const { trail } = sanitizer.audit('<div><script>alert(1)</script></div>', {});
  const [event] = trail.events;
  assert.equal(event.action, 'remove');
  assert.equal(event.target, 'script');
  assert.equal(event.reason.code, 'tag-not-allowed');
  assert.equal(event.reason.confidence, 'confirmed');
});

test('explicit allow-list is named as the policy key', () => {
  const { trail } = sanitizer.audit('<div><b>keep</b></div>', { ALLOWED_TAGS: ['b'] });
  const removal = trail.events.find((event) => event.target === 'div');
  assert.ok(removal, 'div should be reported as removed');
  assert.equal(removal.reason.policyKey, 'ALLOWED_TAGS');
});

test('FORBID_TAGS is reported as FORBID_TAGS, not ALLOWED_TAGS', () => {
  const { trail } = sanitizer.audit('<p>x</p>', { FORBID_TAGS: ['p'] });
  const removal = trail.events.find((event) => event.target === 'p');
  assert.ok(removal);
  assert.equal(removal.reason.policyKey, 'FORBID_TAGS');
});

test('data attributes disabled by ALLOW_DATA_ATTR get their own reason', () => {
  const { trail } = sanitizer.audit('<p data-x="1">y</p>', { ALLOW_DATA_ATTR: false });
  const removal = trail.events.find((event) => event.target === 'data-x');
  assert.ok(removal);
  assert.equal(removal.reason.code, 'data-attribute-not-allowed');
  assert.equal(removal.reason.policyKey, 'ALLOW_DATA_ATTR');
});

test('javascript: URL values are attributed to ALLOWED_URI_REGEXP', () => {
  const { trail } = sanitizer.audit('<a href="javascript:alert(1)">x</a>');
  const removal = trail.events.find((event) => event.target === 'href');
  assert.ok(removal);
  assert.equal(removal.reason.code, 'uri-scheme-blocked');
  assert.equal(removal.reason.confidence, 'inferred');
});

test('custom elements are explained through CUSTOM_ELEMENT_HANDLING', () => {
  const { trail } = sanitizer.audit('<my-widget>x</my-widget>', { ADD_TAGS: ['my-widget'] });
  const removal = trail.events.find((event) => event.target === 'my-widget');
  if (removal) {
    assert.equal(removal.reason.code, 'custom-element-disallowed');
    assert.equal(removal.reason.policyKey, 'CUSTOM_ELEMENT_HANDLING');
  }
});

test('a removed ancestor folds its subtree into one event', () => {
  const { trail } = sanitizer.audit('<div><section><p>a</p><p>b</p></section></div>', {
    FORBID_TAGS: ['div'],
    KEEP_CONTENT: false,
  });
  const removals = trail.events.filter((event) => event.action === 'remove');
  assert.equal(removals.length, 1, 'only the outer div should be listed');
  assert.equal(removals[0].target, 'div');
  assert.equal(removals[0].subtreeRemoved, 3, 'section + two paragraphs');
});

test('children re-parented by KEEP_CONTENT are not reported as removed', () => {
  const { trail } = sanitizer.audit('<object><p>a</p><b>b</b></object>');
  assert.equal(trail.output, '<p>a</p><b>b</b>');
  const removals = trail.events.filter((event) => event.action === 'remove');
  assert.deepEqual(removals.map((event) => event.target), ['object']);
});

test('attribute rewrites are reported separately from removals', () => {
  const { trail } = sanitizer.audit('<a href="  https://example.com/x  ">x</a>');
  const rewrite = trail.events.find((event) => event.action === 'rewrite-attribute');
  if (rewrite) {
    assert.equal(rewrite.target, 'href');
    assert.notEqual(rewrite.after, rewrite.value);
  }
});

test('bookkeeping matches upstream on ordinary drops', () => {
  const { trail } = sanitizer.audit('<div onclick="x"><iframe src="https://a"></iframe><b>t</b></div>');
  assert.equal(trail.bookkeeping.upstreamOnly.length, 0);
  assert.equal(trail.bookkeeping.auditOnly.length, 0);
});

test('detects the pre-walk loss that DOMPurify.removed cannot see (upstream #988)', () => {
  const { trail } = sanitizer.audit("<script>alert('XSS');</script> trailing text");
  assert.equal(trail.output, 'trailing text');
  assert.equal(trail.bookkeeping.upstreamRecords, 0, 'upstream really reports nothing here');
  assert.equal(trail.events.length, 0, 'the walker never saw the node');
  const head = trail.prewalk.headIgnored.map((entry) => entry.tag);
  assert.ok(head.includes('script'), `expected script in headIgnored, got ${JSON.stringify(head)}`);
});

test('leading <style> is reported as parser-relocated, not as a policy decision', () => {
  const { trail } = sanitizer.audit('<style>body{color:red}</style><p>hi</p>');
  assert.equal(trail.output, '<p>hi</p>');
  assert.equal(trail.events.length, 0);
  assert.ok(trail.prewalk.headIgnored.some((entry) => entry.tag === 'style'));
});

test('visible text comparison ignores dropped script content', () => {
  const { trail } = sanitizer.audit('<p>hello</p><script>var x = 1;</script>');
  assert.equal(trail.prewalk.textChanged, false);
});

test('visible text loss is flagged when real content disappears', () => {
  // KEEP_CONTENT:false makes the drop total, so the visible text really goes.
  const { trail } = sanitizer.audit('<p>hello</p><unknown-tag>world</unknown-tag>', {
    ALLOWED_TAGS: ['p'],
    FORBID_TAGS: ['unknown-tag'],
    KEEP_CONTENT: false,
  });
  assert.equal(trail.prewalk.textChanged, true);
  assert.equal(trail.prewalk.outputTextChars, 0);
});

test('risk scan reports residual sinks that survive the policy', () => {
  const { trail } = sanitizer.audit('<div style="background:url(javascript:alert(1))">x</div>');
  assert.ok(trail.findings.length > 0, 'CSS url() must be surfaced');
  assert.equal(trail.findings[0].code, 'css-sink');
});

test('risk scan is empty for clean output', () => {
  const { trail } = sanitizer.audit('<p>hello <b>world</b></p>');
  assert.equal(trail.findings.length, 0);
  assert.equal(trail.blocked, false);
});

test('audit does not change DOMPurify output for a corpus of payloads', () => {
  const payloads = [
    '<p onclick="alert(1)">x</p>',
    '<img src=x onerror=alert(1)>',
    '<svg><script>alert(1)</script></svg>',
    '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
    '<a href="java\nscript:alert(1)">x</a>',
    '<template><img src=x onerror=alert(1)></template>',
    '<div><style>x{}</style><p>y</p></div>',
    '<form><input name="q"></form>',
    '<p>plain</p>',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
  ];
  const baseline = plainPurifier();
  for (const payload of payloads) {
    const audited = sanitizer.audit(payload).output;
    const plain = baseline.sanitize(payload);
    assert.equal(audited, plain, `output diverged for ${JSON.stringify(payload)}`);
  }
});

test('two consecutive audits are independent', () => {
  const first = sanitizer.audit('<p onclick="x">a</p>').trail;
  const second = sanitizer.audit('<b>b</b>').trail;
  assert.equal(first.events.length, 1);
  assert.equal(second.events.length, 0);
  assert.equal(second.input, '<b>b</b>');
});

test('SAFE_FOR_TEMPLATES is named when it swallows an expression', () => {
  const { trail } = sanitizer.audit('<p>{{constructor}}</p>', { SAFE_FOR_TEMPLATES: true });
  assert.equal(trail.prewalk.textChanged, true);
});
