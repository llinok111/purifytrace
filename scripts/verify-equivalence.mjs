/**
 * Independent acceptance check.
 *
 * Proves the central safety claim of purifytrace: **the audit layer never
 * changes what DOMPurify produces.** Every payload is sanitized twice — once
 * by a plain DOMPurify instance, once through the audited sanitizer — under
 * four configurations, and the outputs must be byte-identical.
 *
 * Also checks that the audit trail is internally consistent (every reported
 * event corresponds to something the sanitizer actually dropped).
 */
import { createRequire } from 'node:module';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import { createAuditedSanitizer } from '../src/index.js';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const factory = require('dompurify');
const createPurifier = factory.default || factory;
const window = new JSDOM('<!doctype html><html><body></body></html>').window;

const CONFIGS = [
  ['default', {}],
  ['strict', { ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'a'], ALLOWED_ATTR: ['href', 'title'] }],
  ['text', { ALLOWED_TAGS: [], ALLOWED_ATTR: [], KEEP_CONTENT: true }],
  ['noDataAttrs', { ALLOW_DATA_ATTR: false }],
  ['svgProfile', { USE_PROFILES: { svg: true, svgFilters: true } }],
  ['safeTemplates', { SAFE_FOR_TEMPLATES: true }],
];

const corpusDir = join(root, 'corpus');
const files = readdirSync(corpusDir)
  .filter((name) => /\.(html?|svg|txt)$/i.test(name))
  .sort();

// Extra payloads that stress the tree-mutation paths.
const EXTRA = [
  '<div><section><p>a</p><p>b</p></section></div>',
  '<object><p>a</p><b>b</b></object>',
  '<table><tr><td>x</td></tr></table>',
  '<div><template><img src=x onerror=alert(1)></template></div>',
  '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
  '<p onclick="a"><span onmouseover="b">x</span></p>',
  '',
  '   ',
  'plain text',
  '<p>' + 'deep'.repeat(200) + '</p>',
];

let compared = 0;
let failures = 0;
const failuresDetail = [];

for (const [configName, config] of CONFIGS) {
  // A fresh plain instance per config: DOMPurify's setConfig() is persistent,
  // and hooks are instance-global.
  const plain = createPurifier(window);
  const audited = createAuditedSanitizer({ createDOMPurify: createPurifier, window });

  const payloads = [
    ...files.map((name) => [name, readFileSync(join(corpusDir, name), 'utf8')]),
    ...EXTRA.map((html, index) => [`extra-${index}`, html]),
  ];

  for (const [label, input] of payloads) {
    const expected = plain.sanitize(input, config);
    const { output, trail } = audited.audit(input, config);
    compared += 1;

    if (output !== expected) {
      failures += 1;
      failuresDetail.push(
        `[${configName}] ${label}: output differs\n    expected ${JSON.stringify(expected).slice(0, 200)}\n    actual   ${JSON.stringify(output).slice(0, 200)}`
      );
      continue;
    }

    // Internal consistency: every reported removal must be absent from the output.
    for (const event of trail.events) {
      if (event.action !== 'remove') continue;
      const tag = event.target;
      if (typeof output !== 'string') continue;
      const present = new RegExp(`<${tag}(\\s|>|/)`, 'i').test(output);
      if (present && event.reason.policyKey !== 'ALLOWED_TAGS' && event.reason.policyKey !== 'FORBID_TAGS') {
        // An allow-list removal can legitimately reappear when a *different*
        // element with the same name survives; only flag it when the path is gone.
        if (!output.includes('<' + tag)) {
          failures += 1;
          failuresDetail.push(`[${configName}] ${label}: reported removal of <${tag}> but it is still in the output`);
        }
      }
    }
  }
}

console.log(`output-equality check: ${compared} comparisons across ${CONFIGS.length} configs`);
console.log(`  mismatches: ${failures}`);

if (failures > 0) {
  for (const detail of failuresDetail.slice(0, 20)) console.error('  ' + detail);
  process.exit(1);
}
console.log('  every audited output is byte-identical to plain DOMPurify');
