/**
 * Builds the static demo page: `demo/index.html` + `demo/data.js`.
 *
 * The demo is fully offline — the audit data is pre-computed at build time, so
 * the page has no runtime dependency and no network access.
 */
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { JSDOM } from 'jsdom';
import { createAuditedSanitizer } from '../src/index.js';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const factory = require('dompurify');
const createPurifier = factory.default || factory;
const window = new JSDOM('<!doctype html><html><body></body></html>').window;
const sanitizer = createAuditedSanitizer({ createDOMPurify: createPurifier, window });

const corpusDir = join(root, 'corpus');
const files = readdirSync(corpusDir)
  .filter((name) => /\.(html?|svg|txt)$/i.test(name))
  .sort();

const CONFIGS = {
  default: {},
  strict: {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'a'],
    ALLOWED_ATTR: ['href', 'title'],
  },
};

const entries = [];
for (const file of files) {
  const input = readFileSync(join(corpusDir, file), 'utf8');
  const byConfig = {};
  for (const [configName, config] of Object.entries(CONFIGS)) {
    const { output, trail } = sanitizer.audit(input, config);
    byConfig[configName] = {
      output,
      events: trail.events.map((event) => ({
        action: event.action,
        target: event.target,
        on: event.on,
        path: event.path,
        value: event.value,
        reason: event.reason.code,
        policyKey: event.reason.policyKey,
        confidence: event.reason.confidence,
        detail: event.reason.detail,
      })),
      findings: trail.findings.map((finding) => ({
        code: finding.code,
        severity: finding.severity,
        note: finding.note,
        evidence: finding.evidence,
      })),
      upstreamRecords: trail.bookkeeping.upstreamRecords,
      upstreamMismatch:
        trail.bookkeeping.auditOnly.length +
        trail.bookkeeping.upstreamOnly.filter((item) => !item.explained).length +
        trail.bookkeeping.auditOnlyAttributes.length +
        trail.bookkeeping.upstreamOnlyAttributes.length,
      headIgnored: trail.prewalk.headIgnored,
      textChanged: trail.prewalk.textChanged,
      stats: trail.stats,
    };
  }
  entries.push({ file, input: input.trim(), configs: byConfig });
}

const data = {
  generatedBy: 'npm run demo',
  dompurify: sanitizer.dompurify,
  purifytrace: sanitizer.version,
  configs: Object.keys(CONFIGS),
  entries,
};

mkdirSync(join(root, 'demo'), { recursive: true });
writeFileSync(join(root, 'demo', 'data.js'), `window.PURIFYTRACE_DATA = ${JSON.stringify(data, null, 2)};\n`, 'utf8');
writeFileSync(join(root, 'demo', 'index.html'), readFileSync(join(here, 'demo-template.html'), 'utf8'), 'utf8');

console.log(`demo written: demo/index.html + demo/data.js (${entries.length} payloads)`);
