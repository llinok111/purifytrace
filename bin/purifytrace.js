#!/usr/bin/env node
/**
 * purifytrace CLI.
 *
 * Exit codes (stable, documented in README):
 *   0  audit completed, no high-severity residual sink
 *   1  audit completed, at least one high-severity residual sink
 *   2  usage / environment / input error (never "silently passed")
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve, basename } from 'node:path';
import { createRequire } from 'node:module';
import { createAuditedSanitizer } from '../src/index.js';
import { renderText, renderJson, renderSarif, diffTrails, renderDiffText } from '../src/report.js';

const require = createRequire(import.meta.url);

const PRESETS = {
  default: {},
  strict: { ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'a'], ALLOWED_ATTR: ['href', 'title'] },
  text: { ALLOWED_TAGS: [], ALLOWED_ATTR: [], KEEP_CONTENT: true },
  safeForTemplates: { SAFE_FOR_TEMPLATES: true },
  noDataAttrs: { ALLOW_DATA_ATTR: false },
  svgProfile: { USE_PROFILES: { svg: true, svgFilters: true } },
  htmlProfile: { USE_PROFILES: { html: true } },
};

function usage(code = 2, message = '') {
  const out = [
    message ? `error: ${message}` : '',
    'usage:',
    '  purifytrace <file|-> [options]            audit one payload',
    '  purifytrace --corpus <dir> [options]      audit every file in a directory',
    '  purifytrace --diff <presetA> <presetB> <file>   compare two policies',
    '',
    'options:',
    '  --config <preset|file.json>   DOMPurify config (preset name or JSON file)',
    '  --format text|json|sarif      output format (default text)',
    '  --dom jsdom|global            DOM implementation (default jsdom)',
    '  --strict-exit                 exit 1 on any finding, not just high',
    '  --quiet                       suppress per-item text, print summary only',
    '  --presets                     list built-in presets',
  ].filter(Boolean).join('\n');
  console.log(out);
  process.exit(code);
}

function loadDom(kind) {
  if (kind === 'global') {
    if (typeof globalThis.DOMParser !== 'function' || typeof globalThis.document !== 'object') {
      throw new Error('--dom global requested but no global DOM is present');
    }
    return globalThis;
  }
  let jsdom;
  try {
    jsdom = require('jsdom');
  } catch {
    throw new Error(
      'jsdom is not installed. Install it (npm i jsdom) or run with --dom global inside a DOM runtime.'
    );
  }
  return new jsdom.JSDOM('<!doctype html><html><body></body></html>').window;
}

function loadPurifier(window) {
  // Resolve the installed DOMPurify build relative to this package so the CLI
  // always audits the same version it reports.
  const candidates = ['dompurify'];
  for (const id of candidates) {
    try {
      const mod = require(id);
      const factory = mod.default || mod;
      if (typeof factory === 'function') return factory(window);
    } catch {
      /* try next */
    }
  }
  throw new Error('DOMPurify not found. Install dompurify or run from the repository that vendors it.');
}

function loadConfig(spec) {
  if (!spec) return {};
  if (Object.prototype.hasOwnProperty.call(PRESETS, spec)) return { ...PRESETS[spec] };
  if (spec.endsWith('.json')) {
    const raw = JSON.parse(readFileSync(spec, 'utf8'));
    // JSON has no RegExp; allow `"ALLOWED_URI_REGEXP": "/.../i"` string form.
    for (const key of Object.keys(raw)) {
      const value = raw[key];
      if (typeof value === 'string' && value.startsWith('/') && /\/[gimsuy]*$/.test(value)) {
        const end = value.lastIndexOf('/');
        raw[key] = new RegExp(value.slice(1, end), value.slice(end + 1));
      }
    }
    return raw;
  }
  throw new Error(`unknown config "${spec}" — use a preset name or a .json path (see --presets)`);
}

function readInput(path) {
  if (path === '-') return readFileSync(0, 'utf8');
  if (!existsSync(path)) throw new Error(`no such file: ${path}`);
  return readFileSync(path, 'utf8');
}

function listCorpus(dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    const stat = statSync(full);
    if (stat.isFile() && /\.(html?|xhtml|svg|txt)$/i.test(name)) out.push(full);
  }
  return out;
}

function parseArgs(argv) {
  const args = { positional: [], options: {} };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--corpus') args.options.corpus = argv[++i];
    else if (token === '--config') args.options.config = argv[++i];
    else if (token === '--format') args.options.format = argv[++i];
    else if (token === '--dom') args.options.dom = argv[++i];
    else if (token === '--diff') args.options.diff = [argv[++i], argv[++i]];
    else if (token === '--strict-exit') args.options.strictExit = true;
    else if (token === '--quiet') args.options.quiet = true;
    else if (token === '--presets') args.options.presets = true;
    else if (token === '--help' || token === '-h') args.options.help = true;
    else if (token.startsWith('--')) usage(2, `unknown option ${token}`);
    else args.positional.push(token);
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.options.help) usage(0);
  if (args.options.presets) {
    console.log(Object.keys(PRESETS).join('\n'));
    return;
  }

  const format = args.options.format || 'text';
  if (!['text', 'json', 'sarif'].includes(format)) usage(2, `unknown --format ${format}`);

  const window = loadDom(args.options.dom || 'jsdom');
  const purifier = loadPurifier(window);
  const sanitizer = createAuditedSanitizer({
    createDOMPurify: () => purifier,
    window,
  });

  if (args.options.diff) {
    const [presetA, presetB] = args.options.diff;
    const target = args.positional[0];
    if (!target) usage(2, '--diff needs an input file');
    const input = readInput(target);
    const before = sanitizer.audit(input, loadConfig(presetA)).trail;
    const after = sanitizer.audit(input, loadConfig(presetB)).trail;
    const diff = diffTrails(before, after);
    console.log(format === 'json' ? JSON.stringify(diff, null, 2) : renderDiffText(diff, presetA, presetB));
    const delta = diff.findings.after.high - diff.findings.before.high;
    process.exit(delta > 0 || (args.options.strictExit && diff.findings.after.total > 0) ? 1 : 0);
  }

  const config = loadConfig(args.options.config);
  let worst = 0;
  let anyHigh = false;

  const emit = (label, input) => {
    const { trail } = sanitizer.audit(input, config);
    if (format === 'json') {
      console.log(JSON.stringify({ label, ...trail }, null, 2));
    } else if (format === 'sarif') {
      console.log(renderSarif(trail, { uri: label }));
    } else if (!args.options.quiet) {
      console.log(`\n===== ${label} =====`);
      console.log(renderText(trail));
    }
    if (trail.findings.some((f) => f.severity === 'high')) anyHigh = true;
    if (args.options.strictExit && trail.findings.length > 0) anyHigh = true;
    return trail;
  };

  if (args.options.corpus) {
    const files = listCorpus(resolve(args.options.corpus));
    if (files.length === 0) usage(2, `no .html/.svg/.txt files in ${args.options.corpus}`);
    const rows = [];
    for (const file of files) {
      const trail = emit(basename(file), readFileSync(file, 'utf8'));
      rows.push({
        file: basename(file),
        events: trail.events.length,
        high: trail.findingSummary.high,
        medium: trail.findingSummary.medium,
        low: trail.findingSummary.low,
        upstreamMismatch:
          trail.bookkeeping.auditOnly.length +
          trail.bookkeeping.upstreamOnly.filter((item) => !item.explained).length +
          trail.bookkeeping.auditOnlyAttributes.length +
          trail.bookkeeping.upstreamOnlyAttributes.length,
        prewalk: trail.prewalk.headIgnored.length + trail.prewalk.bodyUnseen.length + (trail.prewalk.textChanged ? 1 : 0),
      });
    }
    if (format === 'text') {
      const head = ['file', 'events', 'high', 'med', 'low', 'mismatch', 'prewalk'];
      const widths = head.map((h, index) =>
        Math.max(h.length, ...rows.map((row) => String(Object.values(row)[index]).length))
      );
      const line = (cells) => cells.map((cell, index) => String(cell).padEnd(widths[index])).join('  ');
      console.log('');
      console.log(line(head));
      console.log(line(widths.map((w) => '-'.repeat(w))));
      for (const row of rows) console.log(line(Object.values(row)));
      const totals = rows.reduce(
        (acc, row) => ({
          events: acc.events + row.events,
          high: acc.high + row.high,
          med: acc.med + row.medium,
          low: acc.low + row.low,
          mismatch: acc.mismatch + row.upstreamMismatch,
          prewalk: acc.prewalk + row.prewalk,
        }),
        { events: 0, high: 0, med: 0, low: 0, mismatch: 0, prewalk: 0 }
      );
      console.log('');
      console.log(`files ${rows.length} · events ${totals.events} · high ${totals.high} · medium ${totals.med} · low ${totals.low}`);
      console.log(`upstream mismatches ${totals.mismatch} · pre-walk losses ${totals.prewalk}`);
    }
    worst = anyHigh ? 1 : 0;
    process.exit(worst);
  }

  const target = args.positional[0];
  if (!target) usage(2, 'no input given');
  emit(target === '-' ? '<stdin>' : target, readInput(target));
  process.exit(anyHigh ? 1 : 0);
}

try {
  main();
} catch (error) {
  console.error(`purifytrace: ${error && error.message ? error.message : error}`);
  process.exit(2);
}
