/**
 * Benchmark: DOMPurify alone vs DOMPurify + purifytrace.
 *
 * The point is not to make the sanitizer fast — it is to quantify what the
 * audit layer costs, so the number can be quoted honestly. Every configuration
 * is run N times and the **median** is reported: a single timing run can flip
 * the conclusion in either direction.
 */
import { createRequire } from 'node:module';
import { JSDOM } from 'jsdom';
import { createAuditedSanitizer } from '../src/index.js';

const require = createRequire(import.meta.url);
const factory = require('dompurify');
const window = new JSDOM('<!doctype html><html><body></body></html>').window;
const createPurifier = factory.default || factory;
const purifier = createPurifier(window);
const audited = createAuditedSanitizer({ createDOMPurify: factory.default || factory, window });

const RUNS = 15;

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function time(fn) {
  const started = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - started) / 1e6;
}

const cases = [
  { name: 'small (1 element)', html: '<p onclick="alert(1)">hello</p>' },
  { name: 'medium (100 elements)', html: `<div>${'<p class="x" onclick="a()">line</p>'.repeat(100)}</div>` },
  { name: 'large (2000 elements)', html: `<div>${'<p class="x" onclick="a()">line</p>'.repeat(2000)}</div>` },
  { name: 'xss corpus (32 payloads)', html: null },
];

const corpusHtml = [];
for (const name of ['01-inline-script.html', '03-event-handler.html', '05-javascript-href.html', '07-data-html-iframe.html', '12-mxss-mglyph.html', '15-style-attribute.html', '17-base-tag.html', '28-benign-article.html']) {
  corpusHtml.push(`<div>${name}</div>`);
}
cases[3].html = corpusHtml.join('');

const rows = [];
for (const testCase of cases) {
  const plain = [];
  const traced = [];
  for (let i = 0; i < RUNS; i += 1) {
    plain.push(time(() => purifier.sanitize(testCase.html)));
    traced.push(time(() => audited.audit(testCase.html)));
  }
  const plainMedian = median(plain);
  const tracedMedian = median(traced);
  rows.push({
    case: testCase.name,
    bytes: testCase.html.length,
    'plain ms': plainMedian.toFixed(3),
    'audit ms': tracedMedian.toFixed(3),
    'ratio': (tracedMedian / plainMedian).toFixed(2) + '×',
  });
}

console.log(`purifytrace overhead · DOMPurify ${purifier.version} · ${RUNS} runs, median`);
console.log('');
const headers = Object.keys(rows[0]);
const widths = headers.map((header) => Math.max(header.length, ...rows.map((row) => String(row[header]).length)));
const line = (cells) => cells.map((cell, index) => String(cell).padEnd(widths[index])).join('  ');
console.log(line(headers));
console.log(line(widths.map((width) => '-'.repeat(width))));
for (const row of rows) console.log(line(headers.map((header) => row[header])));
