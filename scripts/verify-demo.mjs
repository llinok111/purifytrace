/**
 * Demo page verification.
 *
 * Renders demo/index.html in a real browser, takes a screenshot and probes the
 * DOM for the states the page must show. Exits non-zero when anything is off.
 *
 * playwright-core is intentionally NOT a dependency of this package: it is
 * resolved from PLAYWRIGHT_PATH (or a local checkout) so a consumer of the
 * library never has to install a browser stack.
 */
import { createRequire } from 'node:module';
import { existsSync, readFileSync, mkdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const shotsDir = join(root, 'shots');

function loadPlaywright() {
  const candidates = [
    process.env.PLAYWRIGHT_PATH,
    join(root, 'node_modules', 'playwright-core'),
    join(root, '..', '_uiverify', 'node_modules', 'playwright-core'),
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      const require = createRequire(join(resolve(candidate), 'index.js'));
      return require('playwright-core');
    }
  }
  throw new Error(
    'playwright-core not found. Set PLAYWRIGHT_PATH to a playwright-core install directory.'
  );
}

const { chromium } = loadPlaywright();

const EXECUTABLE = process.env.CHROME_PATH;
const browser = await chromium.launch({
  headless: true,
  ...(EXECUTABLE ? { executablePath: EXECUTABLE } : {}),
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
});

const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const page = await context.newPage();

const consoleErrors = [];
const failedRequests = [];
page.on('console', (message) => {
  if (message.type() === 'error') consoleErrors.push(message.text());
});
page.on('pageerror', (error) => consoleErrors.push(String(error)));
page.on('requestfailed', (request) => failedRequests.push(`${request.url()} ${request.failure()?.errorText}`));

mkdirSync(shotsDir, { recursive: true });
const url = pathToFileURL(join(root, 'demo', 'index.html')).href;
await page.goto(url, { waitUntil: 'load' });
await page.waitForTimeout(400);

const probe = await page.evaluate(() => {
  const fileButtons = document.querySelectorAll('#filelist button');
  const first = fileButtons[0];
  if (first) first.click();
  return {
    title: document.title,
    meta: document.getElementById('meta')?.textContent || '',
    fileCount: fileButtons.length,
    hasData: typeof window.PURIFYTRACE_DATA === 'object',
    dataEntries: window.PURIFYTRACE_DATA ? window.PURIFYTRACE_DATA.entries.length : 0,
    contentRendered: document.getElementById('content').children.length > 0,
    externalResources: Array.from(document.querySelectorAll('script[src], link[href]'))
      .map((node) => node.getAttribute('src') || node.getAttribute('href'))
      .filter((value) => value && !value.startsWith('data.js')),
  };
});

await page.waitForTimeout(200);
const afterClick = await page.evaluate(() => ({
  panels: document.querySelectorAll('#content .panel').length,
  statBoxes: document.querySelectorAll('#content .stat').length,
  activeFile: document.querySelector('#filelist button.active')?.textContent || '',
}));

// Switch to a payload that produces events, so the events table is exercised.
const scripted = await page.evaluate(() => {
  const buttons = Array.from(document.querySelectorAll('#filelist button'));
  const target = buttons.find((button) => button.textContent.includes('03-event-handler'));
  if (target) target.click();
  return Boolean(target);
});
await page.waitForTimeout(200);
const withEvents = await page.evaluate(() => ({
  rows: document.querySelectorAll('#content table tbody tr').length,
  headers: Array.from(document.querySelectorAll('#content table thead th')).map((th) => th.textContent),
}));

await page.screenshot({ path: join(shotsDir, 'demo.png'), fullPage: false });

// Search filter
const filtered = await page.evaluate(() => {
  const search = document.getElementById('search');
  search.value = 'benign';
  search.dispatchEvent(new Event('input'));
  return document.querySelectorAll('#filelist button').length;
});

await browser.close();

const problems = [];
if (consoleErrors.length > 0) problems.push(`console errors: ${consoleErrors.join(' | ')}`);
if (failedRequests.length > 0) problems.push(`failed requests: ${failedRequests.join(' | ')}`);
if (probe.externalResources.length > 0) problems.push(`external resources: ${probe.externalResources.join(', ')}`);
if (!probe.hasData) problems.push('PURIFYTRACE_DATA missing');
if (probe.dataEntries < 30) problems.push(`only ${probe.dataEntries} payloads in the data`);
if (probe.fileCount < 30) problems.push(`only ${probe.fileCount} file buttons rendered`);
if (!probe.contentRendered) problems.push('content panel not rendered');
if (afterClick.panels < 3) problems.push(`expected ≥3 panels, got ${afterClick.panels}`);
if (afterClick.statBoxes < 4) problems.push(`expected ≥4 stat boxes, got ${afterClick.statBoxes}`);
if (!scripted) problems.push('could not click the event-handler payload');
if (withEvents.rows < 1) problems.push('events table is empty for a payload that must produce events');
if (filtered < 1 || filtered >= probe.fileCount) problems.push(`search filter did not narrow the list (${filtered})`);

const report = {
  title: probe.title,
  meta: probe.meta,
  payloads: probe.dataEntries,
  panels: afterClick.panels,
  statBoxes: afterClick.statBoxes,
  eventRows: withEvents.rows,
  eventColumns: withEvents.headers,
  filteredFiles: filtered,
  consoleErrors,
  failedRequests,
  externalResources: probe.externalResources,
  screenshot: join(shotsDir, 'demo.png'),
  problems,
};
console.log(JSON.stringify(report, null, 2));

if (problems.length > 0) {
  console.error(`\ndemo verification FAILED:\n- ${problems.join('\n- ')}`);
  process.exit(1);
}
console.log('\ndemo verification passed');
