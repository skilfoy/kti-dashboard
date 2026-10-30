// End-to-end check of the site in Chromium: every page at desktop (1400px) and phone (390px) widths, in light and
// dark, with no script error, no Content-Security-Policy violation and no horizontal scroll; built datasets must load.
//   node test/e2e.mjs [--url http://localhost:4173] [--shots DIR] [--live-optional]
// Without --url it starts test/dev_server.mjs itself (service offline unless --live DIR is passed through).
// --live-optional: panels fed by live queries may show "Failed to load"/"unavailable" (the service is offline in CI).
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
let URL_ = arg('--url', '');
const SHOTS = arg('--shots', '');
const LIVE = arg('--live', '');
const LIVE_OPTIONAL = process.argv.includes('--live-optional');
let server = null;
if (!URL_) {
  const port = 4300 + Math.floor(Math.random() * 500);
  server = spawn(process.execPath, [path.join(ROOT, 'test', 'dev_server.mjs'), '--port', String(port), ...(LIVE ? ['--live', LIVE] : [])], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((r) => server.stdout.once('data', r));
  URL_ = `http://localhost:${port}`;
}
if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });

const site = await (await fetch(URL_ + '/site.json')).json();
const fileIds = Object.entries(site.datasets).filter(([, d]) => d.kind === 'file').map(([id]) => id);
const browser = await chromium.launch();
const problems = [];
const report = [];
for (const [w, h] of [[1400, 900], [390, 844]]) {
  for (const scheme of ['light', 'dark']) {
    const ctx = await browser.newContext({ viewport: { width: w, height: h }, colorScheme: scheme, deviceScaleFactor: 1 });
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
    page.on('console', (m) => { if (m.type() === 'error' && !/Failed to load resource: the server responded with a status of 50[23]/.test(m.text())) errors.push('console: ' + m.text()); });
    await page.addInitScript(() => { window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' ' + (e.blockedURI || '') + ' ' + (e.sourceFile || '') + ':' + e.lineNumber)); });
    await page.goto(URL_ + '/', { waitUntil: 'load' });
    await page.waitForFunction((ids) => window.dash && ids.every((id) => ['ok', 'error', 'missing'].includes(window.dash.data(id).status)), fileIds, { timeout: 60000 });
    const fileFail = await page.evaluate((ids) => ids.filter((id) => window.dash.data(id).status !== 'ok'), fileIds);
    if (fileFail.length) problems.push(`${w}px ${scheme}: built datasets did not load: ${fileFail.join(', ')}`);
    const tabs = await page.$$eval('.ti-tab', (b) => b.map((x) => x.dataset.page));
    for (const t of tabs) {
      await page.click(`#tab-${t}`);
      await page.waitForTimeout(t === 'map' ? 2500 : 900);
      const st = await page.evaluate(() => ({
        overflow: document.documentElement.scrollWidth - window.innerWidth,
        failed: [...document.querySelectorAll('.ti-page:not([hidden]) .ti-failed')].map((e) => (e.closest('[id]') || {}).id || '?'),
        skeleton: [...document.querySelectorAll('.ti-page:not([hidden]) .dash-skeleton')].map((e) => e.id || (e.closest('[id]') || {}).id || '?'),
        csp: window.__csp.slice(),
      }));
      if (st.overflow > 1) problems.push(`${w}px ${scheme} ${t}: page scrolls sideways by ${st.overflow}px`);
      if (st.csp.length) problems.push(`${w}px ${scheme} ${t}: CSP violations: ${[...new Set(st.csp)].join(' | ')}`);
      if (st.failed.length && !LIVE_OPTIONAL) problems.push(`${w}px ${scheme} ${t}: failed panels: ${[...new Set(st.failed)].join(', ')}`);
      report.push({ w, scheme, tab: t, failed: [...new Set(st.failed)], loading: [...new Set(st.skeleton)].slice(0, 8) });
      if (SHOTS) await page.screenshot({ path: path.join(SHOTS, `${t}-${w}-${scheme}.png`), fullPage: false });
    }
    // The theme control cycles auto -> dark -> light and sets the document root, so the whole page follows it.
    await page.click('#tab-brief');
    await page.click('#ti-theme');
    const root = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
    if (root !== 'dark') problems.push(`${w}px ${scheme}: theme control did not set the root theme (got ${root})`);
    if (errors.length) problems.push(`${w}px ${scheme}: ${[...new Set(errors)].slice(0, 10).join(' | ')}`);
    await ctx.close();
  }
}
await browser.close();
if (server) server.kill();
for (const r of report) if (r.failed.length || r.loading.length) console.log(`${r.w}px ${r.scheme} ${r.tab}: failed [${r.failed.join(', ')}] loading [${r.loading.join(', ')}]`);
if (problems.length) { console.error('E2E FAILED\n - ' + problems.join('\n - ')); process.exit(1); }
console.log(`PASS e2e: ${report.length} page views (${new Set(report.map((r) => r.tab)).size} pages x 2 widths x 2 themes), no script errors, no CSP violations, no sideways scroll`);
