// Offline test of the data sources registry (data/data_sources.json) and its check (pipeline/check_data_sources.mjs):
// the real file passes, and each rule fails a deliberately broken copy.
// node test/data_sources_test.mjs <repository root>   (after python3 pipeline/collector_build.py .)
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';

const ROOT = path.resolve(process.argv[2] || '.');
const K = await import(path.join(ROOT, 'pipeline', 'check_data_sources.mjs'));
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };
const text = fs.readFileSync(path.join(ROOT, 'data', 'data_sources.json'), 'utf8');
const REG = JSON.parse(text);
const C = K.context(ROOT), F = await K.collectorFacts(ROOT);
const clone = () => JSON.parse(JSON.stringify(REG));
const errs = (reg) => K.check(reg, JSON.stringify(reg), C, F);
const has = (reg, re) => errs(reg).some((e) => re.test(e));

// The inputs the check compares against are the real ones.
ok(C.datasets.length >= 60 && C.datasets.includes('kev') && C.datasets.includes('live_sec8k'), 'site.json datasets read from pipeline/datasets.py: ' + C.datasets.length);
ok(['cables', 'gdelt', 'retention', 'sec8k'].every((j) => C.jobs.includes(j)), 'lease jobs read from neon/schema.sql: ' + C.jobs.join(','));
ok(!F.health.includes('overpass') && F.health.includes('wikidata') && !F.health.includes('greynoise') && !F.health.includes('hibp') && F.health.length >= 28, 'health feed ids from the collector: ' + F.health.length);
ok(['gdelt_doc_api', 'marad_msci', 'nga_asam', 'nga_msi', 'ukmto'].every((g) => F.gaps.includes(g)) && !F.gaps.includes('greynoise'), 'known gaps from the collector: ' + F.gaps.join(','));
ok(C.pages.includes('sources') && C.pages.includes('map'), 'page ids from public/index.html');

// The real registry passes.
const real = errs(REG);
ok(real.length === 0, 'the registry passes: ' + real.slice(0, 5).join(' | '));
ok(REG.rows.length >= 90 && REG.rows.every((r) => r.licence), 'every row has a licence (' + REG.rows.length + ' rows)');

// Each rule fails a broken copy.
{ const r = clone(); r.rows = r.rows.filter((x) => x.health_feed !== 'wikidata'); ok(has(r, /health feed wikidata has no row/), 'a collector feed without a row fails'); }
{ const r = clone(); r.rows = r.rows.filter((x) => !x.feeds.includes('ics_advisories')); ok(has(r, /dataset ics_advisories \(site\.json\) has no row/), 'a site.json dataset without a row fails'); }
{ const r = clone(); for (const x of r.rows) x.jobs = x.jobs.filter((j) => j !== 'cables'); ok(has(r, /lease job cables has no row/), 'a lease job without a row fails'); }
{ const r = clone(); r.rows.find((x) => x.id === 'marad').status = 'live'; ok(has(r, /known gap marad_msci \(KNOWN_GAPS\) has no known_gap row/), 'a documented gap not marked known_gap fails'); }
{ const r = clone(); const x = r.rows.find((y) => y.id === 'tranco'); x.status = 'known_gap'; x.gap_note = 'x'; ok(has(r, /names tranco, which KNOWN_GAPS does not list/), 'a known_gap row the collector does not list fails'); }
{ const r = clone(); r.rows[3].licence = ''; ok(has(r, /no licence/), 'a row without a licence fails'); }
{ const r = clone(); r.rows[0].feeds.push('kevv'); ok(has(r, /unknown dataset kevv/), 'a typo in a dataset id fails'); }
{ const r = clone(); r.rows[0].status = 'maybe'; ok(has(r, /status maybe not one of/), 'an unknown status fails'); }
{ const r = clone(); r.rows.push({ ...r.rows[0] }); ok(has(r, /duplicate id/), 'a duplicate id fails'); }
{ const r = clone(); r.rows.find((x) => x.id === 'nasa-firms').secret = { name: 'FIRMS_MAP_KEY', where: 'neon_function_variable', value: 'x' }; ok(has(r, /secret must be/), 'a secret with any field beyond name and where fails'); }
{ const r = clone(); r.rows.find((x) => x.id === 'nasa-firms').secret = null; ok(has(r, /access "key" needs a secret name/), 'a keyed source without a secret name fails'); }
{ const r = clone(); r.rows.find((x) => x.id === 'cand-ucdp').gap_note = ''; ok(has(r, /status candidate needs a gap_note/), 'a candidate without a reason fails'); }
// Key-shaped strings anywhere fail, wherever they sit.
for (const [label, s] of [['AWS key id', 'AKIA' + 'ABCDEFGHIJKLMNOP'], ['GitHub token', 'ghp_' + 'a'.repeat(36)], ['Neon storage key', 'nak_live_' + '0123456789abcdef'],
  ['connection string', 'postgresql://ti_app:' + 'pw@ep-x.neon.tech/db'], ['bearer token', 'Bearer ' + 'abcdefghijklmnopqrstuvwxyz'], ['JWT', 'eyJ' + 'hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig'],
  ['presigned URL', 'https://x/y?X-Amz-Signature=' + 'abc'], ['long hex', 'e3b0c442' + '98fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'], ['private key', '-----BEGIN RSA PRIVATE KEY-----']]) {
  const r = clone(); r.rows[5].note = 'pasted ' + s;
  ok(has(r, /key-shaped string/), 'a ' + label + ' in a note fails');
}
ok(K.keyShaped(text).length === 0, 'the real file holds no key-shaped string');
ok(REG.rows.every((r) => r.secret == null || (Object.keys(r.secret).join() === 'name,where')), 'secrets by name and location only');

// Item 3 statuses carried into the registry.
const by = Object.fromEntries(REG.rows.map((r) => [r.id, r]));
ok(by['osm-cables'].licence === 'ODbL-1.0' && by['osm-cables'].attribution === '© OpenStreetMap contributors' && by['wikidata-cables'].licence === 'CC0-1.0' && by.telegeography.status === 'declined', 'cables sources and TeleGeography declined');
ok(['cand-usgs-earthquakes', 'cand-gdacs', 'cand-eonet', 'cand-cloudflare-radar', 'cand-ooni', 'cand-ripestat', 'cand-aisstream', 'cand-gfw', 'cand-reliefweb', 'cand-acled', 'cand-ucdp'].every((id) => by[id] && by[id].status === 'candidate'),
  'the candidate sources Sean asked about are rows');
ok(Object.values(by).filter((r) => r.status === 'candidate' && /unverified/.test(r.licence)).every((r) => r.terms_verified === false), 'unverified terms say so');

// The page: standalone, marked, no outside scripts or styles, linked from the Sources tab and the footer only.
{
  const page = fs.readFileSync(path.join(ROOT, 'public', 'data-sources.html'), 'utf8');
  const js = fs.readFileSync(path.join(ROOT, 'public', 'js', 'data-sources.js'), 'utf8');
  const index = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
  ok(/TLP:GREEN/.test(page) && /href="\/data-sources\.json"/.test(page) && /\/css\/tokens\.css/.test(page) && /\/runtime\/theme\.js/.test(page), 'page: marking, registry link, site theme');
  ok(![...page.matchAll(/<(?:script|link)[^>]+(?:src|href)="(https?:)?\/\/[^"]+"/g)].length && !/innerHTML/.test(js), 'page: no outside scripts or styles, text set without innerHTML');
  ok((index.match(/href="\/data-sources"/g) || []).length === 2 && !/data-page="data-sources"/.test(index), 'linked from the Sources tab and the footer, not a new tab');
  ok(/\/api\/health/.test(js) && /attribution/.test(js), 'page reads live status and renders the attribution block');
  const vj = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
  ok(vj.rewrites.some((r) => r.source === '/data-sources' && r.destination === '/data-sources.html'), '/data-sources served');
  ok(/data-sources\.json/.test(fs.readFileSync(path.join(ROOT, 'pipeline', 'site_build.py'), 'utf8')), 'the site build publishes the registry');
}

console.log(`PASS ${pass} checks (data sources registry)`);
