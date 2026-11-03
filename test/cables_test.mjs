// Offline test of the submarine cables job (neon/parts/37e-cables.mjs) and its /api/context?type=cables route: fixture
// Overpass and Wikidata answers, real Postgres (PGlite) behind a fake Neon SQL endpoint, an in-memory bucket, no network.
// Covers the User-Agent and Accept headers, mirror fallback, 429 back-off, coordinate validation and stripped OSM
// metadata, the antimeridian split, the payload cap, the exact-name Wikidata join (no fuzzy match), hold-last-good, the
// licence and attribution on every answer, and the GeoJSON open file.
// node test/cables_test.mjs <repository root>   (after python3 pipeline/collector_build.py .)
import { PGlite } from '@electric-sql/pglite';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const ROOT = path.resolve(process.argv[2] || '.');
const require = createRequire(path.join(ROOT, 'node_modules', 'x.js'));
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };
const OVERPASS = JSON.parse(fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'overpass_cables.json'), 'utf8'));
const WIKIDATA = JSON.parse(fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'wikidata_cables.json'), 'utf8'));

const db = await PGlite.create();
await db.exec(fs.readFileSync(path.join(ROOT, 'neon', 'schema.sql'), 'utf8'));
const RAW = Object.fromEntries(Array.from({ length: 6000 }, (_, i) => [i, (v) => v]));
const runSql = async (q, params) => { const r = await db.query(q, params, { rowMode: 'array', parsers: RAW }); return { fields: r.fields, rows: r.rows }; };
process.env.DATABASE_URL = 'postgresql://ti_app:pw@ep-test-pooler.c-14.us-east-1.aws.neon.tech/threatintel?sslmode=require';
process.env.AWS_ENDPOINT_URL_S3 = 'https://br-test.storage.c-14.us-east-1.aws.neon.tech';
process.env.AWS_ACCESS_KEY_ID = 'nak_test'; process.env.AWS_SECRET_ACCESS_KEY = 'nsk_test';
process.env.SEC_USER_AGENT = 'Test Operator ops@example.org';
const bucket = new Map();
const seen = [];
let overpassPlan = []; // per call: 'ok' | status number | 'net'
let wikidataStatus = 200;
const resp = (status, body, headers = {}) => new Response(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body), { status, headers });
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url), h = Object.fromEntries(Object.entries(opts.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
  if (u === 'https://api.c-14.us-east-1.aws.neon.tech/sql') {
    const body = JSON.parse(opts.body);
    try {
      if (body.queries) { await db.exec('BEGIN'); try { const results = []; for (const q of body.queries) results.push(await runSql(q.query, q.params)); await db.exec('COMMIT'); return resp(200, { results }); } catch (e) { await db.exec('ROLLBACK'); throw e; } }
      return resp(200, await runSql(body.query, body.params));
    } catch (e) { return resp(400, { message: e.message }); }
  }
  if (u.startsWith(process.env.AWS_ENDPOINT_URL_S3 + '/')) {
    const key = decodeURIComponent(new URL(u).pathname.slice(1));
    if (opts.method === 'PUT') { bucket.set(key, Buffer.from(opts.body)); return resp(200, ''); }
    return bucket.has(key) ? resp(200, bucket.get(key)) : resp(404, 'NoSuchKey');
  }
  if (/\/api\/interpreter$/.test(u)) {
    seen.push({ host: new URL(u).host, ua: h['user-agent'], accept: h.accept, method: opts.method, body: String(opts.body || '') });
    const step = overpassPlan.shift() ?? 'ok';
    if (step === 'net') throw new TypeError('fetch failed');
    if (typeof step === 'number') return resp(step, 'busy', step === 429 ? { 'retry-after': '3600' } : {});
    return resp(200, typeof step === 'object' ? step : OVERPASS);
  }
  if (u.startsWith('https://query.wikidata.org/sparql')) {
    seen.push({ host: 'query.wikidata.org', ua: h['user-agent'], accept: h.accept });
    return wikidataStatus === 200 ? resp(200, WIKIDATA) : resp(wikidataStatus, 'no');
  }
  throw new Error('unexpected network request ' + u);
};
const M = await import(path.join(ROOT, 'neon', 'collector.mjs'));
const doc = () => JSON.parse(zlib.gunzipSync(bucket.get('ti-docs/docs/cables.json.gz')).toString());

// ---------------------------------------------------------------- pure pieces
{
  const ua = M.cableUserAgent('Test Operator ops@example.org');
  ok(/^threat-feeds-collector\/1\.0 \(.*contact: Test Operator ops@example\.org\)$/.test(ua), 'User-Agent names the project and the contact');
  ok(M.normName('Asia-America Gateway') === M.normName('Asia America  gateway') && M.normName('Sèa-Mé-We 3') === 'sea me we 3' && M.normName('Southern Cross') !== M.normName('Southern Cross Cable'),
    'normalised names: case, accents and punctuation only, no suffix stripping');
  const parts = M.splitAntimeridian([[178, -17], [179.5, -16.5], [180.5, -16], [182, -15.5]]);
  ok(parts.length === 2 && parts[0][parts[0].length - 1][0] === 180 && parts[1][0][0] === -180 && parts.flat().every(([x]) => x >= -180 && x <= 180), 'antimeridian split ' + JSON.stringify(parts));
  ok(Math.abs(parts[0][parts[0].length - 1][1] - parts[1][0][1]) < 1e-9, 'both parts meet at the same latitude');
  const west = M.splitAntimeridian([[-178, 10], [-179.5, 11], [-180.5, 12], [-182, 13]]);
  ok(west.length === 2 && west[0][west[0].length - 1][0] === -180 && west[1][0][0] === 180, 'westward crossing');
  ok(M.keepNewSnapshot(374, 187) && !M.keepNewSnapshot(374, 186) && M.keepNewSnapshot(0, 5) && !M.keepNewSnapshot(0, 0), 'hold-last-good rule: at least half the previous ways');
  // Payload cap: one dense way of 5,000 points and a global cap of 1,000.
  const dense = { elements: [{ type: 'way', id: 9, tags: { name: 'Dense' }, geometry: Array.from({ length: 5000 }, (_, i) => ({ lat: Math.sin(i / 50) * 10, lon: -170 + i * 0.068 })) }] };
  const pd = M.parseOverpass(dense, { maxPoints: 1000 });
  ok(pd.ways[0].points <= M.CABLE_LIMITS.MAX_POINTS_PER_WAY && pd.ways[0].points < 5000, 'one dense way capped per way ' + pd.ways[0].points);
  // Twenty dense ways against a global cap of 1,000 points: the tolerance rises until the total fits.
  const many = { elements: Array.from({ length: 20 }, (_, w) => ({ type: 'way', id: 100 + w, tags: { name: 'D' + w },
    geometry: Array.from({ length: 3000 }, (_, i) => ({ lat: w + Math.sin(i / 40) * 3, lon: -150 + i * 0.1 })) })) };
  const pm = M.parseOverpass(many, { maxPoints: 1000 });
  ok(pm.points <= 1000 && pm.tolerance > 0 && pm.ways.length === 20, 'global payload cap by simplification ' + JSON.stringify({ points: pm.points, tol: pm.tolerance }));
  ok(Buffer.byteLength(JSON.stringify(pm.ways)) < 60000, 'bounded payload in bytes');
}

// ---------------------------------------------------------------- first run: mirror fallback, parse, join, publish
{
  overpassPlan = ['net', 'ok'];
  const r = await M.runJob('cables', {});
  ok(r.ok && r.mirror === M.OVERPASS_MIRRORS[1] && r.tried.length === 2 && /fetch failed/.test(r.tried[0].error), 'falls back to the next mirror when the first cannot answer ' + JSON.stringify(r.tried));
  const ov = seen.filter((s) => /interpreter/.test(s.host) || s.host.startsWith('overpass'));
  ok(ov.length === 2 && ov[0].host === 'overpass-api.de' && ov[1].host === 'overpass.private.coffee' && ov.every((s) => s.accept === 'application/json' && /contact: Test Operator/.test(s.ua) && s.method === 'POST'),
    'one request per mirror, in order, with User-Agent and Accept');
  ok(decodeURIComponent(ov[0].body.slice(5)) === M.CABLE_QUERY, 'the documented query is sent');
  const wd = seen.find((s) => s.host === 'query.wikidata.org');
  ok(wd && wd.accept === 'application/sparql-results+json' && /contact:/.test(wd.ua), 'Wikidata asked with User-Agent and Accept');
  ok(r.counts.ways === 5 && r.counts.named === 4 && r.counts.stations === 1 && r.counts.dropped_ways === 1, 'counts after validation ' + JSON.stringify(r.counts));
  const rows = (await db.query(`SELECT osm_id::text, name, tags, parts, wikidata FROM ti.cable ORDER BY osm_id`)).rows;
  const by = Object.fromEntries(rows.map((x) => [x.name || 'unnamed', x]));
  ok(!JSON.stringify(rows).match(/mapper_one|"uid"|"user"|changeset|fixme/) && by['SEA-ME-WE 3'].tags.operator === 'Consortium', 'no OSM user, uid or edit metadata stored; whitelisted tags kept');
  ok(by.unnamed.parts[0].length === 3 && by.unnamed.parts.flat().every(([x, y]) => Math.abs(y) <= 90 && Math.abs(x) <= 180), 'invalid coordinates dropped');
  ok(by['Southern Cross'].parts.length === 2, 'antimeridian cable stored as two parts');
  ok(by['SEA-ME-WE 3'].wikidata.qid === 'Q530880' && JSON.stringify(by['SEA-ME-WE 3'].wikidata.owners) === '["China Telecom","Orange S.A."]' && by['SEA-ME-WE 3'].wikidata.length_km === 39000
    && by['SEA-ME-WE 3'].wikidata.ready_for_service === '2000-03-01' && by['SEA-ME-WE 3'].wikidata.ready_for_service_basis === 'inception (P571)', 'exact match joins owner, length and inception');
  ok(by.MAREA.wikidata.ready_for_service === '2018-02-01' && /P729/.test(by.MAREA.wikidata.ready_for_service_basis), 'service entry preferred to inception');
  ok(by['Southern Cross'].wikidata === null, '"Southern Cross" does not match "Southern Cross Cable": no fuzzy join');
  ok(by['Asia-America Gateway'].wikidata === null && r.counts.ambiguous_ways === 1, 'a name matching two Wikidata items stays unmatched');
  const st = (await db.query(`SELECT name, tags FROM ti.cable_station`)).rows;
  ok(st.length === 1 && st[0].name === 'Fortaleza CLS' && !JSON.stringify(st).includes('mapper_two'), 'station kept, invalid one dropped, no user field');
  const meta = (await db.query(`SELECT v FROM ti.kv WHERE k = 'cables:meta'`)).rows[0].v;
  ok(meta.osm_base === '2026-11-02T18:40:12Z' && meta.licence === 'ODbL-1.0' && meta.attribution === '© OpenStreetMap contributors' && meta.source_url === M.OVERPASS_MIRRORS[1] && meta.counts.ways === 5,
    'kv meta row: osm_base, counts, source, licence, attribution');
  const d = doc();
  ok(d.licence === 'ODbL-1.0' && d.attribution === '© OpenStreetMap contributors' && d.coverage === 'partial' && /cables-LICENSE/.test(d.share_alike) && d.rows.length === 6, 'published document carries the terms');
  const vol = (await db.query(`SELECT feed, n FROM ti.feed_volume ORDER BY feed`)).rows;
  ok(JSON.stringify(vol) === '[{"feed":"cables_stations","n":1},{"feed":"cables_ways","n":5}]', 'volume rows recorded');
}

// ---------------------------------------------------------------- hold-last-good
{
  const thin = { ...OVERPASS, elements: OVERPASS.elements.filter((e) => e.id === 1001 || e.id === 2001) };
  overpassPlan = [thin];
  const before = bucket.get('ti-docs/docs/cables.json.gz');
  const r = await M.runJob('cables', {});
  const n = (await db.query(`SELECT count(*)::int AS n FROM ti.cable`)).rows[0].n;
  ok(!r.ok && /held: 1 ways against 5/.test(r.error) && n === 5 && bucket.get('ti-docs/docs/cables.json.gz') === before, 'a snapshot under half the previous ways is held, the run fails ' + r.error);
  overpassPlan = [{ ...OVERPASS, elements: OVERPASS.elements.filter((e) => e.id !== 1003 && e.id !== 1006) }];
  const r2 = await M.runJob('cables', {});
  ok(r2.ok && (await db.query(`SELECT count(*)::int AS n FROM ti.cable`)).rows[0].n === 3, 'three of five (60 percent) replaces the snapshot');
}

// ---------------------------------------------------------------- 429: no retry storm, back-off honoured
{
  seen.length = 0;
  overpassPlan = [429];
  const r = await M.runJob('cables', {});
  const ov = seen.filter((s) => s.host !== 'query.wikidata.org');
  ok(!r.ok && /HTTP 429/.test(r.error) && ov.length === 1, '429 ends the attempt after one request (no mirror storm)');
  const meta = (await db.query(`SELECT v FROM ti.kv WHERE k = 'cables:meta'`)).rows[0].v;
  ok(Date.parse(meta.next_after) - Date.now() > 3500e3 && meta.counts.ways === 3, 'Retry-After recorded, last good meta kept');
  seen.length = 0;
  const r2 = await M.runJob('cables', {});
  ok(r2.ok && r2.skipped && seen.length === 0, 'while backing off, no request is sent');
  overpassPlan = [504];
  const r3 = await M.runJob('cables', { force: true });
  ok(!r3.ok && /HTTP 504/.test(r3.error), '504 handled the same way');
}

// ---------------------------------------------------------------- Wikidata down: OSM still published, unjoined
{
  await db.query(`UPDATE ti.kv SET v = v - 'next_after' WHERE k = 'cables:meta'`);
  wikidataStatus = 503;
  overpassPlan = ['ok'];
  const r = await M.runJob('cables', {});
  ok(r.ok && /Wikidata not joined/.test(r.wikidata_note) && doc().rows.filter((x) => x.kind === 'cable').every((x) => x.wikidata === null), 'Wikidata failure leaves cables unjoined, says so');
  wikidataStatus = 200;
}

// ---------------------------------------------------------------- without a contact the job refuses to ask
{
  const ua = process.env.SEC_USER_AGENT; delete process.env.SEC_USER_AGENT;
  seen.length = 0;
  const r = await M.runJob('cables', {});
  ok(!r.ok && /SEC_USER_AGENT/.test(r.error) && seen.length === 0, 'no identifying contact: no request');
  process.env.SEC_USER_AGENT = ua;
}

// ---------------------------------------------------------------- the route: store-first, terms on every answer, GeoJSON
{
  const stored = doc();
  const COLLECTOR = 'https://br-summer-scene-b8t048y2-ti.compute.c-14.us-east-1.aws.neon.tech';
  const real = globalThis.fetch;
  let present = true;
  globalThis.fetch = async (u) => { if (String(u).startsWith(COLLECTOR + '/doc/cables')) return present ? resp(200, zlib.gzipSync(Buffer.from(JSON.stringify(stored)))) : resp(404, { error: 'missing' }); throw new Error('unexpected ' + u); };
  const call = (query) => new Promise((resolve) => {
    for (const k of Object.keys(require.cache)) if (k.startsWith(ROOT)) delete require.cache[k];
    const handler = require(path.join(ROOT, 'api', '_context.js'));
    const res = { headers: {}, setHeader(k, v) { this.headers[k] = v; }, status(c) { this.code = c; return this; }, send(b) { resolve({ code: this.code, body: JSON.parse(b) }); }, end() { resolve({ code: this.code }); } };
    handler({ method: 'GET', query, headers: { host: 'intel.example.org', 'x-vercel-oidc-token': 't' }, url: '/api/context' }, res);
  });
  const a = await call({ type: 'cables' });
  ok(a.code === 200 && a.body.licence === 'ODbL-1.0' && a.body.attribution === '© OpenStreetMap contributors' && a.body.licence_note === '/open-data/cables-LICENSE.txt' && a.body.served_from === 'store', 'route serves the store copy with terms');
  const g = await call({ type: 'cables', format: 'geojson' });
  const lines = g.body.features.filter((f) => f.geometry.type === 'MultiLineString'), pts = g.body.features.filter((f) => f.geometry.type === 'Point');
  ok(g.body.type === 'FeatureCollection' && g.body.attribution === '© OpenStreetMap contributors' && lines.length > 0 && pts.length === 1 && pts[0].geometry.coordinates[0] === -38.5, 'GeoJSON open file with attribution');
  present = false;
  const m = await call({ type: 'cables' });
  ok(m.code === 502 && m.body.attribution === '© OpenStreetMap contributors', 'not collected yet still carries the terms');
  globalThis.fetch = real;
  const vj = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
  ok(vj.rewrites.some((r) => r.source === '/open-data/cables.geojson' && /type=cables&format=geojson/.test(r.destination)), 'open-data path rewritten to the route');
  const lic = fs.readFileSync(path.join(ROOT, 'public', 'open-data', 'cables-LICENSE.txt'), 'utf8');
  ok(/ODbL\) 1\.0/.test(lic) && /© OpenStreetMap contributors/.test(lic) && /Share-alike/.test(lic) && /partial/.test(lic), 'LICENSE note present');
}

// ---------------------------------------------------------------- schedule, health probes, known-gap classes, GreyNoise key
{
  ok(M.plan(new Date('2026-11-08T05:19:00Z')).includes('cables') && !M.plan(new Date('2026-11-07T05:19:00Z')).includes('cables') && !M.plan(new Date('2026-11-08T06:19:00Z')).includes('cables'), 'weekly: Sundays 05:19 UTC only');
  const sch = fs.readFileSync(path.join(ROOT, 'neon', 'schema.sql'), 'utf8');
  ok(/CREATE TABLE IF NOT EXISTS ti\.cable \(/.test(sch) && /CREATE TABLE IF NOT EXISTS ti\.cable_station/.test(sch), 'schema adds the two tables');
  // feedState: the GDELT DOC API alternates between 429 and timeouts; both are one answer class. 200 lifts the gap.
  ok(M.feedState({ feed: 'gdelt_doc_api', ok: false, status: 429 }) === 'known_gap' && M.feedState({ feed: 'gdelt_doc_api', ok: false, status: 0 }) === 'known_gap'
    && M.feedState({ feed: 'gdelt_doc_api', ok: true, status: 200 }) === 'up' && M.feedState({ feed: 'gdelt_doc_api', ok: false, status: 503 }) === 'down', 'gdelt_doc_api: 429 and timeout one class; 200 lifts it');
  ok(M.feedState({ feed: 'greynoise', ok: false, status: 0 }) === 'known_gap' && M.feedState({ feed: 'greynoise', ok: false, status: 429 }) === 'known_gap' && M.feedState({ feed: 'greynoise', ok: false, status: 401 }) === 'down',
    'greynoise: same class');
  delete process.env.GREYNOISE_API_KEY;
  ok(!('key' in M.greynoiseHeaders()), 'no key: keyless lookup');
  process.env.GREYNOISE_API_KEY = 'gn-test-value';
  ok(M.greynoiseHeaders().key === 'gn-test-value', 'key set: sent as the "key" header');
  delete process.env.GREYNOISE_API_KEY;
}

console.log(`PASS ${pass} checks (cables)`);
