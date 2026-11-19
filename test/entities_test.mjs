// Offline test of the entity graph (neon/parts/37k-entities.mjs): the matcher's modes on fixed headlines, the
// ambiguity rule, the rise score and normalized PMI, then the entities job on real Postgres (PGlite) behind a fake Neon
// SQL endpoint with an in-memory bucket and a fixture gazetteer: mentions, entry documents, the gazetteer sync, the
// keyset watermark (a rerun reads nothing new and writes no duplicate), the site-down bucket fallback, the graph
// document and the three graph queries. No network.
// node test/entities_test.mjs <repository root>   (after python3 pipeline/collector_build.py .)
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';

const ROOT = path.resolve(process.argv[2] || '.');
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };

const GAZ = {
  version: 1, date: '2026-11-19', counts: { actor: 3 }, names: 20, terms: 'fixture',
  entities: [
    { id: 'actor:G0007', t: 'actor', n: 'APT28', a: [['APT28', 'i'], ['Fancy Bear', 'i'], ['Sofacy', 's']], m: { attack: 'G0007' } },
    { id: 'actor:G0034', t: 'actor', n: 'Sandworm Team', a: [['Sandworm Team', 'i'], ['Sandworm', 's']] },
    { id: 'actor:G1040', t: 'extortion', n: 'Play', a: [['Play', 'w']], m: { leak: 'play' } },
    { id: 'extortion:qilin', t: 'extortion', n: 'Qilin', a: [['Qilin', 's'], ['Agenda', 's']] },
    { id: 'malware:S0625', t: 'malware', n: 'Cuba', a: [['Cuba', 'w']] },
    { id: 'malware:S0154', t: 'malware', n: 'Cobalt Strike', a: [['Cobalt Strike', 'i'], ['BEACON', 'w']] },
    { id: 'vendor:microsoft', t: 'vendor', n: 'Microsoft', a: [['Microsoft', 's']] },
    { id: 'vendor:ivanti', t: 'vendor', n: 'Ivanti', a: [['Ivanti', 's']] },
    { id: 'product:microsoft:exchangeserver', t: 'product', n: 'Microsoft Exchange Server', a: [['Exchange Server', 'v'], ['Microsoft Exchange Server', 'i']], m: { vendor: 'vendor:microsoft' } },
    { id: 'product:ivanti:connectsecure', t: 'product', n: 'Ivanti Connect Secure', a: [['Connect Secure', 'v'], ['Ivanti Connect Secure', 'i']], m: { vendor: 'vendor:ivanti' } },
    { id: 'extortion:global', t: 'extortion', n: 'Global', a: [['Global', 'w']] },
    { id: 'malware:donot', t: 'malware', n: 'DONOT', a: [['DONOT', 'i']] },
    { id: 'vendor:progress', t: 'vendor', n: 'Progress', a: [['Progress', 'w']] },
    { id: 'cve:CVE-2024-3400', t: 'cve', n: 'CVE-2024-3400', a: [['CVE-2024-3400', 'i']], m: { kev: '2024-04-12' } },
  ],
  edges: [['actor:G0007', 'malware:S0154', 'uses', 'attack'], ['product:microsoft:exchangeserver', 'vendor:microsoft', 'made-by', 'kev'], ['actor:G0007', 'country:RU', 'attributed-to', 'misp']],
};
for (let i = 0; i < 1000; i++) GAZ.entities.push({ id: 'malware:mp:filler' + i, t: 'malware', n: 'Fillerfamily' + i, a: [['Fillerfamily' + i, 'i']] });

const db = await PGlite.create({ extensions: { pg_trgm } });
await db.exec(fs.readFileSync(path.join(ROOT, 'neon', 'schema.sql'), 'utf8'));
const RAW = Object.fromEntries(Array.from({ length: 6000 }, (_, i) => [i, (v) => v]));
const runSql = async (q, params) => { const r = await db.query(q, params, { rowMode: 'array', parsers: RAW }); return { fields: r.fields, rows: r.rows }; };
process.env.DATABASE_URL = 'postgresql://ti_app:pw@ep-test-pooler.c-14.us-east-1.aws.neon.tech/threatintel?sslmode=require';
process.env.AWS_ENDPOINT_URL_S3 = 'https://br-test.storage.c-14.us-east-1.aws.neon.tech';
process.env.AWS_ACCESS_KEY_ID = 'nak_test'; process.env.AWS_SECRET_ACCESS_KEY = 'nsk_test';
const bucket = new Map();
let siteUp = true, siteCalls = 0;
const resp = (status, body, headers = {}) => new Response(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body), { status, headers });
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
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
  if (u === 'https://intel.kilfoycyber.com/data/entity_gazetteer.json') { siteCalls++; return siteUp ? resp(200, GAZ) : resp(503, 'down'); }
  throw new Error('unexpected network request ' + u);
};
const M = await import(path.join(ROOT, 'neon', 'collector.mjs'));

// ---------------------------------------------------------------- matcher
{
  const G = M.compileGazetteer(GAZ, { ambiguous: ['agenda', 'sandworm'] });
  const ids = (t) => [...M.matchText(G, t).keys()].sort();
  ok(M.squashName('APT 28') === 'apt28' && M.squashName('LAPSUS$') === 'lapsus' && M.tokenize('U.S. and CVE-2024-3400').map((t) => t.raw).join('|') === 'U.S|and|CVE-2024-3400', 'squash and tokens');
  ok(ids('Russian hackers APT 28 hit Ukrainian grid').join() === 'actor:G0007,country:RU,country:UA', 'multi-token name with a split digit, demonyms ' + ids('Russian hackers APT 28 hit Ukrainian grid'));
  ok(ids('Fancy bear phishing wave').join() === 'actor:G0007', 'an any-case name matches in lower case');
  ok(ids('sofacy returns').join() === '' && ids('Sofacy returns').join() === 'actor:G0007', 'a single word counts only capitalized');
  ok(ids('Sandworm hits Kyiv').join() === '' && ids('Sandworm hackers hit Kyiv').join() === 'actor:G0034', 'an ambiguous word needs a cue beside it');
  ok(ids('Kids Play in Paris').join() === '' && ids('Play ransomware claims a US city').join() === 'actor:G1040,country:US', 'a cue-only word, and "US" in exact case');
  ok(ids('Tell us about Microsoft Exchange Server').join() === 'product:microsoft:exchangeserver,vendor:microsoft', 'lower-case "us" is no country; the full product names its vendor');
  ok(ids('Exchange Server prices rise').join() === '' && ids('Microsoft warns of Exchange Server flaw').join() === 'product:microsoft:exchangeserver,vendor:microsoft', 'a bare product name needs its vendor');
  ok(ids('Ivanti Connect Secure exploited').join() === 'product:ivanti:connectsecure,vendor:ivanti', 'a product named with its vendor adds the vendor');
  ok(ids('Cuba and Germany sign trade deal').join() === '' && ids('Cuba ransomware hits Germany').join() === 'country:DE,malware:S0625', 'countries alone are dropped; a cue makes Cuba the family');
  ok(ids('Cuba talks: Cobalt Strike beacons found').join() === 'country:CU,malware:S0154', 'without a cue the capitalized word is the country');
  ok(ids('PAN-OS CVE-2024-3400 and cve-2025-0001 exploited').join() === 'cve:CVE-2024-3400,cve:CVE-2025-0001', 'CVE identifiers in any case, outside the gazetteer too');
  ok(ids('Agenda for the summit').join() === '' && ids('Qilin claims hospital').join() === 'extortion:qilin', 'an ambiguous alias of a group');
  ok(ids('Global security threats rise in cyber attacks').join() === '' && ids('Global ransomware gang claims a hospital').join() === 'extortion:global', 'a threat name needs a threat cue, not a generic one');
  ok(ids('Progress ransomware report').join() === '' && ids('Progress patches MOVEit flaw').join() === 'vendor:progress', 'a vendor name needs a vulnerability cue');
  ok(ids('Do not click: DONOT targets Pakistan').join() === 'country:PK,malware:donot', 'a letters-only name matches only as one word');
  ok(M.entryText({ title: 'Qilin hits clinic - The Record', source: 'The Record', summary: 'x' }) === 'Qilin hits clinic . x', 'the aggregator publisher suffix is dropped');
}
{
  const amb = M.ambiguousWords(['agenda', 'sandworm', 'turla', 'kimsuky', 'qilin', 'rover'], [{ word: 'agenda', ndoc: 120 }, { word: 'sandworm', ndoc: 5 }, { word: 'turla', ndoc: 1 }, { word: 'rover', ndoc: 1 }],
    [{ word: 'sandworm', ndoc: 40 }, { word: 'kimsuky', ndoc: 1 }, { word: 'turla', ndoc: 30 }, { word: 'qilin', ndoc: 46 }]);
  ok(amb.join() === 'agenda,kimsuky,rover,sandworm', 'a single word stands alone only when attested in cyber news and rare in general news ' + amb);
  ok(M.riseScore(20, 23) > 3 && M.riseScore(7, 30) < 1 && M.riseScore(5, 5) >= 3 && M.riseScore(10, 20, 7) < M.riseScore(10, 20, 23), 'rise score ' + [M.riseScore(20, 23), M.riseScore(7, 30), M.riseScore(5, 5)]);
  ok(M.npmi(10, 10, 10, 1000) > 0.6 && M.npmi(1, 500, 500, 1000) < 0 && M.npmi(0, 1, 1, 10) === 0, 'normalized PMI');
}

// ---------------------------------------------------------------- the job
const now = Date.now(), iso = (h) => new Date(now - h * 3600e3).toISOString();
const ITEMS = [
  ['https://a.example/1', 'APT28 targets logistics with Cobalt Strike', 'Russian operators', 'research', 'a.example', 2],
  ['https://b.example/1', 'Fancy Bear (Sofacy) phishing uses Cobalt Strike beacons', '', 'cyber-news', 'b.example', 5],
  ['https://c.example/1', 'Sofacy and Cobalt Strike again', 'Russian intelligence', 'research', 'c.example', 30],
  ['https://d.example/1', 'Cuba and Germany sign a trade deal', 'Talks in Berlin', 'geopolitics', 'd.example', 3],
  ['https://e.example/1', 'Microsoft fixes Exchange Server flaw CVE-2026-1111', '', 'vulnerability', 'e.example', 1],
  ['https://f.example/1', 'Qilin ransomware claims attack on a German hospital - Example News', '', 'topic-cyber', 'f.example', 4],
];
let k = 0;
for (const [link, title, summary, category, host, h] of ITEMS) {
  await db.query(`INSERT INTO ti.item (link, fp, feed, source, host, title, summary, published, category, lang, seen_at) VALUES ($1, $2, 'f', $3, $4, $5, $6, $7, $8, 'en', $9)`,
    [link, 'fp' + k++, host === 'f.example' ? 'Example News' : null, host, title, summary, iso(h), category, iso(h - 0.5)]);
}
await db.query(`INSERT INTO ti.advisory (link, feed, title, published, cves, seen_at) VALUES ('https://psirt.example/a1', 'psirt', 'Ivanti Connect Secure advisory', $1, '["CVE-2024-3400"]', $1)`, [iso(6)]);

let r = await M.runJob('entities');
ok(r.ok && r.read === 7 && r.by_source.item.read === 6 && r.by_source.advisory.read === 1, 'reads every entry once ' + JSON.stringify(r).slice(0, 300));
ok(r.gazetteer.synced && r.gazetteer.via === 'site' && r.gazetteer.entities === GAZ.entities.length, 'gazetteer from the site, synced to ti.entity');
const ments = (await db.query(`SELECT eid, link FROM ti.mention ORDER BY link, eid`)).rows;
const by = (l) => ments.filter((m) => m.link === l).map((m) => m.eid).sort().join();
ok(by('https://a.example/1') === 'actor:G0007,country:RU,malware:S0154', 'entry a ' + by('https://a.example/1'));
ok(by('https://c.example/1') === 'actor:G0007,country:RU,malware:S0154', 'entry c: Sofacy capitalized');
ok(by('https://d.example/1') === '' && !(await db.query(`SELECT 1 FROM ti.mdoc WHERE link = 'https://d.example/1'`)).rows.length, 'a countries-only entry leaves no rows');
ok(by('https://e.example/1') === 'cve:CVE-2026-1111,product:microsoft:exchangeserver,vendor:microsoft', 'entry e ' + by('https://e.example/1'));
ok(by('https://psirt.example/a1') === 'cve:CVE-2024-3400,product:ivanti:connectsecure,vendor:ivanti', 'advisory CVEs come from the feed ' + by('https://psirt.example/a1'));
ok(by('https://f.example/1') === 'country:DE,extortion:qilin', 'aggregator title with the publisher dropped; the demonym counts beside the group ' + by('https://f.example/1'));
const cveRow = (await db.query(`SELECT t, n FROM ti.entity WHERE id = 'cve:CVE-2026-1111'`)).rows[0];
ok(cveRow && cveRow.t === 'cve', 'a CVE outside the gazetteer becomes an entity on first mention');
ok((await db.query(`SELECT count(*)::int AS n FROM ti.erel`)).rows[0].n === 3, 'curated edges stored');
const doc = JSON.parse(zlib.gunzipSync(bucket.get('ti-docs/docs/entities.json.gz')).toString());
const ent = doc.rows.filter((x) => x.kind === 'entity'), edg = doc.rows.filter((x) => x.kind === 'edge');
ok(ent.find((e) => e.id === 'actor:G0007').n30 === 3 && ent.find((e) => e.id === 'actor:G0007').p30 === 3, 'entity counts and publishers');
ok(doc.baseline_ready === false && !ent.some((e) => e.rising || e.new) && ent.every((e) => e.z === null), 'no rising or new entity before the baseline holds 14 days');
ok(edg.some((e) => e.a === 'actor:G0007' && e.b === 'malware:S0154' && e.n === 3 && e.p === 3 && e.an === 'APT28'), 'co-mention edge with names ' + JSON.stringify(edg[0]));
ok(!edg.some((e) => e.a.startsWith('country:') && e.b.startsWith('country:')), 'no country-to-country edges');

// Entries that share one seen_at to the microsecond (one insert statement) are read once each, across batches.
{
  const before = (await db.query(`SELECT count(*)::int AS n FROM ti.item`)).rows[0].n;
  for (let i = 0; i < 7; i++) await db.query(`INSERT INTO ti.item (link, fp, feed, host, title, summary, published, category, lang, seen_at) VALUES ($1, $2, 'f', 'g.example', $3, '', now(), 'research', 'en', '2099-01-01 00:00:00.123456+00')`,
    ['https://g.example/' + i, 'fpg' + i, 'APT28 note ' + i]);
  const keep = M.ENTITY.BATCH; M.ENTITY.BATCH = 3;
  const rb = await M.runJob('entities');
  M.ENTITY.BATCH = keep;
  ok(rb.ok && rb.by_source.item.read === 7 && (await db.query(`SELECT count(*)::int AS n FROM ti.mention WHERE link LIKE 'https://g.example/%'`)).rows[0].n === 7, 'one microsecond, seven entries, batches of three: each read once ' + JSON.stringify(rb.by_source));
  const mk = (await db.query(`SELECT v FROM ti.kv WHERE k = 'entities:mark'`)).rows[0].v;
  ok(/\.123456/.test(mk.item.at), 'the watermark keeps microseconds ' + mk.item.at);
  await db.query(`DELETE FROM ti.mention WHERE link LIKE 'https://g.example/%'`); await db.query(`DELETE FROM ti.mdoc WHERE link LIKE 'https://g.example/%'`);
  await db.query(`DELETE FROM ti.item WHERE link LIKE 'https://g.example/%'`);
  await db.query(`UPDATE ti.kv SET v = jsonb_set(v, '{item}', $1::jsonb) WHERE k = 'entities:mark'`, [JSON.stringify({ at: (await db.query(`SELECT max(seen_at)::text AS s FROM ti.item`)).rows[0].s, link: (await db.query(`SELECT link FROM ti.item ORDER BY seen_at DESC, link DESC LIMIT 1`)).rows[0].link })]);
  ok((await db.query(`SELECT count(*)::int AS n FROM ti.item`)).rows[0].n === before, 'fixture removed');
}
// A rerun reads nothing and writes nothing.
const n0 = (await db.query(`SELECT count(*)::int AS n FROM ti.mention`)).rows[0].n;
r = await M.runJob('entities');
ok(r.ok && r.read === 0 && r.gazetteer.synced === false && (await db.query(`SELECT count(*)::int AS n FROM ti.mention`)).rows[0].n === n0, 'idempotent rerun ' + JSON.stringify(r).slice(0, 200));
// A new entry with the same seen_at as the last one still gets read (keyset on seen_at and link).
const lastSeen = (await db.query(`SELECT max(seen_at) AS s FROM ti.item`)).rows[0].s;
await db.query(`INSERT INTO ti.item (link, fp, feed, host, title, summary, published, category, lang, seen_at) VALUES ('https://z.example/9', 'fpz', 'f', 'z.example', 'Sandworm Team wiper hits Ukraine', '', $1, 'research', 'en', $1)`, [lastSeen]);
r = await M.runJob('entities');
ok(r.read === 1, 'an entry at the watermark instant is read');
ok((await db.query(`SELECT eid FROM ti.mention WHERE link = 'https://z.example/9' ORDER BY eid`)).rows.map((x) => x.eid).join() === 'actor:G0034,country:UA', 'Sandworm Team and Ukraine');

// Site down: the bucket copy (pushed by the operator) serves; without it the job fails and says why.
siteUp = false;
r = await M.runJob('entities');
ok(r.ok, 'the gazetteer held in memory serves for six hours');
M.resetGazetteer();
ok(bucket.has('ti-docs/ref/entity_gazetteer.json.gz'), 'the sync kept a bucket copy of the site gazetteer');
const kept = bucket.get('ti-docs/ref/entity_gazetteer.json.gz');
bucket.delete('ti-docs/ref/entity_gazetteer.json.gz');
r = await M.runJob('entities');
ok(!r.ok && /ref\/entity_gazetteer\.json is missing/.test(r.error), 'no site and no bucket copy: a clear error ' + r.error);
bucket.set('ti-docs/ref/entity_gazetteer.json.gz', kept);
M.resetGazetteer();
r = await M.runJob('entities');
ok(r.ok && r.gazetteer.via === 'bucket' && r.gazetteer.synced === false, 'the bucket copy serves, same content so no resync ' + JSON.stringify(r.gazetteer));
siteUp = true;

// New matching rules re-derive every mention: stored entries from the start, older documents from their titles.
{
  await db.query(`INSERT INTO ti.mdoc (link, src, host, title, published) VALUES ('https://old.example/1', 'item', 'old.example', 'Fancy Bear returns with Cobalt Strike', now() - interval '200 days')`);
  await db.query(`INSERT INTO ti.mention (eid, link, published, host, via) VALUES ('vendor:microsoft', 'https://old.example/1', now() - interval '200 days', 'old.example', 'stale')`);
  await db.query(`INSERT INTO ti.mdoc (link, src, host, title, published) VALUES ('https://old.example/2', 'item', 'old.example', 'Nothing to see here', now() - interval '200 days')`);
  await db.query(`INSERT INTO ti.mention (eid, link, published, host, via) VALUES ('vendor:microsoft', 'https://old.example/2', now() - interval '200 days', 'old.example', 'stale')`);
  const n0 = (await db.query(`SELECT count(*)::int AS n FROM ti.mention WHERE link NOT LIKE 'https://old.example/%'`)).rows[0].n;
  GAZ.rules = 9; M.resetGazetteer();
  const rr = await M.runJob('entities');
  ok(rr.ok && rr.rederived && rr.rederived.to === M.MATCH_V + '.9' && rr.rederived.older_docs === 2 && rr.rederived.older_kept === 1, 'rederived on a rules change ' + JSON.stringify(rr.rederived));
  const old1 = (await db.query(`SELECT eid FROM ti.mention WHERE link = 'https://old.example/1' ORDER BY eid`)).rows.map((x) => x.eid).join();
  ok(old1 === 'actor:G0007,malware:S0154', 'an older document is matched again from its title ' + old1);
  ok(!(await db.query(`SELECT 1 FROM ti.mdoc WHERE link = 'https://old.example/2'`)).rows.length && !(await db.query(`SELECT 1 FROM ti.mention WHERE link = 'https://old.example/2'`)).rows.length, 'an older document that names nothing under the new rules is dropped');
  ok(rr.read >= 8 && (await db.query(`SELECT count(*)::int AS n FROM ti.mention WHERE link NOT LIKE 'https://old.example/%'`)).rows[0].n === n0, 'the stored entries are read again and give the same mentions');
  const rr2 = await M.runJob('entities');
  ok(rr2.ok && !rr2.rederived && rr2.read === 0, 'no second rederivation');
}

// ---------------------------------------------------------------- queries
const card = await M.entityCard('actor:G0007');
ok(card.entity.n === 'APT28' && card.entries === 3 && card.series.length >= 1, 'card: entity and series');
ok(card.co_mentioned[0].id === 'malware:S0154' && card.co_mentioned[0].n === 3 && card.co_mentioned[0].t === 'malware', 'card: co-mentions ' + JSON.stringify(card.co_mentioned[0]));
ok(card.curated.some((c) => c.id === 'malware:S0154' && c.rel === 'uses' && c.basis === 'attack' && c.dir === 'out') && card.curated.some((c) => c.id === 'country:RU' && c.rel === 'attributed-to'), 'card: curated relationships');
ok(card.recent.length === 4 && card.recent[0].link === 'https://a.example/1' && card.recent[3].link === 'https://old.example/1' && card.recent.every((d) => d.title && d.via), 'card: recent entries newest first with the words that named it');
ok((await M.entityCard('nonsense')).status === 400 && (await M.entityCard('actor:G9999')).status === 404, 'card: bad and unknown ids');
const pair = await M.entityPair('actor:G0007', 'malware:S0154');
ok(pair.shared === 3 && pair.curated.length === 1 && pair.entries[0].via_a && pair.entries[0].via_b, 'pair: shared entries and curated link');
const s1 = await M.entitySearch('fancy');
ok(s1.hits[0] && s1.hits[0].id === 'actor:G0007', 'search by alias ' + JSON.stringify(s1.hits[0]));
const s2 = await M.entitySearch('exchange', 'product');
ok(s2.hits.length === 1 && s2.hits[0].id === 'product:microsoft:exchangeserver', 'search by type');
ok(M.plan(new Date('2026-11-19T10:04:00Z')).join() === 'gdelt,infra,snap,sources,entities,reports' && M.plan(new Date('2026-11-19T10:49:00Z')).slice(-3).join() === 'triage,entities,reports', 'entities in every slot, after the sources and triage');

console.log(`entities_test: ${pass} checks passed`);
