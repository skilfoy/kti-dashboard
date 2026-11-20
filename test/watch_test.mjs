// Offline test of the standing watches (neon/parts/37l-watch.mjs) with the repository's data/watches.json, on real
// Postgres (PGlite) behind a fake Neon SQL endpoint and an in-memory bucket: each watch kind, one alert per watch and
// subject across runs, the quiet period, the 14-day baseline gate, the alerts document and a visitor's watchlist.
// node test/watch_test.mjs <repository root>   (after python3 pipeline/collector_build.py .)
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';

const ROOT = path.resolve(process.argv[2] || '.');
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };
const WATCHES = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'watches.json'), 'utf8'));
const pirs = new Set(JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'authored', 'pirs.json'), 'utf8')).map((p) => p.pir_id));
ok(WATCHES.watches.every((w) => pirs.has(w.pir) && (!w.terms || WATCHES.terms[w.terms])) && new Set(WATCHES.watches.map((w) => w.id)).size === WATCHES.watches.length, 'every watch names a PIR and a known term list, ids unique');

const db = await PGlite.create({ extensions: { pg_trgm } });
await db.exec(fs.readFileSync(path.join(ROOT, 'neon', 'schema.sql'), 'utf8'));
const RAW = Object.fromEntries(Array.from({ length: 6000 }, (_, i) => [i, (v) => v]));
const runSql = async (q, params) => { const r = await db.query(q, params, { rowMode: 'array', parsers: RAW }); return { fields: r.fields, rows: r.rows }; };
process.env.DATABASE_URL = 'postgresql://ti_app:pw@ep-test-pooler.c-14.us-east-1.aws.neon.tech/threatintel?sslmode=require';
process.env.AWS_ENDPOINT_URL_S3 = 'https://br-test.storage.c-14.us-east-1.aws.neon.tech';
process.env.AWS_ACCESS_KEY_ID = 'nak_test'; process.env.AWS_SECRET_ACCESS_KEY = 'nsk_test';
const bucket = new Map();
let siteUp = true;
const resp = (status, body) => new Response(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body), { status });
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
  if (u === 'https://intel.kilfoycyber.com/data/watches.json') return siteUp ? resp(200, WATCHES) : resp(503, 'down');
  throw new Error('unexpected network request ' + u);
};
const M = await import(path.join(ROOT, 'neon', 'collector.mjs'));

// ---------------------------------------------------------------- pure pieces
ok(M.termRegex(WATCHES, 'financial').startsWith('\\m(bank|banks') && M.termRegex(WATCHES, 'identity').includes('help ?desk'), 'term lists become word-bounded alternations');
assert.throws(() => M.termRegex({ terms: { x: 'a|b);drop' } }, 'x'), /bad term list/); pass++;

// ---------------------------------------------------------------- fixture: entities, attribution, entries
const day = (d) => new Date(Date.now() - d * 864e5).toISOString();
await db.query(`INSERT INTO ti.entity (id, t, n, m) VALUES ('actor:G0007', 'actor', 'APT28', '{}'), ('actor:G1015', 'actor', 'Scattered Spider', '{}'), ('extortion:qilin', 'extortion', 'Qilin', '{}'),
  ('malware:S0154', 'malware', 'Cobalt Strike', '{}'), ('vendor:ivanti', 'vendor', 'Ivanti', '{}'), ('product:ivanti:connectsecure', 'product', 'Ivanti Connect Secure', '{}'),
  ('cve:CVE-2026-1111', 'cve', 'CVE-2026-1111', $1), ('cve:CVE-2026-2222', 'cve', 'CVE-2026-2222', '{}')`,
  [JSON.stringify({ kev: day(1).slice(0, 10), vendor: 'Ivanti', product: 'Connect Secure', ransomware: true })]);
await db.query(`INSERT INTO ti.erel (a, b, rel, basis) VALUES ('actor:G0007', 'country:RU', 'attributed-to', 'misp'), ('cve:CVE-2026-1111', 'product:ivanti:connectsecure', 'affects', 'kev'), ('cve:CVE-2026-1111', 'vendor:ivanti', 'affects', 'kev')`);
const E = [
  // link, title, host, category, days ago, entities
  ['https://a/1', 'APT28 targets European banks with new backdoor', 'a.com', 'research', 1, ['actor:G0007', 'country:RU']],
  ['https://b/1', 'NCSC advisory on APT28 activity', 'ncsc.gov.uk', 'government', 2, ['actor:G0007']],
  ['https://c/1', 'APT28 hits power grid operators', 'c.com', 'cyber-news', 2, ['actor:G0007']],
  ['https://d/1', 'Qilin ransomware claims a credit union', 'd.com', 'topic-cyber', 1, ['extortion:qilin']],
  ['https://e/1', 'Scattered Spider uses help desk vishing again', 'e.com', 'cyber-news', 1, ['actor:G1015']],
  ['https://f/1', 'Help desk vishing wave hits retailers', 'f.com', 'cyber-news', 1, []],
  ['https://g/1', 'Retailers report help desk vishing', 'g.com', 'research', 2, []],
  ['https://h/1', 'Scattered Spider member arrested in Spain', 'h.com', 'cyber-news', 1, ['actor:G1015']],
  ['https://i/1', 'Police arrest Scattered Spider suspect', 'i.com', 'research', 3, ['actor:G1015']],
  ['https://j/1', 'Ivanti Connect Secure CVE-2026-1111 exploited', 'j.com', 'vulnerability', 9, ['cve:CVE-2026-1111', 'product:ivanti:connectsecure', 'vendor:ivanti']],
  ['https://k/1', 'CVE-2026-2222 under attack', 'k.com', 'cyber-news', 1, ['cve:CVE-2026-2222']],
  ['https://l/1', 'Exploits for CVE-2026-2222 appear', 'l.com', 'research', 1, ['cve:CVE-2026-2222']],
  ['https://m/1', 'CVE-2026-2222 patch urged', 'm.com', 'vulnerability', 2, ['cve:CVE-2026-2222']],
];
const insert = async (rows) => {
  for (const [link, title, host, category, d, ents] of rows) {
    await db.query(`INSERT INTO ti.mdoc (link, src, host, title, published, category) VALUES ($1, 'item', $2, $3, $4, $5)`, [link, host, title, day(d), category]);
    for (const e of ents) await db.query(`INSERT INTO ti.mention (eid, link, published, host, via) VALUES ($1, $2, $3, $4, 'x')`, [e, link, day(d), host]);
  }
};
await insert(E);
await db.query(`INSERT INTO ti.kv (k, v) VALUES ('entities:since', $1)`, [JSON.stringify({ since: day(3) })]);

// ---------------------------------------------------------------- the job
let r = await M.runJob('watch');
ok(r.ok && r.via === 'site' && r.baseline_ready === false && Object.values(r.per_watch).every((x) => !x.error), 'all watches evaluate ' + JSON.stringify(r.per_watch));
const alerts = async () => (await db.query(`SELECT id, watch, subject, n, p, headline, detail, opened_at FROM ti.alert ORDER BY watch, subject`)).rows;
let A = await alerts();
const has = (w, s) => A.find((a) => a.watch === w && a.subject === s);
ok(has('W-1A', 'actor:G0007') && has('W-1A', 'actor:G0007').n === 1, 'W-1A: a state actor named with banks');
const lk = (await db.query(`SELECT links FROM ti.alert WHERE watch = 'W-1A'`)).rows[0].links;
ok(Array.isArray(lk) && lk[0].link === 'https://a/1' && lk[0].title.startsWith('APT28'), 'alert links are a JSON array of entries ' + JSON.stringify(lk).slice(0, 120));
ok(!has('W-1A', 'extortion:qilin'), 'W-1A: Qilin has no attributed country');
ok(has('W-3A', 'extortion:qilin') && /credit union|financial/.test(has('W-3A', 'extortion:qilin').headline), 'W-3A: an extortion group with a financial victim ' + (has('W-3A', 'extortion:qilin') || {}).headline);
ok(!has('W-1B', 'extortion:qilin'), 'W-1B needs two publishers');
ok(has('W-5A', 'actor:G0007'), 'W-5A: state actor with the power grid');
ok(has('W-5B', 'actor:G0007') && /government or CERT/.test(has('W-5B', 'actor:G0007').headline), 'W-5B: a government publication naming a state actor');
ok(has('W-6A', 'term:help desk') && has('W-6A', 'term:help desk').p === 3, 'W-6A: a term in three publishers\' titles ' + JSON.stringify(A.filter((a) => a.watch === 'W-6A')));
ok(has('W-6B', 'actor:G1015'), 'W-6B: an actor with an identity technique');
ok(has('W-7A', 'actor:G1015') && has('W-7A', 'actor:G1015').p === 2, 'W-7A: arrests by two publishers');
const kv = has('W-2A', 'cve:CVE-2026-1111');
ok(kv && kv.detail.lead_days === 8 && kv.detail.ransomware === true && /8 days earlier/.test(kv.headline), 'W-2A: KEV addition with the collection\'s lead time ' + (kv && kv.headline));
ok(has('W-2B', 'cve:CVE-2026-2222') && !has('W-2B', 'cve:CVE-2026-1111'), 'W-2B: a CVE outside KEV by three publishers, not the KEV one');
ok(!A.some((a) => a.watch === 'W-1C' || a.watch === 'W-3B'), 'first-seen and surge wait for the baseline');
const doc = JSON.parse(zlib.gunzipSync(bucket.get('ti-docs/docs/alerts.json.gz')).toString());
ok(doc.rows.filter((x) => x.kind === 'watch').length === WATCHES.watches.length && doc.rows.filter((x) => x.kind === 'alert').length === A.length
  && doc.rows.find((x) => x.watch === 'W-1C').waits_for_baseline === true, 'alerts document: watches with counts and the alerts ' + JSON.stringify([doc.rows.filter((x) => x.kind === 'watch').length, doc.rows.filter((x) => x.kind === 'alert').length, A.length, doc.rows.find((x) => x.watch === 'W-1C')]));

// A rerun keeps one alert per watch and subject; a new entry updates it.
const n0 = A.length, id0 = has('W-7A', 'actor:G1015').id;
await insert([['https://n/1', 'Scattered Spider suspect charged in US', 'n.com', 'cyber-news', 0.5, ['actor:G1015']]]);
r = await M.runJob('watch');
A = await alerts();
ok(r.ok && A.length === n0 && r.opened === 0, 'rerun: no new alert ' + JSON.stringify({ n: A.length, opened: r.opened }));
ok(has('W-7A', 'actor:G1015').id === id0 && has('W-7A', 'actor:G1015').p === 3, 'the open alert takes the new entry');
// Quiet for longer than QUIET_DAYS: the next match opens a new alert.
await db.query(`UPDATE ti.alert SET last_at = now() - interval '20 days', first_at = now() - interval '25 days' WHERE id = $1`, [id0]);
await db.query(`UPDATE ti.mdoc SET published = now() - interval '25 days' WHERE link IN ('https://h/1', 'https://i/1', 'https://n/1')`);
await insert([['https://o/1', 'Scattered Spider ringleader extradited', 'o.com', 'cyber-news', 0.2, ['actor:G1015']], ['https://p/1', 'Scattered Spider extradition confirmed', 'p.com', 'research', 0.2, ['actor:G1015']]]);
r = await M.runJob('watch');
A = await alerts();
ok(A.filter((a) => a.watch === 'W-7A' && a.subject === 'actor:G1015').length === 2 && r.opened === 1, 'a subject quiet for 14 days opens a new alert');

// The baseline: after 14 days, first-seen fires for a group first named this week.
await db.query(`UPDATE ti.kv SET v = $1 WHERE k = 'entities:since'`, [JSON.stringify({ since: day(20) })]);
r = await M.runJob('watch');
A = await alerts();
ok(r.baseline_ready && has('W-1C', 'actor:G1015') && has('W-1C', 'extortion:qilin') === undefined, 'first-seen after the baseline, with two publishers ' + JSON.stringify(A.filter((a) => a.watch === 'W-1C').map((a) => a.subject)));

// Site down: the bucket copy kept on the last good read serves.
siteUp = false; M.resetWatches();
r = await M.runJob('watch');
ok(r.ok && r.via === 'bucket', 'the bucket copy of the watch list serves when the site is down');
siteUp = true; M.resetWatches();

// ---------------------------------------------------------------- a visitor's watchlist
const w = await M.watchChanges('actor:G1015,vendor:ivanti,bogus id', day(2.5));
ok(w.ids.join() === 'actor:G1015,vendor:ivanti', 'invalid ids are dropped');
const sp = w.items.find((x) => x.id === 'actor:G1015'), iv = w.items.find((x) => x.id === 'vendor:ivanti');
ok(sp.entries === 3 && ['https://o/1', 'https://p/1'].includes(sp.latest[0].link) && sp.alerts.length >= 2, 'entries and alerts since the time ' + JSON.stringify({ e: sp.entries, a: sp.alerts.length }));
ok(iv.kev.length === 1 && iv.kev[0].cve === 'CVE-2026-1111' && iv.entries === 0, 'a KEV addition for a watched vendor');
ok(w.events.some((e) => e.kind === 'kev') && w.events.some((e) => e.kind === 'entry') && w.events.every((e, i, a) => i === 0 || String(a[i - 1].at) >= String(e.at)), 'one chronological event list');
const w2 = await M.watchChanges('actor:G0007', day(30));
ok(w2.items[0].new_partners.some((p) => p.id === 'malware:S0154') === false && w2.items[0].entries === 3, 'partners: only co-mentions in the entries (none here)');
ok((await M.watchChanges('', day(1))).status === 400, 'ids required');
ok(M.plan(new Date('2026-11-19T10:04:00Z')).join() === 'gdelt,infra,snap,sources,translate,entities,watch,foresight,reports', 'watch runs after entities in every slot');

// ---------------------------------------------------------------- track record (37m-score.mjs)
{
  ok(M.median([3, 1, 2]) === 2 && M.median([4, 1, 2, 3]) === 2.5 && M.median([]) === null, 'median');
  // CVE-2026-2222 (a W-2B alert) is listed by KEV after its alert opened; the alert is aged past 30 days.
  await db.query(`UPDATE ti.entity SET m = $1 WHERE id = 'cve:CVE-2026-2222'`, [JSON.stringify({ kev: day(0).slice(0, 10) })]);
  await db.query(`UPDATE ti.alert SET opened_at = now() - interval '40 days' WHERE watch = 'W-2B'`);
  await db.query(`INSERT INTO ti.feed (id, url, active, status, fails) VALUES ('a', 'https://a', true, 'ok', 0), ('b', 'https://b', true, 'unchanged', 0), ('c', 'https://c', true, 'error', 9)`);
  const rs = await M.runJob('score');
  const sd = JSON.parse(zlib.gunzipSync(bucket.get('ti-docs/docs/scorecard.json.gz')).toString());
  ok(rs.ok && sd.kev_foresight.kev_added === 2 && sd.kev_foresight.named_first === 2 && sd.kev_foresight.median_lead_days != null, 'KEV foresight: both KEV CVEs named first ' + JSON.stringify(sd.kev_foresight));
  ok(sd.cve_surge_hits.mature === 1 && sd.cve_surge_hits.listed_after === 1 && sd.cve_surge_hits.share === 100, 'a surge alert whose CVE KEV listed later is a hit ' + JSON.stringify(sd.cve_surge_hits));
  ok(sd.sources.active === 3 && sd.sources.answering === 2 && sd.sources.failing === 1 && sd.collector.runs_7d > 0, 'sources and collector shares');
  ok(sd.rows.some((r) => r.metric === 'kev_foresight_share' && r.value === 100 && r.n === 2), 'the day\'s values are kept as a series');
  const again = await M.runJob('score');
  ok(again.ok && (await db.query(`SELECT count(*)::int AS n FROM ti.score WHERE metric = 'kev_foresight_share'`)).rows[0].n === 1, 'one value per metric and day');
}
// ---------------------------------------------------------------- cyber-physical coincidences (37n-cyphys.mjs)
{
  ok(M.conflictZ(60, 10, 5) === 10 && M.conflictZ(12, 10, 0) === 0.6 && M.conflictZ(null, 1, 1) === null, 'conflict z, with a Poisson floor on the spread');
  const f = M.flagsOf({ outage_hours: 3, conflict_z: 4, conflict_24h: 50, cyber_p: 3, cyber_per_day: 2, cyber_base: 0.2 });
  ok(f.outage && f.conflict && f.cyber && f.elevated === 3 && M.flagsOf({ outage_hours: 0.5, conflict_z: 4, conflict_24h: 5, cyber_p: 1, cyber_per_day: 1, cyber_base: 1 }).elevated === 0, 'flags and their floors');
  // Ukraine: three hours of outage, a conflict spike over ten quiet days, and threat reporting from three publishers.
  await db.query(`INSERT INTO ti.disruption (source, entity, start_at, end_at, cc, name, level, score) VALUES ('ioda', 'country/UA/bgp', now() - interval '5 hours', now() - interval '2 hours', 'UA', 'Ukraine', 'warning', 900),
    ('ioda', 'country/UA/ping-slash24', now() - interval '4 hours', now() - interval '3 hours', 'UA', 'Ukraine', 'critical', 2000), ('ioda', 'country/FR/bgp', now() - interval '10 hours', now() - interval '9 hours', 'FR', 'France', 'normal', 10)`);
  for (let d = 2; d <= 12; d++) await db.query(`INSERT INTO ti.gdelt_country (slot, iso2, n, m) VALUES (now() - make_interval(days => $1), 'UA', 20, 10)`, [d]);
  await db.query(`INSERT INTO ti.gdelt_country (slot, iso2, n, m) VALUES (now() - interval '3 hours', 'UA', 300, 120)`);
  await insert([['https://u/1', 'Sandworm wiper hits Ukrainian grid', 'u1.com', 'research', 0.3, ['actor:G0007', 'country:UA']], ['https://u/2', 'APT28 targets Ukraine again', 'u2.com', 'cyber-news', 0.4, ['actor:G0007', 'country:UA']],
    ['https://u/3', 'Ukrainian CERT warns of APT28', 'u3.com', 'government', 0.5, ['actor:G0007', 'country:UA']]]);
  const rc = await M.runJob('cyphys');
  const cd = JSON.parse(zlib.gunzipSync(bucket.get('ti-docs/docs/cyphys.json.gz')).toString());
  const ua = cd.rows.find((r) => r.cc === 'UA'), ru = cd.rows.find((r) => r.cc === 'RU');
  ok(rc.ok && ua && ua.outage && ua.conflict && ua.cyber && ua.elevated === 3 && ua.outage_hours === 3 && ua.outage_signals === 2 && ua.outage_critical, 'Ukraine: three signals elevated ' + JSON.stringify(ua).slice(0, 300));
  ok(!cd.rows.some((r) => r.cc === 'FR'), 'a normal-level outage is not a signal');
  ok(ru && ru.attributed_actors.some((a) => a.id === 'actor:G0007') && ru.elevated === 0, 'Russia carries the attributed actor (attacker side), not an elevated signal');
  ok(cd.coincidences === 1 && ua.entities.some((e) => e.n === 'APT28'), 'one coincidence, with the threat entities named beside the country');
  await M.runJob('watch');
  const w4 = (await db.query(`SELECT headline, subject FROM ti.alert WHERE watch = 'W-4A'`)).rows;
  ok(w4.length === 1 && w4[0].subject === 'country:UA' && /outage, conflict, cyber elevated together/.test(w4[0].headline), 'W-4A: the coincidence becomes a change alert ' + JSON.stringify(w4));
}
console.log(`watch_test: ${pass} checks passed`);
