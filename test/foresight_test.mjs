// Offline test of threatcasting (neon/parts/37p-foresight.mjs) and the signpost watch (37l-watch.mjs, kind signpost):
// the set checker's failures, the reading, theater choice and refresh rules, one repair round, the stored attempts,
// the published document, the bucket fallback when the site is down, and a signpost alert on an indicator state change.
// node test/foresight_test.mjs <repository root>   (after python3 pipeline/collector_build.py .)
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';

const ROOT = path.resolve(process.argv[2] || '.');
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };

const db = await PGlite.create({ extensions: { pg_trgm } });
await db.exec(fs.readFileSync(path.join(ROOT, 'neon', 'schema.sql'), 'utf8'));
const RAW = Object.fromEntries(Array.from({ length: 6000 }, (_, i) => [i, (v) => v]));
const runSql = async (q, params) => { const r = await db.query(q, params, { rowMode: 'array', parsers: RAW }); return { fields: r.fields, rows: r.rows }; };
process.env.DATABASE_URL = 'postgresql://ti_app:pw@ep-test-pooler.c-14.us-east-1.aws.neon.tech/threatintel?sslmode=require';
process.env.AWS_ENDPOINT_URL_S3 = 'https://br-test.storage.c-14.us-east-1.aws.neon.tech';
process.env.AWS_ACCESS_KEY_ID = 'nak_test'; process.env.AWS_SECRET_ACCESS_KEY = 'nsk_test';
const bucket = new Map();

// ---------------------------------------------------------------- fixture site data
const T = (id, name, tc, label, trend) => ({ theater_id: id, name, region: 'Test', threatcon: tc, label, trend, key_judgment: `${name} judgment.`, basis: 'Basis text.', sponsor_posture: 'Posture.',
  cyber_nexus: 'Nexus.', scenario: 'Analyst scenario.', so_what: 'So what.', outlook: 'Outlook.', countries: 'IR' });
const theaters = [T('T-HRM', 'Strait of Hormuz', 5, 'CRITICAL', 'Escalating'), T('T-LEV', 'Levant', 4, 'HIGH', 'Stable'), T('T-BAL', 'Balkans', 2, 'GUARDED', 'Stable'),
  T('T-X1', 'Filler one', 1, 'LOW', 'Stable'), T('T-X2', 'Filler two', 1, 'LOW', 'Stable')];
const I = (id, th, dir, state, item) => ({ ind_id: id, theater_id: th, indicator: `Indicator ${id}`, direction: dir, state, last_seen: '2026-11-15', item_id: item, note: `Note ${id}`, theater_name: th });
let indicators = [I('W-HRM-1', 'T-HRM', 'Escalation', 'Emerging', 'I-1'), I('W-HRM-2', 'T-HRM', 'Escalation', 'Observed', 'I-2'), I('W-HRM-3', 'T-HRM', 'Escalation', 'Observed', 'I-3'),
  I('W-HRM-4', 'T-HRM', 'De-escalation', 'Not observed', 'I-4'), I('W-LEV-1', 'T-LEV', 'Escalation', 'Not observed', 'I-5'), I('W-LEV-2', 'T-LEV', 'Escalation', 'Observed', 'I-6'),
  ...Array.from({ length: 8 }, (_, n) => I(`W-BAL-${n}`, 'T-BAL', 'Escalation', 'Not observed', null))];
const items = Array.from({ length: 140 }, (_, n) => ({ item_id: `I-${n + 1}`, theater_id: n < 60 ? 'T-HRM' : n < 100 ? 'T-LEV' : 'T-BAL', date: `2026-11-${String(18 - (n % 18)).padStart(2, '0')}`,
  title: `Item ${n + 1} title`, url: `https://news.example/${n + 1}` }));
const WATCHES = { version: 1, terms: {}, term_labels: {}, watches: [{ id: 'W-4B', pir: 'PIR-4', kind: 'signpost', title: 'Signpost changed state' }] };
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
  const site = 'https://intel.kilfoycyber.com/data/';
  if (u.startsWith(site)) {
    if (!siteUp) return resp(503, 'down');
    const name = u.slice(site.length);
    if (name === 'theaters.json') return resp(200, theaters);
    if (name === 'theater_indicators.json') return resp(200, indicators);
    if (name === 'items.json') return resp(200, items);
    if (name === 'watches.json') return resp(200, WATCHES);
  }
  throw new Error('unexpected network request ' + u);
};
const M = await import(path.join(ROOT, 'neon', 'collector.mjs'));
const inp = () => ({ theaters, indicators, items });

// ---------------------------------------------------------------- the checker
const F = (kind, signposts, extra = {}) => ({ kind, name: `${kind} future for Hormuz`, narrative: 'A '.repeat(70) + kind,
  threatcast: { person: 'A treasury operations analyst', place: 'Dubai', activity: 'settling a cross-border payment run', adversary: 'IRGC-aligned operators seeking leverage', enablers: 'Exposed remote access', effects: 'Delayed settlement and staff relocation' },
  signposts, proposed_indicators: [{ indicator: 'Insurers withdraw war-risk cover for the strait', expect: 'present', why: 'Shipping cost signal' }],
  backcast: [{ when: 'month 6', step: 'The strait stays closed to unescorted traffic' }, { when: 'month 3', step: 'Strike package authorised by Washington' }, { when: 'now', step: 'Tanker claims rise week on week' }],
  actions: ['Review Gulf staff relocation triggers', 'Test payment failover away from Gulf data centers'], evidence: ['I-1', 'I-2'], ...extra });
const good = { futures: [
  F('escalation', [{ ind_id: 'W-HRM-1', expect: 'present' }, { ind_id: 'W-HRM-2', expect: 'present' }, { ind_id: 'W-HRM-4', expect: 'absent' }]),
  F('continuation', [{ ind_id: 'W-HRM-2', expect: 'present' }, { ind_id: 'W-HRM-3', expect: 'present' }]),
  F('de-escalation', [{ ind_id: 'W-HRM-1', expect: 'absent' }, { ind_id: 'W-HRM-4', expect: 'present' }]),
] };
const hrm = theaters[0], hrmInds = indicators.filter((i) => i.theater_id === 'T-HRM');
const ctx = { theater: hrm, indicators: hrmInds, items: new Set(items.filter((i) => i.theater_id === 'T-HRM').map((i) => i.item_id)) };
{
  const c = M.checkSet(good, ctx);
  ok(c.ok && c.set.futures.map((f) => f.kind).join() === 'escalation,continuation,de-escalation' && c.set.horizon_months === 6, 'a well-formed set passes ' + JSON.stringify(c.failures));
  const bad = (mut, re) => { const s = JSON.parse(JSON.stringify(good)); mut(s); const r = M.checkSet(s, ctx); ok(!r.ok && r.failures.some((f) => re.test(f)), `rejected: ${re} ${JSON.stringify(r.failures)}`); };
  bad((s) => s.futures.pop(), /three futures are needed/);
  bad((s) => { s.futures[1].kind = 'escalation'; }, /one future of each kind/);
  bad((s) => { s.futures[0].signposts.push({ ind_id: 'W-LEV-1', expect: 'present' }); }, /W-LEV-1 is not an indicator of T-HRM/);
  bad((s) => { s.futures[0].signposts[0].expect = 'absent'; }, /escalation future expects escalation indicators present/);
  bad((s) => { s.futures[2].signposts[1].expect = 'absent'; }, /de-escalation future expects/);
  bad((s) => { s.futures[2].signposts = [{ ind_id: 'W-HRM-4', expect: 'present' }, { ind_id: 'W-HRM-1', expect: 'absent' }]; s.futures[0].signposts = [{ ind_id: 'W-HRM-1', expect: 'present' }]; s.futures[0].signposts.push({ ind_id: 'W-HRM-4', expect: 'absent' }); s.futures[2].signposts.push({ ind_id: 'W-HRM-2', expect: 'present' }); }, /de-escalation future expects/);
  bad((s) => { s.futures[1].signposts = [{ ind_id: 'W-HRM-2', expect: 'present' }]; s.futures[1].proposed_indicators = []; }, /three or more signposts/);
  bad((s) => { s.futures[1].signposts = []; }, /at least one signpost must be an existing indicator/);
  bad((s) => { s.futures[0].evidence = ['I-120']; }, /evidence I-120 is not among the supplied items/);
  bad((s) => { s.futures[0].actions = ['We should review our Gulf exposure now', 'Test failover away from Gulf data centers']; }, /no first person/);
  bad((s) => { s.futures[0].narrative += ' This has a 40% chance of happening.'; }, /no probability or percentage/);
  bad((s) => { s.futures[1].backcast = s.futures[1].backcast.slice(0, 2); }, /three to six milestones/);
  bad((s) => { s.futures[1].threatcast.adversary = ''; }, /threatcast needs adversary/);
  bad((s) => { s.futures[1].name = s.futures[0].name; }, /distinct names/);
  const shared = JSON.parse(JSON.stringify(good));
  shared.futures[2].signposts.push({ ind_id: 'W-HRM-3', expect: 'absent' });
  ok(M.checkSet(shared, ctx).ok, 'escalation and de-escalation may share an indicator when they expect opposite states');
}
// ---------------------------------------------------------------- the reading
{
  const set = M.checkSet(good, ctx).set;
  const r = M.readSet(set, hrmInds);
  ok(r.futures[0].score === 0.83 && r.futures[1].score === 1 && r.futures[2].score === 0.25, 'scores: Emerging counts half ' + JSON.stringify(r.futures.map((f) => f.score)));
  ok(r.leans === null && /do not separate/.test(r.text), 'escalation 0.83 and continuation 1.0 are within 0.2: no lean');
  const r2 = M.readSet(set, hrmInds.map((i) => (i.ind_id === 'W-HRM-3' ? { ...i, state: 'Not observed' } : i)));
  ok(r2.leans === 'escalation' && r2.futures[0].met === 2, 'with continuation down to 0.5, escalation (0.83, two met) leads by more than 0.2 ' + JSON.stringify(r2.futures.map((f) => f.score)));
  const r3 = M.readSet(set, hrmInds.map((i) => (i.ind_id === 'W-HRM-1' ? { ...i, state: 'Not observed' } : i.ind_id === 'W-HRM-4' ? { ...i, state: 'Observed' } : i.ind_id === 'W-HRM-2' ? { ...i, state: 'Not observed' } : i)));
  ok(r3.leans === 'de-escalation' && r3.futures[2].met === 2 && /never a forecast/.test(r3.text), 'the de-escalation future leads when its signposts are met ' + JSON.stringify(r3.futures.map((f) => f.score)));
}
// ---------------------------------------------------------------- the job end to end
const sets = (kind) => ({ futures: good.futures });
let turn = 0;
const chat = async (model, messages) => {
  turn++;
  if (turn === 1) return { ok: true, msg: { content: '```json\n' + JSON.stringify({ futures: good.futures.slice(0, 2) }) + '\n```' } };
  return { ok: true, msg: { content: JSON.stringify(sets()) }, usage: { prompt_tokens: 5000, completion_tokens: 2000 } };
};
process.env.OPENROUTER_API_KEY = 'test-key';
const due = await M.foreDue(inp());
ok(due.map((d) => d.t.theater_id).join() === 'T-HRM,T-LEV' && due[0].why === 'no accepted set', 'only ThreatCon 4 and above, highest first ' + JSON.stringify(due.map((d) => [d.t.theater_id, d.why])));
const r1 = await M.runJob('foresight', { chat, models: ['test/model:free'] });
const row1 = (await db.query(`SELECT * FROM ti.foresight ORDER BY id`)).rows;
ok(r1.ok && row1.length === 1 && row1[0].outcome === 'accepted' && row1[0].theater_id === 'T-HRM' && row1[0].calls.length === 2, 'one repair round turns a two-future answer into an accepted set ' + JSON.stringify(r1).slice(0, 300));
const doc1 = JSON.parse(zlib.gunzipSync(bucket.get('ti-docs/docs/foresight.json.gz')).toString());
if (process.env.FORESIGHT_DOC_OUT) fs.writeFileSync(process.env.FORESIGHT_DOC_OUT, JSON.stringify(doc1));
const fut = doc1.rows.filter((r) => r.kind === 'future'), rd = doc1.rows.find((r) => r.kind === 'reading');
ok(fut.length === 3 && rd && rd.current === true && fut[0].signposts[0].url === 'https://news.example/1' && fut[0].evidence[0].title === 'Item 1 title', 'the document carries futures with signpost states, links and evidence');
ok(doc1.signposts['W-HRM-1'].length === 2 && (await db.query(`SELECT v FROM ti.kv WHERE k = 'foresight:signposts'`)).rows[0].v['W-HRM-4'].length === 2, 'the signpost index is published and kept for the watch');
turn = 1;
const r2 = await M.runJob('foresight', { chat, models: ['test/model:free'] });
ok(r2.attempt.theater_id === 'T-LEV' && r2.attempt.outcome === 'rejected', 'the next due theater is drafted; its answer cites the wrong theater\'s indicators and is rejected ' + JSON.stringify(r2.attempt));
const rej = (await db.query(`SELECT failures FROM ti.foresight WHERE theater_id = 'T-LEV'`)).rows[0].failures;
ok(rej.some((f) => /W-HRM-1 is not an indicator of T-LEV/.test(f)), 'rejected attempts keep the reasons');
const r3 = await M.runJob('foresight', { chat, models: ['test/model:free'] });
ok(r3.skipped === 'no theater is due', 'a rejected theater waits RETRY_H before another attempt; an accepted set waits for a change ' + JSON.stringify(r3));
// A change in an indicator state makes the theater due again, but not within a day of its last set.
indicators = indicators.map((i) => (i.ind_id === 'W-HRM-1' ? { ...i, state: 'Observed' } : i));
M.resetForesight();
ok(!(await M.foreDue(inp())).some((d) => d.t.theater_id === 'T-HRM'), 'a changed theater waits CHANGED_MIN_H');
await db.query(`UPDATE ti.foresight SET created_at = now() - interval '30 hours'`);
const d2 = await M.foreDue(inp());
ok(d2[0].t.theater_id === 'T-LEV' && d2[0].why === 'no accepted set' && d2[1].t.theater_id === 'T-HRM' && /changed/.test(d2[1].why), 'a missing set goes before a changed one ' + JSON.stringify(d2.map((d) => [d.t.theater_id, d.why])));
const doc2 = await M.foresightDoc(inp());
ok(doc2.rows.find((r) => r.kind === 'reading').current === false, 'the document marks a set drafted on older indicator states');
// The site down: the job reads the bucket copies.
siteUp = false; M.resetForesight();
const r4 = await M.runJob('foresight', { chat: async () => ({ ok: true, msg: { content: '{"futures": []}' } }), models: ['m:free'] });
ok(r4.ok && r4.attempt.theater_id === 'T-LEV', 'with the site down the inputs come from the bucket ' + JSON.stringify(r4).slice(0, 300));
siteUp = true; M.resetForesight();
ok(M.plan(new Date('2026-11-20T10:04:00Z')).includes('foresight') && !M.plan(new Date('2026-11-20T10:34:00Z')).includes('foresight'), 'foresight runs in the :04 quarter hour');

// ---------------------------------------------------------------- the signpost watch
M.resetWatches();
const w1 = await M.runJob('watch', {});
ok(w1.ok && w1.per_watch['W-4B'].candidates === 0 && (await db.query(`SELECT v FROM ti.kv WHERE k = 'signpost:states'`)).rows[0].v['W-HRM-4'] === 'Not observed', 'the first run records the states and opens nothing ' + JSON.stringify(w1).slice(0, 300));
indicators = indicators.map((i) => (i.ind_id === 'W-HRM-4' ? { ...i, state: 'Observed', item_id: 'I-7' } : i.ind_id === 'W-BAL-1' ? { ...i, state: 'Observed' } : i));
M.resetForesight();
const w2 = await M.runJob('watch', {});
const al = (await db.query(`SELECT * FROM ti.alert WHERE watch = 'W-4B'`)).rows;
ok(al.length === 1 && al[0].subject === 'indicator:W-HRM-4:Observed' && al[0].links[0].link === 'https://news.example/7', 'a signpost moving opens one alert with its item; a non-signpost indicator opens none ' + JSON.stringify(al));
ok(/W-HRM-4 \(T-HRM\) moved Not observed to Observed: Indicator W-HRM-4; now meets the signpost of "de-escalation future for Hormuz"/.test(al[0].headline), 'the headline names the future it now meets: ' + al[0].headline);
const w3 = await M.runJob('watch', {});
ok((await db.query(`SELECT count(*)::int AS n FROM ti.alert WHERE watch = 'W-4B'`)).rows[0].n === 1 && w3.per_watch['W-4B'].candidates === 0, 'no new alert without a new change');
console.log(`foresight_test: ${pass} checks passed`);
