// Offline test of the collector alert workflow (.github/workflows/collector-alert.yml): the script is taken from the
// workflow file itself, so the test runs exactly what the scheduled job runs. Problems are judged on the health record
// of 2 November 2026 (test/fixtures/health_20261102.json) and variations of it; GitHub and the endpoint are mocked.
// node test/alert_test.mjs <repository root>
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

const ROOT = path.resolve(process.argv[2] || '.');
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };

// ---------------------------------------------------------------- the script, as the workflow writes it
const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'collector-alert.yml'), 'utf8').split('\n');
const from = yml.findIndex((l) => l.includes("<<'SCRIPT'"));
const to = yml.findIndex((l, i) => i > from && l.trim() === 'SCRIPT');
ok(from > 0 && to > from, 'workflow embeds the script');
const indent = yml[from].match(/^ */)[0].length;
const src = yml.slice(from + 1, to).map((l) => l.slice(indent)).join('\n') + '\n';
ok(/^permissions:\n  issues: write\n\n/m.test(yml.join('\n')) && !/actions\/checkout|contents:/.test(yml.join('\n')), 'workflow token: issues write only, no checkout');
const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'alert-')), 'collector_alert.mjs');
fs.writeFileSync(file, src);
process.env.HEALTH_URL = 'https://health.test/api/health';
process.env.GITHUB_REPOSITORY = 'owner/repo';
process.env.GITHUB_TOKEN = 'test-token';
const A = await import(pathToFileURL(file).href);

const BASE = JSON.parse(fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'health_20261102.json'), 'utf8'));
const NOW = Date.parse(BASE.at);
const clone = () => JSON.parse(JSON.stringify(BASE));
const job = (h, name) => h.collector.jobs.find((j) => j.job === name);
const feed = (h, name) => h.collector.feeds.find((f) => f.feed === name);
const titles = (r) => r.problems.map((p) => p.title).sort();
const minAgo = (m) => new Date(NOW - m * 60000).toISOString();

// ---------------------------------------------------------------- evaluate
{
  const r = A.evaluate(BASE, NOW);
  ok(r.complete && r.problems.length === 0, 'the 2 November record holds no problem (gaps hold, GreyNoise is not a map feed) ' + titles(r));
}
{
  const h = clone();
  Object.assign(job(h, 'snap'), { ok: false, error: 'no snapshot succeeded: 503' });
  job(h, 'gdelt').last_run = minAgo(120);
  Object.assign(job(h, 'links'), { failed_24h: 3, runs_24h: 24 });
  job(h, 'unit42').last_run = minAgo(20 * 60);   // daily: 20 hours is within its cadence
  job(h, 'genioc').last_run = minAgo(26 * 60);   // daily: 26 hours is past 24 hours plus 90 minutes
  h.collector.jobs = h.collector.jobs.filter((j) => j.job !== 'sec8k');
  const r = A.evaluate(h, NOW);
  ok(JSON.stringify(titles(r)) === JSON.stringify(['Collector: gdelt failing', 'Collector: genioc failing', 'Collector: links failing', 'Collector: sec8k failing', 'Collector: snap failing']), 'job problems ' + titles(r));
  const by = Object.fromEntries(r.problems.map((p) => [p.title, p]));
  ok(/last run failed .*503/.test(by['Collector: snap failing'].lines[0]) && /silent for 120 minutes/.test(by['Collector: gdelt failing'].lines[0]) && /3 of 24 runs failed/.test(by['Collector: links failing'].lines[0])
    && /no run recorded/.test(by['Collector: sec8k failing'].lines[0]), 'job problem detail');
  ok(A.silentAfterMin('gdelt') === 90 && A.silentAfterMin('blogs') === 90 && A.silentAfterMin('unit42') === 1530 && A.silentAfterMin('sec8k') === 930 && A.silentAfterMin('ransompay') === 10170, 'silence judged against each cadence');
}
{
  const h = clone();
  Object.assign(feed(h, 'feodo'), { ok: false, status: 503, failing_streak: 4, error: 'HTTP 503' });
  Object.assign(feed(h, 'epss'), { ok: false, status: 503, failing_streak: 3 });
  feed(h, 'greynoise').failing_streak = 9;
  const r = A.evaluate(h, NOW);
  ok(JSON.stringify(titles(r)) === '["Collector: feodo failing"]' && /failing streak of 4 checks/.test(r.problems[0].lines[0]), 'feed streak of 4 on a map feed only ' + titles(r));
  feed(h, 'feodo').failing_streak = 7;
  ok(A.evaluate(h, NOW).problems[0].fingerprint === r.problems[0].fingerprint, 'a growing streak keeps the same fingerprint');
}
{
  const h = clone();
  Object.assign(feed(h, 'marad_msci'), { ok: true, status: 200, failing_streak: 0 });
  Object.assign(feed(h, 'nga_msi'), { ok: false, status: 503, error: 'HTTP 503' });
  feed(h, 'gdelt_doc_api').status = 429;
  h.collector.volume.find((v) => v.feed === 'asam').n = 3;
  const r = A.evaluate(h, NOW);
  ok(JSON.stringify(titles(r)) === JSON.stringify(['Collector: asam answer changed', 'Collector: marad_msci answer changed', 'Collector: nga_msi answer changed']), 'known gaps reported only when their answer changes ' + titles(r));
  // A collector that marks states decides by state.
  Object.assign(feed(h, 'ukmto'), { status: 0, ok: false, state: 'known_gap' });
  Object.assign(feed(h, 'gdelt_doc_api'), { status: 429, ok: false, state: 'down' });
  const r2 = A.evaluate(h, NOW);
  ok(!titles(r2).includes('Collector: ukmto answer changed') && titles(r2).includes('Collector: gdelt_doc_api answer changed'), 'state field wins when present');
}
{
  const h = clone();
  h.collector.checked_at = minAgo(150);
  const r = A.evaluate(h, NOW);
  ok(!r.complete && JSON.stringify(titles(r)) === '["Collector: health failing"]' && /150 minutes ago/.test(r.problems[0].lines[0]), 'a stale record is one problem and is not judged further');
  const c = clone(); c.collector = { ok: false, reason: 'collector HTTP 503' };
  const rc = A.evaluate(c, NOW);
  ok(!rc.complete && JSON.stringify(titles(rc)) === '["Collector: collector record failing"]' && rc.closable.includes('Collector: api/health failing'), 'unreadable collector record');
  const re = A.evaluate({ error: 'HTTP 502' }, NOW);
  ok(!re.complete && JSON.stringify(titles(re)) === '["Collector: api/health failing"]' && re.closable.length === 0, 'endpoint down');
}

// ---------------------------------------------------------------- plan
{
  const lab = [{ name: A.LABEL }];
  const h = clone();
  Object.assign(feed(h, 'feodo'), { ok: false, status: 503, failing_streak: 5, error: 'HTTP 503' });
  const r = A.evaluate(h, NOW), at = BASE.at;
  let acts = A.plan(r, [], at);
  ok(acts.length === 1 && acts[0].op === 'create' && acts[0].title === 'Collector: feodo failing' && acts[0].body.includes('fingerprint:'), 'create one issue per problem');
  const open = [{ number: 7, title: 'Collector: feodo failing', body: acts[0].body, labels: lab }];
  ok(A.plan(r, open, at).length === 0, 'same detail: nothing to do');
  feed(h, 'feodo').status = 404; feed(h, 'feodo').error = 'HTTP 404';
  acts = A.plan(A.evaluate(h, NOW), open, at);
  ok(acts.length === 1 && acts[0].op === 'update' && acts[0].number === 7 && /HTTP 404/.test(acts[0].comment), 'changed detail: body updated and commented');
  const cleared = A.plan(A.evaluate(BASE, NOW), [...open, { number: 8, title: 'Collector: blogs failing', body: '', labels: [] }], at);
  ok(cleared.length === 1 && cleared[0].op === 'close' && cleared[0].number === 7 && /Cleared at/.test(cleared[0].comment), 'cleared: closed with a comment; an unlabelled issue is left alone');
  const stale = clone(); stale.collector.checked_at = minAgo(200);
  ok(A.plan(A.evaluate(stale, NOW), open, at).filter((a) => a.op === 'close').length === 0, 'an incomplete record closes nothing it could not judge');
  const endpointIssue = { number: 9, title: 'Collector: api/health failing', body: '', labels: lab };
  ok(A.plan(A.evaluate(stale, NOW), [endpointIssue], at).some((a) => a.op === 'close' && a.number === 9), 'the endpoint issue closes once the endpoint answers');
}

// ---------------------------------------------------------------- end to end against a fake GitHub and endpoint
{
  let health = clone(), nextNo = 100;
  const issues = [], calls = [];
  health.collector.checked_at = new Date().toISOString();
  for (const j of health.collector.jobs) j.last_run = new Date().toISOString();
  globalThis.fetch = async (url, opts = {}) => {
    const u = new URL(String(url)), method = opts.method || 'GET';
    if (u.host === 'health.test') return health ? new Response(JSON.stringify(health), { status: 200 }) : new Response('bad gateway', { status: 502 });
    assert.equal(u.host, 'api.github.com');
    assert.equal(opts.headers.authorization, 'Bearer test-token');
    calls.push(method + ' ' + u.pathname);
    const b = opts.body ? JSON.parse(opts.body) : null;
    if (method === 'GET' && u.pathname === '/repos/owner/repo/issues') return new Response(JSON.stringify(issues.filter((i) => i.state === 'open')), { status: 200 });
    if (method === 'POST' && u.pathname === '/repos/owner/repo/issues') { const i = { number: nextNo++, title: b.title, body: b.body, labels: b.labels.map((name) => ({ name })), state: 'open', comments: [] }; issues.push(i); return new Response(JSON.stringify(i), { status: 201 }); }
    const m = u.pathname.match(/^\/repos\/owner\/repo\/issues\/(\d+)(\/comments)?$/);
    const i = m && issues.find((x) => x.number === +m[1]);
    if (i && m[2] && method === 'POST') { i.comments.push(b.body); return new Response('{}', { status: 201 }); }
    if (i && method === 'PATCH') { Object.assign(i, b); return new Response(JSON.stringify(i), { status: 200 }); }
    return new Response('not found', { status: 404 });
  };
  delete process.env.DRY_RUN;
  Object.assign(feed(health, 'threatfox'), { ok: false, status: 401, failing_streak: 6, error: 'HTTP 401' });
  await A.main();
  ok(issues.length === 1 && issues[0].title === 'Collector: threatfox failing' && issues[0].labels[0].name === A.LABEL, 'main opens the issue');
  await A.main();
  ok(issues.length === 1 && issues[0].comments.length === 0, 'second run with the same detail changes nothing');
  Object.assign(feed(health, 'threatfox'), { ok: true, status: 200, failing_streak: 0, error: null });
  await A.main();
  ok(issues[0].state === 'closed' && issues[0].state_reason === 'completed' && /Cleared at/.test(issues[0].comments[0]), 'cleared problem closed with a comment');
  process.env.DRY_RUN = '1';
  Object.assign(feed(health, 'urlhaus'), { ok: false, status: 500, failing_streak: 4 });
  const n = calls.length;
  await A.main();
  ok(issues.length === 1 && calls.slice(n).every((c) => c.startsWith('GET')), 'dry run reads, writes nothing');
  delete process.env.DRY_RUN;
  health = null;
  const r = await A.readHealth('https://health.test/api/health', [1, 1]);
  ok(r.error === 'HTTP 502', 'endpoint failure after three tries ' + JSON.stringify(r));
}

console.log(`PASS ${pass} checks (collector alerts)`);
