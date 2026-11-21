// Offline test of non-English collection (neon/parts/37q-translate.mjs): language identification on the shared samples,
// the entry language at insert, the translation checks, and the translate job on real Postgres (PGlite) with a fake
// model: priority order, stored English titles, failures counted and given up after two, a model that answers nothing,
// the daily allowance, and search matching an English title.
// node test/translate_test.mjs <repository root>   (after python3 pipeline/collector_build.py .)
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
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
const resp = (status, body) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (u === 'https://api.c-14.us-east-1.aws.neon.tech/sql') {
    const body = JSON.parse(opts.body);
    try {
      if (body.queries) { await db.exec('BEGIN'); try { const results = []; for (const q of body.queries) results.push(await runSql(q.query, q.params)); await db.exec('COMMIT'); return resp(200, { results }); } catch (e) { await db.exec('ROLLBACK'); throw e; } }
      return resp(200, await runSql(body.query, body.params));
    } catch (e) { return resp(400, { message: e.message }); }
  }
  throw new Error('unexpected network request ' + u);
};
const M = await import(path.join(ROOT, 'neon', 'collector.mjs'));

// ---------------------------------------------------------------- language identification
const samples = JSON.parse(fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'lang_samples.json'), 'utf8')).cases;
for (const [t, l] of samples) ok(M.detectLang(t) === l, `${JSON.stringify(t)}: ${l}, got ${M.detectLang(t)}`);
ok(M.entryLang('Banco de Mexico hacked', '', 'es') === 'es' && M.entryLang('Banco de Mexico hacked', '', undefined) === 'en', 'an unsettled title takes the feed tag, else en');
ok(M.entryLang('Patch now', 'Microsoft fixed the flaw in the update that shipped on Tuesday for all users', 'ru') === 'en', 'an English entry in a Russian-tagged feed is English');
ok(M.entryLang('Короткий', 'Хакеры атаковали крупнейший банк России, сбои в работе приложения', 'en') === 'ru', 'the summary settles a short title');

// ---------------------------------------------------------------- translation checks
const ck = M.checkTranslation;
ok(!ck('Хакеры атаковали банк', 'ru', 'Hackers attacked a bank').length, 'a plain translation passes');
ok(ck('Уязвимость CVE-2026-12345 в роутерах', 'ru', 'Vulnerability in routers').some((f) => /CVE-2026-12345 not kept/.test(f)), 'a dropped CVE id fails');
ok(ck('В 2026 году атаки выросли', 'ru', 'Attacks grew this year').some((f) => /number 2026 not kept/.test(f)), 'a dropped year fails');
ok(!ck('Утечка 15 000 записей в 2026', 'ru', 'Leak of 15,000 records in 2026').length, 'reformatted thousands pass');
ok(!ck('٢٠٢٦ هجوم سيبراني', 'ar', 'Cyber attack in 2026').length, 'Arabic-Indic digits count as their ASCII digits');
ok(ck('Хакеры атаковали банк', 'ru', 'Хакеры атаковали банк').some((f) => /Latin|same as the source/.test(f)), 'an untranslated line fails');
ok(ck('网络安全漏洞预警', 'zh', '').includes('empty') && ck('漏洞', 'zh', 'x'.repeat(500)).some((f) => /400|length/.test(f)), 'empty and overlong answers fail');
ok(!ck('Cyberangriff auf Stadtwerke', 'de', 'Cyberattack on municipal utilities').length, 'German passes');
const pa = M.parseTranslations('```json\n{"t":[{"i":1,"en":"a"},{"i":1,"en":"dup"},{"i":3,"en":"c"},{"i":9,"en":"out of range"}]}\n```', 3);
ok(pa.size === 2 && pa.get(1) === 'a' && pa.get(3) === 'c', 'duplicates and out-of-range lines are dropped');
// 3.12.1: the other shapes models answer in.
const arr = M.parseTranslations('[{"i":1,"en":"a"},{"i":2,"en":"b"}]', 2);
ok(arr.size === 2 && arr.get(2) === 'b', 'a bare JSON array is read');
const cut = M.parseTranslations('{"t": [{"i": 1, "en": "Hackers attacked a bank"}, {"i": 2, "en": "Leak of \\"15,000\\" records"}, {"i": 3, "en": "Cyber', 3);
ok(cut.size === 2 && cut.get(2) === 'Leak of "15,000" records', 'an answer cut short keeps its complete entries ' + JSON.stringify([...cut]));
const lines = M.parseTranslations('1\t[ru]\tHackers attacked a bank\n2. Vulnerability in routers\n3) Cyber warning\nNote: done', 3);
ok(lines.size === 3 && lines.get(1) === 'Hackers attacked a bank' && lines.get(3) === 'Cyber warning', 'numbered lines in the request layout are read ' + JSON.stringify([...lines]));
let pe = ''; try { M.parseTranslations('', 2); } catch (e) { pe = e.message; }
ok(pe === 'empty answer', 'an empty answer says so');
pe = ''; try { M.parseTranslations('Sorry, I cannot help.', 2); } catch (e) { pe = e.message; }
ok(pe === 'no numbered translations in the answer', 'prose is unreadable');
ok(M.rankModels(['a', 'b', 'c'], {}).join() === 'a,b,c', 'without a record the list order stands');
ok(M.rankModels(['a', 'b', 'c'], { a: { ok: 0, bad: 6 }, c: { ok: 5, bad: 0 } }).join() === 'c,b,a', 'the record orders the models');
const ms1 = M.updateModelStats({ a: { ok: 10, bad: 0 }, z: { ok: 0.01, bad: 0.01 } }, [{ model: 'a', ok: true, error: null }, { model: 'b', ok: true, error: 'unreadable answer: empty answer' },
  { model: 'c', ok: false, status: 429 }, { model: 'd', ok: false, error: 'deadline passed', short: true }, { model: 'e', ok: false, error: 'deadline passed' }]);
ok(ms1.a.ok === 10.7 && ms1.b.bad === 1 && !ms1.c && !ms1.d && ms1.e.bad === 1 && !ms1.z, 'stats decay; 429s and run-shortened timeouts count nothing ' + JSON.stringify(ms1));

// ---------------------------------------------------------------- the job
const item = (link, title, lang, category, hoursAgo) => db.query(`INSERT INTO ti.item (link, fp, feed, host, title, summary, published, category, lang, seen_at) VALUES ($1, $1, 'f', 'h.example', $2, '', now() - make_interval(hours => $5), $3, $4, now() - make_interval(hours => $5))`, [link, title, category, lang, hoursAgo]);
await item('https://ru/1', 'Хакеры атаковали банк', 'ru', 'geopolitics', 1);
await item('https://ru/2', 'Уязвимость CVE-2026-12345 в роутерах', 'ru', 'cyber-news', 2);
await item('https://zh/1', '网络安全漏洞预警：路由器存在远程代码执行漏洞', 'zh', 'research', 3);
await item('https://en/1', 'Hackers attack a bank', 'en', 'cyber-news', 1);
await item('https://ru/old', 'Старая новость', 'ru', 'cyber-news', 60);
const pend = await M.pendingTitles(10);
ok(pend.map((r) => r.link).join() === 'https://ru/2,https://zh/1,https://ru/1', 'cyber categories first, newest first; English and older than 48 hours left out ' + JSON.stringify(pend.map((r) => r.link)));
const seen = [];
const chat = async (model, messages) => {
  seen.push(messages[1].content);
  const lines = messages[1].content.split('\n').map((l) => l.split('\t'));
  const t = lines.map(([i, , src]) => ({ i: +i, en: /CVE/.test(src) ? 'Vulnerability in routers' : /路由器/.test(src) ? 'Cybersecurity warning: remote code execution flaw in routers' : 'Hackers attacked a bank' }));
  return { ok: true, msg: { content: JSON.stringify({ t }) } };
};
process.env.OPENROUTER_API_KEY = 'test-key';
const r1 = await M.runJob('translate', { chat, models: ['m:free'] });
const rows = Object.fromEntries((await db.query(`SELECT link, title_en, tr_model, tr_fail, tr_at FROM ti.item`)).rows.map((r) => [r.link, r]));
ok(r1.ok && r1.translated === 2 && r1.failed === 1 && r1.reasons['# not kept'] === 1, 'two stored, one failed for a dropped CVE id ' + JSON.stringify(r1).slice(0, 400));
ok(rows['https://ru/1'].title_en === 'Hackers attacked a bank' && rows['https://ru/1'].tr_model === 'm:free' && rows['https://ru/1'].tr_at && rows['https://ru/2'].title_en === null && rows['https://ru/2'].tr_fail === 1, 'English titles stored with model and time; the failure counted');
ok(/^1\t\[ru\]\tУязвимость CVE-2026-12345/.test(seen[0]), 'lines are numbered with their language');
ok(r1.queue.waiting === 1 && r1.queue.translated === 2, 'the queue status ' + JSON.stringify(r1.queue));
await M.runJob('translate', { chat, models: ['m:free'] });
const r3 = await M.runJob('translate', { chat, models: ['m:free'] });
ok((await db.query(`SELECT tr_fail FROM ti.item WHERE link = 'https://ru/2'`)).rows[0].tr_fail === 2 && r3.batches === 0, 'a title is given up after two failures');
const st = (await db.query(`SELECT v FROM ti.kv WHERE k = 'translate:status'`)).rows[0].v;
ok(st.given_up === 1 && st.langs_24h.some((l) => l.lang === 'ru' && l.translated === 1), 'status in kv for the sources document ' + JSON.stringify(st));
// A model that never answers readable JSON: the batch counts a failure for each line so the queue moves.
await item('https://ko/1', '국내 금융기관 해킹 사이버공격으로 서비스 장애', 'ko', 'topic-cyber', 1);
const r4 = await M.runJob('translate', { chat: async () => ({ ok: true, msg: { content: 'Sorry, I cannot help.' } }), models: ['a:free', 'b:free'] });
ok(r4.stop === 'no model answered with readable JSON' && r4.calls.length === 2 && (await db.query(`SELECT tr_fail FROM ti.item WHERE link = 'https://ko/1'`)).rows[0].tr_fail === 1, 'unreadable answers: each model tried, the line counted ' + JSON.stringify(r4).slice(0, 300));
const r4b = await M.runJob('translate', { chat: async () => ({ ok: false, status: 0, error: 'deadline passed' }), models: ['a:free', 'b:free'] });
ok(r4b.stop === 'no model answered with readable JSON' && (await db.query(`SELECT tr_fail FROM ti.item WHERE link = 'https://ko/1'`)).rows[0].tr_fail === 1, 'timeouts count nothing against the titles ' + JSON.stringify(r4b).slice(0, 200));
const late = await M.translateBatch([{ link: 'x', title: 'Хакеры', lang: 'ru' }], { chat, models: ['m:free'] }, Date.now() + 5000);
ok(late.stop === 'run time spent' && late.calls.length === 0, 'no request starts without enough of the run left');
let k429 = 0;
const r6 = await M.runJob('translate', { chat: async (model, msgs) => (model === 'a:free' ? (k429++, { ok: false, status: 429, error: 'rate limited' }) : chat(model, msgs)), models: ['a:free', 'b:free'] });
ok(k429 >= 1 && r6.translated >= 1 && r6.calls.some((c) => c.model === 'b:free' && c.ok), 'a 429 on one model passes the batch to the next ' + JSON.stringify(r6).slice(0, 300));
await db.query(`UPDATE ti.item SET title_en = NULL, tr_at = NULL, tr_fail = 1 WHERE link = 'https://ko/1'`);
const r5 = await M.runJob('translate', { chat: async () => ({ ok: false, status: 429, error: 'rate limited' }), models: ['a:free'] });
ok(r5.stop === 'every model answered HTTP 429' && (await db.query(`SELECT tr_fail FROM ti.item WHERE link = 'https://ko/1'`)).rows[0].tr_fail === 1, 'a rate limit stops the run and counts nothing against the titles');
// An answer that leaves lines out: the lines answered are stored, the others wait without a failure counted.
await db.query(`UPDATE ti.item SET title_en = NULL, tr_at = NULL, tr_fail = 0 WHERE link = 'https://ko/1'`);
await item('https://ko/2', '사이버 공격으로 은행 서비스 중단', 'ko', 'topic-cyber', 1);
await db.query(`DELETE FROM ti.kv WHERE k = 'translate:models'`);
const rh = await M.runJob('translate', { chat: async () => ({ ok: true, finish: 'length', msg: { content: '{"t":[{"i":1,"en":"Hacking of a domestic financial institution disrupts service"},{"i":2,"en":"Cyber attack' } }), models: ['h:free'] });
const kos = Object.fromEntries((await db.query(`SELECT link, title_en, tr_fail FROM ti.item WHERE link LIKE 'https://ko/%'`)).rows.map((r) => [r.link, r]));
ok(rh.translated === 1 && rh.unanswered === 1 && Object.values(kos).filter((r) => r.title_en).length === 1 && Object.values(kos).every((r) => r.tr_fail === 0), 'a cut-short answer stores what it completed; the rest waits ' + JSON.stringify({ rh: { t: rh.translated, u: rh.unanswered, f: rh.failed }, kos }));
const mk = (await db.query(`SELECT v FROM ti.kv WHERE k = 'translate:models'`)).rows[0].v;
ok(mk.stats['h:free'].ok === 1 && mk.order[0] === 'h:free', 'the model record is kept in kv ' + JSON.stringify(mk));
// The daily allowance (real budget path, no injected chat).
await db.query(`INSERT INTO ti.kv (k, v, at) VALUES ('translate:budget', $1, now())`, [{ day: new Date().toISOString().slice(0, 10), used: M.TR.DAILY }]);
ok((await M.translateBatch([{ link: 'x', title: 'Хакеры', lang: 'ru' }], { models: ['m:free'] })).stop === 'daily allowance spent', 'the daily allowance stops requests');
// Search matches the English title of a Russian entry.
const s = await M.search({ q: 'attacked a bank', days: 7 });
ok(s.hits.some((h) => h.link === 'https://ru/1' && h.title_en === 'Hackers attacked a bank' && h.lang === 'ru'), 'search finds a Russian entry by its English title ' + JSON.stringify(s.hits.map((h) => h.link)));
ok(M.plan(new Date('2026-11-20T10:04:00Z')).join().includes('sources,translate,entities') && M.plan(new Date('2026-11-20T10:49:00Z')).join().includes('sources,translate,triage'), 'translate runs right after sources in every slot');

// ---------------------------------------------------------------- scale (3.11.0): theater priority, parallel batches, the allowance under concurrency
await db.query(`DELETE FROM ti.item`);
await db.query(`DELETE FROM ti.kv WHERE k = 'translate:budget'`);
for (let n = 0; n < 130; n++) await db.query(`INSERT INTO ti.item (link, fp, feed, host, title, summary, published, category, region, lang, seen_at) VALUES ($1, $1, 'f', 'h', $2, '', now(), $3, $4, 'fa', now() - make_interval(mins => $5))`,
  [`https://fa/${n}`, `خبر شماره ${1000 + n} درباره حمله`, n < 10 ? 'cyber-news' : 'geopolitics', n % 2 ? 'T-HRM' : 'T-BAL', n]);
const pr = await M.pendingTitles(20, [], ['T-HRM']);
ok(pr.slice(0, 10).every((r) => +r.link.split('/').pop() < 10) && pr.slice(10).every((r) => +r.link.split('/').pop() % 2 === 1), 'cyber first, then the high-level theater\'s press ' + JSON.stringify(pr.map((r) => r.link.split('/').pop())));
const order = [];
const pchat = async (model, messages) => {
  order.push(model);
  await new Promise((r) => setTimeout(r, 20));
  const lines = messages[1].content.split('\n').map((l) => l.split('\t'));
  return { ok: true, msg: { content: JSON.stringify({ t: lines.map(([i, , src]) => ({ i: +i, en: `News number ${src.match(/\d{4}/)[0]} about an attack` })) }) } };
};
const rp = await M.runJob('translate', { chat: pchat, models: ['a:free', 'b:free', 'c:free'] });
ok(rp.ok && rp.translated === 130 && rp.batches === 4, 'parallel rounds clear 130 titles in four batches ' + JSON.stringify(rp).slice(0, 300));
ok(order.slice(0, 3).sort().join() === 'a:free,b:free,c:free', 'the parallel batches of a round start on different models ' + JSON.stringify(order));
// The allowance holds under parallel requests: 10 requests at once against 3 left grant exactly 3.
await db.query(`DELETE FROM ti.kv WHERE k = 'translate:budget'`);
await db.query(`INSERT INTO ti.kv (k, v, at) VALUES ('translate:budget', $1, now())`, [{ day: new Date().toISOString().slice(0, 10), used: M.TR.DAILY - 3, cap: M.TR.DAILY }]);
const got = await Promise.all(Array.from({ length: 10 }, () => M.translateBatch([{ link: 'z', title: 'خبر', lang: 'fa' }], { models: ['m:free'] }).catch((e) => ({ err: e.message }))));
const used = (await db.query(`SELECT v FROM ti.kv WHERE k = 'translate:budget'`)).rows[0].v.used;
ok(used === M.TR.DAILY && got.filter((g) => g.stop === 'daily allowance spent').length >= 7, 'parallel requests never overspend the allowance ' + JSON.stringify({ used, stops: got.map((g) => g.stop) }));
console.log(`translate_test: ${pass} checks passed`);
