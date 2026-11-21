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
// The daily allowance (real budget path, no injected chat).
await db.query(`INSERT INTO ti.kv (k, v, at) VALUES ('translate:budget', $1, now())`, [{ day: new Date().toISOString().slice(0, 10), used: M.TR.DAILY }]);
ok((await M.translateBatch([{ link: 'x', title: 'Хакеры', lang: 'ru' }], { models: ['m:free'] })).stop === 'daily allowance spent', 'the daily allowance stops requests');
// Search matches the English title of a Russian entry.
const s = await M.search({ q: 'attacked a bank', days: 7 });
ok(s.hits.some((h) => h.link === 'https://ru/1' && h.title_en === 'Hackers attacked a bank' && h.lang === 'ru'), 'search finds a Russian entry by its English title ' + JSON.stringify(s.hits.map((h) => h.link)));
ok(M.plan(new Date('2026-11-20T10:04:00Z')).join().includes('sources,translate,triage,entities') && !M.plan(new Date('2026-11-20T10:49:00Z')).includes('translate'), 'translate runs between sources and entities, in the slots that read sources');
console.log(`translate_test: ${pass} checks passed`);
