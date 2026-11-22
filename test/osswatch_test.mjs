// Offline test of the open-source disclosure watch (neon/parts/37r-osswatch.mjs): fixture answers from OSV.dev, the
// GitHub tree of google/oss-fuzz, ecosyste.ms, seclists.org, HackerOne Hacktivity and CVE Services, real Postgres
// (PGlite) behind a fake Neon SQL endpoint, an in-memory bucket, no network. Covers the ranged modified_id.csv read
// (cut last line, window cutoff, malicious-package ids skipped), one row per advisory across ecosystems, reach (critical,
// top 1%, limited, OSS-Fuzz, unmeasured), CVE states (complete, incomplete, reserved, none), the lead and "ahead",
// Hacktivity paging and its weakness counts, the token path (Basic auth, the weakness list), records not read twice,
// and the recheck that completes a record.
// node test/osswatch_test.mjs <repository root>   (after python3 pipeline/collector_build.py .)
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
delete process.env.HACKERONE_API_USERNAME; delete process.env.HACKERONE_API_TOKEN;

// ---------------------------------------------------------------- fixtures, dated from now so the windows hold
const DAY = 86400000, now = Date.now();
const at = (d) => new Date(now - d * DAY).toISOString();
const atNs = (d) => at(d).replace('Z', '123456Z'); // OSV writes nanoseconds
const OSV = {
  npm: [[0.1, 'MAL-2026-90001'], [0.2, 'GHSA-aaaa-aaaa-aaaa'], [1, 'GHSA-bbbb-bbbb-bbbb'], [40, 'GHSA-old0-old0-old0']],
  PyPI: [[0.5, 'GHSA-cccc-cccc-cccc'], [2, 'PYSEC-2026-77']],
  Maven: [[0.3, 'GHSA-aaaa-aaaa-aaaa']],
  'OSS-Fuzz': [[0.4, 'OSV-2026-1001']],
};
const csv = (eco) => OSV[eco].map(([d, id]) => `${atNs(d)},${id}`).join('\n') + '\n2026-01-01T00:00:00Z,GHSA-cut'; // ranged read ends mid-line
const REC = {
  'GHSA-aaaa-aaaa-aaaa': { id: 'GHSA-aaaa-aaaa-aaaa', aliases: ['CVE-2026-1111'], summary: 'left-pad prototype pollution', published: at(5), modified: atNs(0.2),
    affected: [{ package: { ecosystem: 'npm', name: 'left-pad' } }, { package: { ecosystem: 'Maven', name: 'org.webjars.npm:left-pad' } }],
    database_specific: { cwe_ids: ['CWE-1321'], severity: 'HIGH', github_reviewed: true } },
  'GHSA-bbbb-bbbb-bbbb': { id: 'GHSA-bbbb-bbbb-bbbb', aliases: [], summary: 'left-pad ReDoS with no CVE', published: at(2), modified: atNs(1),
    affected: [{ package: { ecosystem: 'npm', name: 'left-pad' } }], database_specific: { cwe_ids: ['CWE-1333'], severity: 'MODERATE' } },
  'GHSA-cccc-cccc-cccc': { id: 'GHSA-cccc-cccc-cccc', aliases: ['CVE-2026-4444'], summary: 'tinylib path traversal', published: at(3), modified: atNs(0.5),
    affected: [{ package: { ecosystem: 'PyPI', name: 'tinylib' } }], database_specific: { cwe_ids: ['CWE-22'] } },
  'PYSEC-2026-77': { id: 'PYSEC-2026-77', aliases: ['CVE-2026-5555'], details: 'Old advisory modified today\nmore', published: at(200), modified: atNs(2),
    affected: [{ package: { ecosystem: 'PyPI', name: 'popular-lib' } }] },
  'OSV-2026-1001': { id: 'OSV-2026-1001', summary: 'Heap-buffer-overflow in xmlParseChunk', published: at(1), modified: atNs(0.4), affected: [{ package: { ecosystem: 'OSS-Fuzz', name: 'libxml2' } }],
    database_specific: { severity: 'HIGH' } },
};
const FUZZ = ['curl', 'libxml2', 'openssl', 'json', 'git', ...Array.from({ length: 600 }, (_, i) => `proj${i}`)];
const REACH = { 'npmjs.org/left-pad': { critical: true, rankings: { average: 0.9 }, dependent_packages_count: 643, dependent_repos_count: 1195353 },
  'pypi.org/tinylib': { critical: null, rankings: { average: 41.2 }, dependent_packages_count: 2, dependent_repos_count: 9 } };
const RSS = `<?xml version="1.0"?><rss version="2.0"><channel><title>Open Source Security</title>
<item><title>CVE-2026-2222: heap overflow in curl's HTTP/3 handling</title><link>https://seclists.org/oss-sec/2026/q4/900</link><pubDate>${new Date(now - 0.5 * DAY).toUTCString()}</pubDate><description>x</description></item>
<item><title>Re: CVE-2026-2222: heap overflow in curl's HTTP/3 handling</title><link>https://seclists.org/oss-sec/2026/q4/901</link><pubDate>${new Date(now - 0.4 * DAY).toUTCString()}</pubDate></item>
<item><title>json parsing note in a small tool</title><link>https://seclists.org/oss-sec/2026/q4/902</link><pubDate>${new Date(now - 0.3 * DAY).toUTCString()}</pubDate></item>
</channel></rss>`;
const h1 = (id, handle, title, d, cwe, cves = []) => ({ id, type: 'hacktivity_item', attributes: { title, substate: 'resolved', url: `https://hackerone.com/reports/${id}`, disclosed_at: at(d),
  cve_ids: cves, cwe, severity_rating: 'High', votes: 3, total_awarded_amount: 500, latest_disclosable_action: 'Activities::ReportBecamePublic', latest_disclosable_activity_at: at(d), submitted_at: at(d + 30), disclosed: true },
  relationships: { report_generated_content: { data: { attributes: { hacktivity_summary: 'SUMMARY TEXT MUST NOT BE KEPT' } } }, program: { data: { attributes: { handle, name: handle } } } } });
const H1 = [h1(9001, 'curl', 'UAF in cw-pause', 0.2, 'Use After Free', ['CVE-2026-3333']), h1(9002, 'shopify', 'Stored XSS in admin', 0.6, 'Cross-site Scripting (XSS) - Stored'),
  h1(9003, 'wordpress', 'Core comment bypass', 1, 'Improper Access Control - Generic'), h1(9004, 'shopify', 'Old one', 45, 'Open Redirect')];
const cveRec = (id, pub, { cvss = true, cwe = true, versions = true } = {}) => ({ cveMetadata: { cveId: id, state: 'PUBLISHED', datePublished: pub },
  containers: { cna: { metrics: cvss ? [{ cvssV3_1: { baseScore: 7.5 } }] : [], problemTypes: cwe ? [{ descriptions: [{ cweId: 'CWE-416' }] }] : [],
    affected: [{ vendor: 'x', product: 'y', versions: versions ? [{ version: '1.0', status: 'affected' }] : [] }] } } });
let CVE = { 'CVE-2026-1111': cveRec('CVE-2026-1111', at(2)), 'CVE-2026-3333': cveRec('CVE-2026-3333', at(0.1), { cwe: false, cvss: false }), 'CVE-2026-4444': cveRec('CVE-2026-4444', at(3)) };
const CVEID = { 'CVE-2026-2222': { cve_id: 'CVE-2026-2222', state: 'RESERVED', owning_cna: '[REDACTED]' } };

const bucket = new Map(), calls = [];
const resp = (status, body, headers = {}) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
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
  calls.push({ u, h });
  if (u === 'https://api.github.com/repos/google/oss-fuzz/git/trees/master') return resp(200, { tree: [{ path: 'projects', type: 'tree', sha: 'abc123' }, { path: 'README.md', type: 'blob' }] });
  if (u === 'https://api.github.com/repos/google/oss-fuzz/git/trees/abc123') return resp(200, { tree: FUZZ.map((p) => ({ path: p, type: 'tree' })), truncated: false });
  let m = u.match(/^https:\/\/osv-vulnerabilities\.storage\.googleapis\.com\/([^/]+)\/modified_id\.csv$/);
  if (m) { const eco = decodeURIComponent(m[1]); return OSV[eco] ? resp(206, csv(eco)) : resp(404, '<Error>NoSuchKey</Error>'); }
  m = u.match(/^https:\/\/osv-vulnerabilities\.storage\.googleapis\.com\/([^/]+)\/(.+)\.json$/);
  if (m) { const id = decodeURIComponent(m[2]); return REC[id] ? resp(200, REC[id]) : resp(404, 'no'); }
  m = u.match(/^https:\/\/packages\.ecosyste\.ms\/api\/v1\/registries\/([^/]+)\/packages\/(.+)$/);
  if (m) { const k = decodeURIComponent(m[1]) + '/' + decodeURIComponent(m[2]); return REACH[k] ? resp(200, REACH[k]) : resp(404, { error: 'not found' }); }
  if (u === 'https://seclists.org/rss/oss-sec.rss') return resp(200, RSS);
  if (u.startsWith('https://api.hackerone.com/v1/hackers/hacktivity?')) {
    const page = Number(new URL(u).searchParams.get('page[number]'));
    // Page 1 says another page follows; page 2 is short and has no next link, so paging stops there.
    return resp(200, page === 1 ? { data: H1.slice(0, 2), links: { next: u.replace('page%5Bnumber%5D=1', 'page%5Bnumber%5D=2') } } : page === 2 ? { data: H1.slice(2), links: {} } : { data: [], links: {} });
  }
  m = u.match(/^https:\/\/api\.hackerone\.com\/v1\/hackers\/programs\/([^/]+)\/weaknesses/);
  if (m) return h.authorization ? resp(200, { data: [{ id: '1', type: 'weakness', attributes: { name: 'Use After Free', external_id: 'cwe-416' } }, { id: '2', type: 'weakness', attributes: { name: 'Core Bypass Thing', external_id: 'cwe-863' } }] }) : resp(401, { errors: [] });
  m = u.match(/^https:\/\/cveawg\.mitre\.org\/api\/cve\/(CVE-[\d-]+)$/);
  if (m) return CVE[m[1]] ? resp(200, CVE[m[1]]) : resp(404, { error: 'CVE_RECORD_DNE' });
  m = u.match(/^https:\/\/cveawg\.mitre\.org\/api\/cve-id\/(CVE-[\d-]+)$/);
  if (m) return CVEID[m[1]] ? resp(200, CVEID[m[1]]) : resp(404, { error: 'CVE_ID_NOT_FOUND' });
  throw new Error('unexpected network request ' + u);
};
const M = await import(path.join(ROOT, 'neon', 'collector.mjs'));
const doc = () => JSON.parse(zlib.gunzipSync(bucket.get('ti-docs/docs/osswatch.json.gz')).toString());
const q = async (s, p = []) => (await db.query(s, p)).rows;

// ---------------------------------------------------------------- pure pieces
{
  const list = M.parseModified('2026-11-22T03:00:00.5Z,GHSA-x\n2026-11-21T00:00:00Z,MAL-2026-1\n2026-11-20T00:00:00Z,GHSA-y\n2026-10-01T00:00:00Z,GHSA-z\n2026-09-01T00:00:00Z,GHSA-c', '2026-10-15T00:00:00Z');
  ok(list.map((x) => x.id).join() === 'GHSA-x,GHSA-y', 'modified_id.csv: newest first, MAL- skipped, stops at the window, drops the cut last line ' + JSON.stringify(list));
  ok(M.osvRow({ id: 'GHSA-1', withdrawn: '2026-01-01T00:00:00Z' }, 'npm') === null, 'a withdrawn record is dropped');
  const r = M.osvRow(REC['GHSA-aaaa-aaaa-aaaa'], 'npm');
  ok(r.aliases.join() === 'CVE-2026-1111' && r.project === 'left-pad' && r.extra.packages === 2 && r.link === 'https://github.com/advisories/GHSA-aaaa-aaaa-aaaa', 'OSV row ' + JSON.stringify(r));
  ok(M.osvLink('OSV-2026-1001') === 'https://osv.dev/vulnerability/OSV-2026-1001', 'non-GHSA records link to osv.dev');
  const posts = M.parseOssSec(RSS);
  ok(posts.length === 2 && posts[0].aliases.join() === 'CVE-2026-2222' && posts[0].id === 'oss-sec:2026/q4/900', 'oss-security: root posts only, CVE from the title');
  const names = new Set(FUZZ);
  ok(M.ossFuzzMatch("heap overflow in curl's HTTP/3", names) === 'curl' && M.ossFuzzMatch('json parsing note', names) === null && M.ossFuzzMatch('Git 2.47 fixes', names) === 'git',
    'OSS-Fuzz names: whole words, common words skipped, listed short names kept');
  const hr = M.h1Row(H1[0], M.H1_CWE);
  ok(hr.cwes.join() === 'CWE-416' && hr.oss === true && hr.aliases.join() === 'CVE-2026-3333' && !JSON.stringify(hr).includes('SUMMARY'), 'Hacktivity row keeps no summary text, maps the weakness');
  ok(M.h1Row(H1[1], M.H1_CWE).oss === false && M.isH1Oss('ibb-php') && M.isH1Oss('wordpress') && !M.isH1Oss('shopify'), 'open-source programs');
  ok(M.reachOf({ ok: true, critical: true }).reach === 'wide' && M.reachOf({ ok: true, critical: false, rank: 0.4 }).reach === 'wide' && M.reachOf({ ok: true, rank: 3 }).reach === 'limited'
    && M.reachOf({ ok: false }).reach === 'unmeasured', 'reach rules: critical, top 1%, limited, not found');
  ok(M.cveState(cveRec('CVE-1', at(1))).state === 'complete' && M.cveState(cveRec('CVE-1', at(1), { cwe: false })).gaps.join() === 'CWE'
    && M.cveState(null, { state: 'RESERVED' }).state === 'reserved' && M.cveState(null, null).state === 'unknown', 'CVE states');
  ok(M.aheadOf({ cve_state: 'none' }) && M.aheadOf({ cve_state: 'complete', published: at(5), cve_published: at(2) }) && !M.aheadOf({ cve_state: 'complete', published: at(2), cve_published: at(2.5) }),
    'ahead: no record, or a record published a day or more later');
}

// ---------------------------------------------------------------- first run, anonymous Hacktivity
const r1 = await M.runJob('osswatch');
ok(r1.ok, 'first run ' + JSON.stringify(r1).slice(0, 600));
const d1 = doc();
const dis = d1.rows.filter((r) => r.kind === 'disclosure');
const by = Object.fromEntries(dis.map((r) => [r.id, r]));
ok(!by['MAL-2026-90001'] && !by['GHSA-old0-old0-old0'] && !by['PYSEC-2026-77'], 'malicious-package ids, rows past the window and old advisories modified today are not listed');
ok(dis.filter((r) => r.id === 'GHSA-aaaa-aaaa-aaaa').length === 1, 'an advisory in two ecosystems is one row');
ok(!by['GHSA-cccc-cccc-cccc'], 'a package with limited reach is not listed');
ok(by['GHSA-aaaa-aaaa-aaaa'].reach === 'wide' && /critical/.test(by['GHSA-aaaa-aaaa-aaaa'].reach_note), 'critical package is widely deployed');
const a = by['GHSA-aaaa-aaaa-aaaa'];
ok(a.cve_state === 'complete' && a.lead_days === 3 && a.ahead === true, `advisory ahead of a complete record published three days later ${JSON.stringify(a)}`);
const b = by['GHSA-bbbb-bbbb-bbbb'];
ok(b.cve_state === 'none' && b.ahead === true && b.cve_label === 'No CVE id', 'no CVE id');
const f = by['OSV-2026-1001'];
ok(f.reach === 'wide' && f.reach_note === 'OSS-Fuzz project' && f.project === 'libxml2' && f.cve_state === 'none', 'OSS-Fuzz report');
const o = by['oss-sec:2026/q4/900'];
ok(o && o.reach === 'wide' && o.project === 'curl' && o.cve_state === 'reserved' && o.ahead === true, `oss-security post for an OSS-Fuzz project with a reserved id ${JSON.stringify(o)}`);
ok(by['oss-sec:2026/q4/902'] && by['oss-sec:2026/q4/902'].reach === 'unmeasured' && by['oss-sec:2026/q4/902'].ahead === null && by['oss-sec:2026/q4/902'].cve_label === 'No CVE id in the post title',
  'a post naming no OSS-Fuzz project is listed as unmeasured, and a title without a CVE id is not judged');
ok(M.ecoName('Packagist:https://packages.drupal.org/8') === 'Packagist (packages.drupal.org)' && M.ecoName('npm') === 'npm', 'ecosystem names with a registry suffix');
ok(calls.filter((c) => c.u.startsWith('https://api.hackerone.com/v1/hackers/hacktivity')).length === 2, 'Hacktivity paging follows the next link and stops at the window');
const c1 = by['h1:9001'];
ok(c1 && c1.reach === 'wide' && c1.cve_state === 'incomplete' && c1.cve_gaps.join() === 'CVSS,CWE' && c1.ahead === true && c1.program === 'curl', `Hacktivity report with an incomplete record ${JSON.stringify(c1)}`);
ok(by['h1:9003'] && by['h1:9003'].reach === 'unmeasured' && /open-source program/.test(by['h1:9003'].reach_note), 'WordPress on HackerOne: open-source program, reach not measured');
ok(!by['h1:9002'] && !by['h1:9004'], 'reports to other programs are not disclosures in the watch');
const wk = d1.rows.filter((r) => r.kind === 'weakness');
ok(wk.length === 3 && wk.find((w) => w.cwe === 'CWE-79').reports === 1 && wk.find((w) => w.cwe === 'CWE-79').oss_reports === 0 && wk.find((w) => w.cwe === 'CWE-416').oss_reports === 1,
  'weakness counts over every program in the window ' + JSON.stringify(wk));
const src = Object.fromEntries(d1.rows.filter((r) => r.kind === 'source').map((s) => [s.id, s]));
ok(src['osv:npm'].ok && src['osv:Go'].ok === false && src.hacktivity.auth === 'anonymous' && src.hacktivity.cwe_map === 'built-in table' && src.ossfuzz.items === FUZZ.length, 'source status rows');
ok(d1.hacktivity_auth === 'anonymous' && d1.wide >= 5 && d1.by_state.none >= 2 && d1.median_lead_days === 3 && d1.lead_n === 1 && d1.same_day === 1 && d1.cve_first === 0 && d1.with_record === 2, 'document summary ' + JSON.stringify({ wide: d1.wide, by: d1.by_state, med: d1.median_lead_days }));
ok(!JSON.stringify(d1).includes('SUMMARY TEXT'), 'no report text in the document');
ok((await q(`SELECT count(*)::int AS n FROM ti.osw_seen`))[0].n === 5, 'the five OSV records read are marked seen (the cut-off line is never read)');
ok((await q(`SELECT count(*)::int AS n FROM ti.pkg_reach`))[0].n === 2, 'package usage cached for the two packages in the window (left-pad, tinylib)');
const osvFetches1 = calls.filter((c) => /googleapis\.com\/[^/]+\/[^/]+\.json$/.test(c.u)).length;

// ---------------------------------------------------------------- second run with a token; recheck completes a record
process.env.HACKERONE_API_USERNAME = 'kti-test'; process.env.HACKERONE_API_TOKEN = 'token-for-test';
CVE['CVE-2026-3333'] = cveRec('CVE-2026-3333', at(0.1));
const before = calls.length;
const r2 = await M.runJob('osswatch', { oswLimits: { CVE_RECHECK_H: 0 } });
ok(r2.ok, 'second run ' + JSON.stringify(r2).slice(0, 400));
const later = calls.slice(before);
ok(later.filter((c) => /googleapis\.com\/[^/]+\/[^/]+\.json$/.test(c.u)).length === 0 && osvFetches1 === 5, 'OSV records already read at this modification time are not fetched again');
ok(later.filter((c) => c.u.startsWith('https://api.hackerone.com/')).every((c) => c.h.authorization === 'Basic ' + Buffer.from('kti-test:token-for-test').toString('base64')), 'HackerOne requests carry Basic auth with the token');
ok(later.some((c) => /programs\/security\/weaknesses/.test(c.u)), 'the weakness list is read with the token');
ok(!later.some((c) => c.u.endsWith('/api/cve/CVE-2026-1111')), 'a complete CVE record is not checked again');
const d2 = doc();
const c2 = d2.rows.find((r) => r.id === 'h1:9001');
ok(c2.cve_state === 'complete' && c2.cve_complete_seen && d2.hacktivity_auth === 'API token' && d2.cwe_map === 'api', 'recheck completes the record; the document names the token and the API weakness list');
ok(!later.some((c) => c.u.includes('oss-fuzz/git/trees')), 'the OSS-Fuzz list is read once a day');
const kvm = (await q(`SELECT v FROM ti.kv WHERE k = 'osw:h1cwe'`))[0];
ok(kvm && kvm.v.map['core bypass thing'] === 'CWE-863', 'weakness names from the API are cached');
ok(M.plan(new Date('2026-11-22T02:04:00Z')).includes('osswatch') && !M.plan(new Date('2026-11-22T02:19:00Z')).includes('osswatch') && !M.plan(new Date('2026-11-22T03:04:00Z')).includes('osswatch'),
  'scheduled every third hour at :04');
console.log(`PASS ${pass} checks (open-source disclosure watch)`);
