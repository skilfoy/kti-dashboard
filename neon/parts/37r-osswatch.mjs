// ---------------------------------------------------------------- open-source disclosure watch (3.14.0)
// Flaws in widely deployed open-source projects, read where they are first published, and set against the CVE record:
//   OSV.dev        the bulk export of each ecosystem (GitHub-reviewed advisories, PyPA, RustSec, Go, OSS-Fuzz and
//                  others; CC BY 4.0 with each source's own terms), read from the head of its modified_id.csv
//   oss-security   the Openwall list's posts as seclists.org syndicates them (titles and links only)
//   Hacktivity     HackerOne's disclosed reports (titles, links, dates, CWE, severity, CVE ids; never report text or the
//                  AI summary), with HACKERONE_API_USERNAME and HACKERONE_API_TOKEN when set, anonymously otherwise
// Reach: a package counts as widely deployed when ecosyste.ms marks it critical or ranks it in the top 1% of its
// registry by usage (ecosyste.ms open data, CC BY-SA 4.0; one cached lookup per package a week); a project counts when
// it is integrated in Google's OSS-Fuzz (google/oss-fuzz projects/, read daily). CVE record: CVE Services
// (cveawg.mitre.org) answers whether the CVE id exists, is reserved with no record, or has a record, and whether that
// record carries CVSS, a CWE and affected versions; a record not yet complete is checked again every run. Lead: days
// from the disclosure to the CVE record's publication.
export const OSW = {
  WINDOW_DAYS: 30, KEEP_DAYS: 45, SEEN_DAYS: 60, MAX_ROWS: 1500, BUDGET_MS: 170000,
  OSV_BASE: 'https://osv-vulnerabilities.storage.googleapis.com',
  ECOSYSTEMS: ['npm', 'PyPI', 'Maven', 'Go', 'crates.io', 'NuGet', 'RubyGems', 'Packagist', 'Hex', 'Pub', 'GitHub Actions', 'OSS-Fuzz', 'Hackage', 'CRAN', 'SwiftURL'],
  HEAD_BYTES: 524287, OSV_MAX: 900, CONCURRENCY: 8,
  REACH_URL: 'https://packages.ecosyste.ms/api/v1/registries/', REACH_TTL_DAYS: 7, REACH_MAX: 250, RANK_MAX: 1.0,
  OSSFUZZ_TREE: 'https://api.github.com/repos/google/oss-fuzz/git/trees/master', OSSFUZZ_TTL_H: 24,
  CVE_URL: 'https://cveawg.mitre.org/api/cve/', CVEID_URL: 'https://cveawg.mitre.org/api/cve-id/', CVE_MAX: 250, CVE_RECHECK_H: 6,
  OSSSEC_RSS: 'https://seclists.org/rss/oss-sec.rss',
  H1_URL: 'https://api.hackerone.com/v1/hackers/hacktivity', H1_PAGES_FIRST: 8, H1_PAGES: 3, H1_PAGE: 100,
  H1_WEAKNESS_URL: 'https://api.hackerone.com/v1/hackers/programs/', H1_WEAKNESS_PROGRAMS: ['security', 'ibb'], H1_WEAKNESS_TTL_DAYS: 7,
};
// ecosyste.ms registry for each OSV ecosystem it indexes.
export const OSW_REGISTRY = { npm: 'npmjs.org', PyPI: 'pypi.org', Maven: 'repo1.maven.org', Go: 'proxy.golang.org', 'crates.io': 'crates.io', NuGet: 'nuget.org',
  RubyGems: 'rubygems.org', Packagist: 'packagist.org', Hex: 'hex.pm', Pub: 'pub.dev', 'GitHub Actions': 'github actions', Hackage: 'hackage.haskell.org', CRAN: 'cran.r-project.org' };
// HackerOne programs run by open-source projects (handles as HackerOne lists them; "ibb" and every "ibb-" handle is the
// Internet Bug Bounty, which pays for flaws in shared open-source software). A program here is in the watch; its reach is
// measured by OSS-Fuzz membership like any other project.
export const H1_OSS = { ibb: 'Internet Bug Bounty', curl: 'curl', nodejs: 'Node.js', ruby: 'Ruby', rails: 'Ruby on Rails', rubygems: 'RubyGems', kubernetes: 'Kubernetes',
  nextcloud: 'Nextcloud', wordpress: 'WordPress', revive_adserver: 'Revive Adserver', phpbb: 'phpBB', concretecms: 'Concrete CMS', owncloud: 'ownCloud', gitlab: 'GitLab',
  envoy: 'Envoy', istio: 'Istio', jitsi: 'Jitsi', 'mattermost': 'Mattermost', 'grafana': 'Grafana', 'ruby-lang': 'Ruby', 'python': 'Python', 'django': 'Django', 'openssl': 'OpenSSL' };
export const isH1Oss = (handle) => { const h = String(handle || '').toLowerCase(); return h === 'ibb' || h.startsWith('ibb-') || Object.prototype.hasOwnProperty.call(H1_OSS, h); };
// HackerOne weakness names to CWE identifiers, used until the weakness list read with an API token replaces it.
export const H1_CWE = {
  'cross-site scripting (xss) - stored': 'CWE-79', 'cross-site scripting (xss) - reflected': 'CWE-79', 'cross-site scripting (xss) - dom': 'CWE-79', 'cross-site scripting (xss) - generic': 'CWE-79',
  'sql injection': 'CWE-89', 'server-side request forgery (ssrf)': 'CWE-918', 'insecure direct object reference (idor)': 'CWE-639', 'improper access control - generic': 'CWE-284',
  'information disclosure': 'CWE-200', 'cross-site request forgery (csrf)': 'CWE-352', 'open redirect': 'CWE-601', 'code injection': 'CWE-94', 'command injection - generic': 'CWE-77',
  'os command injection': 'CWE-78', 'path traversal': 'CWE-22', 'improper authentication - generic': 'CWE-287', 'business logic errors': 'CWE-840', 'privilege escalation': 'CWE-269',
  'denial of service': 'CWE-400', 'uncontrolled resource consumption': 'CWE-400', 'use after free': 'CWE-416', 'heap overflow': 'CWE-122', 'stack overflow': 'CWE-121',
  'buffer over-read': 'CWE-126', 'classic buffer overflow': 'CWE-120', 'out-of-bounds read': 'CWE-125', 'out-of-bounds write': 'CWE-787', 'integer overflow': 'CWE-190',
  'integer underflow': 'CWE-191', 'null pointer dereference': 'CWE-476', 'double free': 'CWE-415', 'memory corruption - generic': 'CWE-119', 'race condition': 'CWE-362',
  'time-of-check time-of-use (toctou) race condition': 'CWE-367', 'missing critical step in authentication': 'CWE-304', 'improper certificate validation': 'CWE-295',
  'cleartext transmission of sensitive information': 'CWE-319', 'use of hard-coded credentials': 'CWE-798', 'insecure storage of sensitive information': 'CWE-922',
  'xml external entities (xxe)': 'CWE-611', 'deserialization of untrusted data': 'CWE-502', 'unrestricted upload of file with dangerous type': 'CWE-434',
  'http request smuggling': 'CWE-444', 'http response splitting': 'CWE-113', 'crlf injection': 'CWE-93', 'ui redressing (clickjacking)': 'CWE-1021',
  'violation of secure design principles': 'CWE-657', 'insufficient session expiration': 'CWE-613', 'session fixation': 'CWE-384', 'improper input validation': 'CWE-20',
  'reliance on untrusted inputs in a security decision': 'CWE-807', 'cryptographic issues - generic': 'CWE-310', 'insufficiently protected credentials': 'CWE-522',
  'ldap injection': 'CWE-90', 'xpath injection': 'CWE-643', 'resource injection': 'CWE-99', 'improper restriction of authentication attempts': 'CWE-307',
  'weak password recovery mechanism for forgotten password': 'CWE-640', 'authentication bypass using an alternate path or channel': 'CWE-288', 'incorrect authorization': 'CWE-863',
  'missing authorization': 'CWE-862', 'improper privilege management': 'CWE-269', 'embedded malicious code': 'CWE-506', 'uncontrolled search path element': 'CWE-427',
  'allocation of resources without limits or throttling': 'CWE-770', 'inadequate encryption strength': 'CWE-326', 'use of a broken or risky cryptographic algorithm': 'CWE-327',
  'information exposure through debug information': 'CWE-215', 'information exposure through an error message': 'CWE-209', 'information exposure through directory listing': 'CWE-548',
  'missing encryption of sensitive data': 'CWE-311', 'externally controlled reference to a resource in another sphere': 'CWE-610', 'insecure temporary file': 'CWE-377',
  'plaintext storage of a password': 'CWE-256', 'execution with unnecessary privileges': 'CWE-250', 'incorrect default permissions': 'CWE-276', 'off-by-one error': 'CWE-193',
  'type confusion': 'CWE-843', 'uncontrolled recursion': 'CWE-674', 'use of externally-controlled format string': 'CWE-134', 'server-side template injection': 'CWE-1336',
  'prototype pollution': 'CWE-1321', 'improper neutralization of special elements used in a template engine': 'CWE-1336', 'brute force': 'CWE-307',
};
const OSW_CVE = /^CVE-\d{4}-\d{4,7}$/;
const iso = (t) => { const d = new Date(t); return isNaN(d) ? null : d.toISOString(); };
const daysBetween = (a, b) => (a && b ? Math.round(((Date.parse(b) - Date.parse(a)) / 86400000) * 10) / 10 : null);

// ---------------------------------------------------------------- pure pieces (exported for the tests)
// modified_id.csv: "timestamp,id" lines, newest first; the cut last line of a ranged read is dropped.
export function parseModified(text, sinceIso) {
  const out = [];
  const lines = String(text || '').split('\n');
  if (lines.length > 1 && !String(text).endsWith('\n')) lines.pop();
  for (const line of lines) {
    const i = line.indexOf(',');
    if (i < 0) continue;
    const ts = line.slice(0, i).trim(), id = line.slice(i + 1).trim();
    if (!ts || !id) continue;
    if (sinceIso && ts < sinceIso) break;
    if (/^MAL-/.test(id)) continue; // malicious-package reports: not a flaw in a project
    out.push({ ts, id });
  }
  return out;
}
export function osvLink(id) { return /^GHSA-/.test(id) ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${encodeURIComponent(id)}`; }
// OSV names some registries with a suffix ("Packagist:https://packages.drupal.org/8"); shown as "Packagist (packages.drupal.org)",
// and no usage lookup is made for it (ecosyste.ms indexes the main registry only).
export function ecoName(e) {
  const s = String(e || ''), i = s.indexOf(':');
  if (i < 0) return s || null;
  let host = s.slice(i + 1);
  try { host = new URL(host).host || host; } catch { /* not a URL: kept */ }
  return `${s.slice(0, i)} (${host})`;
}
export function osvRow(rec, eco) {
  if (!rec || !rec.id || rec.withdrawn) return null;
  const aff = (rec.affected || []).map((a) => a && a.package).filter(Boolean);
  const pkgs = [...new Set(aff.map((p) => p.name).filter(Boolean))];
  const ds = rec.database_specific || {};
  const cves = [...new Set([rec.id, ...(rec.aliases || [])].filter((x) => OSW_CVE.test(x)))];
  const title = String(rec.summary || (rec.details || '').split('\n')[0] || rec.id).replace(/\s+/g, ' ').trim().slice(0, 240);
  return {
    id: rec.id, src: 'osv', ecosystem: ecoName((aff[0] && aff[0].ecosystem) || eco), project: pkgs[0] || null, title, link: osvLink(rec.id),
    published: iso(rec.published), modified: iso(rec.modified), aliases: cves, cwes: (ds.cwe_ids || []).filter((c) => /^CWE-\d+$/.test(c)).slice(0, 6),
    severity: ds.severity ? String(ds.severity).toUpperCase() : null, oss: true,
    extra: { packages: pkgs.length, reviewed: ds.github_reviewed ?? null, nvd_published_at: ds.nvd_published_at || null },
  };
}
// oss-security root posts (replies are follow-ups to an earlier disclosure). Titles and links only.
export function parseOssSec(xml) {
  const items = parseAdvisories(xml);
  if (!items) return null;
  return items.filter((i) => !/^\s*(re|fwd?)\s*:/i.test(i.title)).map((i) => {
    const m = i.link.match(/oss-sec\/(\d{4})\/(q\d)\/(\d+)/);
    return { id: 'oss-sec:' + (m ? `${m[1]}/${m[2]}/${m[3]}` : i.link), src: 'oss-security', ecosystem: null, project: null, title: i.title.slice(0, 240), link: i.link,
      published: i.published, modified: i.published, aliases: cvesIn(i.title).slice(0, 12), cwes: [], severity: null, oss: true, extra: {} };
  });
}
// An OSS-Fuzz project named in a title: whole words of three characters or more, longest first, outside a short list of
// project names that are also common words in post titles.
// Project names that are also ordinary words in post titles are not matched; short names are matched only when listed.
const OSSFUZZ_STOP = new Set(['json', 'yaml', 'xml', 'http', 'image', 'file', 'time', 'regex', 'test', 'core', 'go', 'net', 'zip', 'tar', 'pip', 'six', 'rich', 'click', 'attrs', 'arrow',
  'markdown', 'requests', 'spring', 'jackson', 'r', 'qs', 'lit', 'nom', 'oak', 'ply', 'wt', 'xs', 'ron', 'stb', 'swc', 'ryu', 'smt', 'avm', 'ots', 'dpp', 'bs4', 'd3', 'h2', 'h3', 'h11',
  'p9', 'ja3', 'jc', 'jq', 'jsc', 'jts', 'mxj', 'ohc', 'lzo', 'lz4', 'hcl', 'gwt', 'fio', 'fmt', 'pcl', 'rnp', 'h2o', 'pem', 'kea', 'njs', 'zxc', 'adal', 'angus-mail', 'anise']);
const OSSFUZZ_SHORT = new Set(['xz', 'git', 'php', 'tor', 'xen', 'v8', 'vlc', 'ntp', 'lua', 'qt', 'icu', 'nss', 'frr', 'lxc', 'mpv', 'upx', 'w3m', 'znc', 'zip']);
export function ossFuzzMatch(title, names) {
  const words = new Set(String(title || '').toLowerCase().match(/[a-z0-9][a-z0-9+_.-]*[a-z0-9+]|[a-z0-9]/g) || []);
  let best = null;
  for (const n of names) {
    if (!words.has(n) || OSSFUZZ_STOP.has(n)) continue;
    if (n.length <= 3 && !OSSFUZZ_SHORT.has(n)) continue;
    if (!best || n.length > best.length) best = n;
  }
  return best;
}
export function h1Row(item, cweMap) {
  const a = (item && item.attributes) || {};
  const p = ((((item || {}).relationships || {}).program || {}).data || {}).attributes || {};
  if (!item || !item.id || !a.disclosed) return null;
  const cweName = a.cwe ? String(a.cwe) : null;
  const cwe = cweName ? (cweMap[cweName.toLowerCase()] || null) : null;
  return { id: 'h1:' + item.id, src: 'hacktivity', ecosystem: 'HackerOne', project: p.handle || null, title: String(a.title || '').slice(0, 240), link: a.url || `https://hackerone.com/reports/${item.id}`,
    published: iso(a.disclosed_at), modified: iso(a.latest_disclosable_activity_at || a.disclosed_at), aliases: (a.cve_ids || []).filter((c) => OSW_CVE.test(c)).slice(0, 12),
    cwes: cwe ? [cwe] : [], severity: a.severity_rating ? String(a.severity_rating).toUpperCase() : null, oss: isH1Oss(p.handle),
    extra: { program: p.name || p.handle || null, weakness: cweName, bounty: a.total_awarded_amount ?? null, submitted_at: iso(a.submitted_at), votes: a.votes ?? null } };
}
// Reach of one package from its ecosyste.ms record.
export function reachOf(rec, rankMax = OSW.RANK_MAX) {
  if (!rec || !rec.ok) return { reach: 'unmeasured', note: 'not found in ecosyste.ms' };
  const rank = rec.rank == null ? null : Number(rec.rank);
  const fmt = (n) => (n == null ? null : Number(n).toLocaleString('en-US'));
  const usage = [rec.dependents != null ? `${fmt(rec.dependents)} dependent packages` : null, rec.dependent_repos != null ? `${fmt(rec.dependent_repos)} dependent repositories` : null].filter(Boolean).join(', ');
  if (rec.critical) return { reach: 'wide', note: `ecosyste.ms critical package${usage ? '; ' + usage : ''}` };
  if (rank != null && rank <= rankMax) return { reach: 'wide', note: `top ${Math.max(0.01, Math.round(rank * 100) / 100)}% of its registry by usage (ecosyste.ms)${usage ? '; ' + usage : ''}` };
  return { reach: 'limited', note: rank != null ? `ranked in the top ${Math.round(rank * 100) / 100}% by usage (ecosyste.ms)${usage ? '; ' + usage : ''}` : (usage || 'no usage ranking') };
}
// What CVE Services says of one CVE id: the record's state, publication date and the fields it still lacks.
export function cveState(rec, idRec) {
  if (rec && rec.cveMetadata) {
    const st = rec.cveMetadata.state;
    if (st === 'REJECTED') return { state: 'rejected', published: iso(rec.cveMetadata.datePublished), gaps: [] };
    const cont = rec.containers || {}, srcs = [cont.cna || {}, ...(cont.adp || [])];
    const hasCvss = srcs.some((s) => (s.metrics || []).some((m) => Object.keys(m || {}).some((k) => /^cvssV/.test(k))));
    const hasCwe = srcs.some((s) => (s.problemTypes || []).some((p) => (p.descriptions || []).some((d) => /^CWE-\d+$/i.test(String(d.cweId || '')))));
    const hasVer = (cont.cna && (cont.cna.affected || []).some((a) => (a.versions || []).length || (a.cpes || []).length)) || srcs.some((s) => (s.affected || []).some((a) => (a.versions || []).length));
    const gaps = [hasCvss ? null : 'CVSS', hasCwe ? null : 'CWE', hasVer ? null : 'affected versions'].filter(Boolean);
    return { state: gaps.length ? 'incomplete' : 'complete', published: iso(rec.cveMetadata.datePublished), gaps };
  }
  if (idRec && idRec.state === 'RESERVED') return { state: 'reserved', published: null, gaps: [] };
  if (idRec && idRec.state === 'REJECTED') return { state: 'rejected', published: null, gaps: [] };
  return { state: 'unknown', published: null, gaps: [] };
}
export const OSW_STATE_LABEL = { none: 'No CVE id', reserved: 'CVE id reserved, no record', incomplete: 'CVE record incomplete', complete: 'CVE record complete', rejected: 'CVE id rejected', unknown: 'CVE id not found' };
// A disclosure is ahead of the CVE record while it has no complete record, or when its record was published later.
export function aheadOf(r) {
  const st = r.cve_state || 'none';
  if (st === 'none' || st === 'reserved' || st === 'unknown') return true;
  if (st === 'rejected') return false;
  const lead = daysBetween(r.published, r.cve_published);
  return st === 'incomplete' || (lead != null && lead >= 1);
}

// ---------------------------------------------------------------- the job
async function oswOssFuzz(deadline) {
  const kv = (await kvGet('osw:ossfuzz')) || null;
  if (kv && kv.names && kv.names.length && Date.now() - Date.parse(kv.at) < OSW.OSSFUZZ_TTL_H * 3600000) return { names: kv.names, note: null, at: kv.at };
  const hdr = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' };
  if (ENV().GITHUB_TOKEN) hdr.authorization = 'Bearer ' + ENV().GITHUB_TOKEN;
  const left = () => Math.max(1000, Math.min(15000, deadline - Date.now()));
  const top = await get(OSW.OSSFUZZ_TREE, { as: 'json', timeout: left(), headers: hdr });
  const sha = top.ok && top.json && (top.json.tree || []).find((t) => t.path === 'projects' && t.type === 'tree');
  const sub = sha ? await get(`${OSW.OSSFUZZ_TREE.replace(/\/master$/, '')}/${sha.sha}`, { as: 'json', timeout: left(), headers: hdr }) : null;
  const names = sub && sub.ok && sub.json ? (sub.json.tree || []).filter((t) => t.type === 'tree').map((t) => String(t.path).toLowerCase()) : [];
  if (names.length > 500) { const v = { at: new Date().toISOString(), names }; await kvPut('osw:ossfuzz', v); return { names, note: null, at: v.at }; }
  const why = 'OSS-Fuzz project list not read this run: ' + ((sub && (sub.error || `HTTP ${sub.status}`)) || (top.error || `HTTP ${top.status}`));
  return { names: (kv && kv.names) || [], note: why, at: kv ? kv.at : null };
}
async function oswH1CweMap(h1Headers, deadline) {
  const kv = await kvGet('osw:h1cwe');
  if (kv && kv.map && Date.now() - Date.parse(kv.at) < OSW.H1_WEAKNESS_TTL_DAYS * 86400000) return { map: { ...H1_CWE, ...kv.map }, from: 'api' };
  if (!h1Headers.authorization) return { map: { ...H1_CWE, ...((kv && kv.map) || {}) }, from: kv ? 'api (cached)' : 'built-in table' };
  const map = {};
  for (const prog of OSW.H1_WEAKNESS_PROGRAMS) {
    for (let page = 1; page <= 4 && deadline - Date.now() > 5000; page++) {
      const r = await get(`${OSW.H1_WEAKNESS_URL}${prog}/weaknesses?page%5Bsize%5D=100&page%5Bnumber%5D=${page}`, { as: 'json', timeout: 12000, headers: h1Headers });
      const data = (r.ok && r.json && r.json.data) || [];
      for (const w of data) {
        const a = w.attributes || {}, ext = String(a.external_id || '').toLowerCase().match(/^cwe-(\d+)$/);
        if (a.name && ext) map[String(a.name).toLowerCase()] = 'CWE-' + ext[1];
      }
      if (data.length < 100) break;
    }
  }
  if (Object.keys(map).length) await kvPut('osw:h1cwe', { at: new Date().toISOString(), map });
  return { map: { ...H1_CWE, ...((kv && kv.map) || {}), ...map }, from: Object.keys(map).length ? 'api' : 'built-in table' };
}
export async function jobOsswatch(opts = {}) {
  const t0 = Date.now(), L = { ...OSW, ...(opts.oswLimits || {}) }, deadline = t0 + L.BUDGET_MS;
  const since = new Date(Date.now() - L.WINDOW_DAYS * 86400000).toISOString();
  const sources = [];
  const rows = [];
  // OSS-Fuzz projects.
  const fuzz = await oswOssFuzz(deadline);
  const fuzzSet = new Set(fuzz.names);
  sources.push({ kind: 'source', id: 'ossfuzz', name: 'OSS-Fuzz projects (google/oss-fuzz)', ok: fuzz.names.length > 0, items: fuzz.names.length, note: fuzz.note, at: fuzz.at });
  // OSV: the head of each ecosystem's modified_id.csv, then the records not seen at this modification time.
  const heads = await pool(L.ECOSYSTEMS, L.CONCURRENCY, async (eco) => {
    const r = await get(`${L.OSV_BASE}/${encodeURIComponent(eco)}/modified_id.csv`, { timeout: 20000, headers: { range: `bytes=0-${L.HEAD_BYTES}` } });
    const ok = r.ok || r.status === 206;
    return { eco, ok, status: r.status, error: ok ? null : (r.error || `HTTP ${r.status}`), list: ok ? parseModified(r.text, since) : [] };
  });
  // One entry per record (an advisory affecting two ecosystems is listed in both files), newest modification first.
  const byId = new Map();
  for (const h of heads) for (const x of h.list) if (!byId.has(x.id) || byId.get(x.id).ts < x.ts) byId.set(x.id, { ...x, eco: h.eco });
  const want = [...byId.values()].sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
  const seen = want.length ? await sql(`SELECT id, modified FROM ti.osw_seen WHERE id IN (SELECT jsonb_array_elements_text($1::jsonb))`, [want.map((w) => w.id)]) : [];
  const seenAt = new Map(seen.map((s) => [s.id, s.modified]));
  const todo = want.filter((w) => seenAt.get(w.id) !== w.ts).slice(0, L.OSV_MAX);
  let osvFetched = 0, osvFailed = 0;
  const fetched = await pool(todo, L.CONCURRENCY, async (w) => {
    if (deadline - Date.now() < 20000) return null;
    const r = await get(`${L.OSV_BASE}/${encodeURIComponent(w.eco)}/${encodeURIComponent(w.id)}.json`, { as: 'json', timeout: 12000 });
    if (!r.ok || !r.json) { osvFailed++; return null; }
    osvFetched++;
    return { w, row: osvRow(r.json, w.eco) };
  });
  const seenNow = [];
  for (const f of fetched) {
    if (!f) continue;
    seenNow.push({ id: f.w.id, modified: f.w.ts });
    if (f.row && f.row.published && f.row.published >= since) rows.push(f.row);
  }
  for (const h of heads) sources.push({ kind: 'source', id: 'osv:' + h.eco, name: `OSV.dev ${h.eco}`, ok: h.ok, status: h.status, items: h.list.length, note: h.error });
  // oss-security.
  const os = await get(L.OSSSEC_RSS, { timeout: 15000, headers: { accept: 'application/rss+xml, application/xml;q=0.9, */*;q=0.5' } });
  const posts = os.ok ? parseOssSec(os.text) : null;
  for (const p of posts || []) if (p.published && p.published >= since) rows.push(p);
  sources.push({ kind: 'source', id: 'oss-security', name: 'oss-security (seclists.org)', ok: !!posts, status: os.status, items: posts ? posts.length : 0, note: posts ? null : (os.error || `HTTP ${os.status}`) });
  // Hacktivity, newest disclosures first, until the window or a page of reports already held.
  const E = ENV(), h1Headers = { accept: 'application/json' };
  if (E.HACKERONE_API_USERNAME && E.HACKERONE_API_TOKEN) h1Headers.authorization = 'Basic ' + Buffer.from(`${E.HACKERONE_API_USERNAME}:${E.HACKERONE_API_TOKEN}`).toString('base64');
  const cw = await oswH1CweMap(h1Headers, deadline);
  const [{ n: h1Held }] = await sql(`SELECT count(*)::int AS n FROM ti.osw_item WHERE src = 'hacktivity'`);
  const h1Pages = h1Held ? L.H1_PAGES : L.H1_PAGES_FIRST;
  let h1Read = 0, h1Status = 0, h1Error = null;
  for (let page = 1; page <= h1Pages && deadline - Date.now() > 15000; page++) {
    const q = `queryString=${encodeURIComponent('disclosed:true')}&sort=-disclosed_at&page%5Bsize%5D=${L.H1_PAGE}&page%5Bnumber%5D=${page}`;
    const r = await get(`${L.H1_URL}?${q}`, { as: 'json', timeout: 15000, headers: h1Headers });
    h1Status = r.status;
    if (!r.ok || !r.json || !Array.isArray(r.json.data)) { h1Error = r.error || `HTTP ${r.status}`; break; }
    const items = r.json.data.map((i) => h1Row(i, cw.map)).filter(Boolean);
    h1Read += items.length;
    const fresh = items.filter((i) => i.published >= since);
    rows.push(...fresh);
    // A page can be shorter than asked for (anonymous answers carry 50); the "next" link says whether another follows.
    if (!items.length || fresh.length < items.length || !(r.json.links && r.json.links.next)) break;
    const held = await sql(`SELECT count(*)::int AS n FROM ti.osw_item WHERE id IN (SELECT jsonb_array_elements_text($1::jsonb)) AND modified >= $2::timestamptz`, [items.map((i) => i.id), items[items.length - 1].modified]);
    if (held[0].n === items.length) break;
  }
  sources.push({ kind: 'source', id: 'hacktivity', name: 'HackerOne Hacktivity', ok: !h1Error, status: h1Status, items: h1Read, note: h1Error,
    auth: h1Headers.authorization ? 'API token' : 'anonymous', cwe_map: cw.from });
  if (!rows.length && !heads.some((h) => h.ok) && !posts && h1Error) throw new Error('no disclosure source answered: ' + sources.filter((s) => !s.ok).map((s) => `${s.id} ${s.note}`).join('; '));
  // Reach.
  const pkgs = [...new Map(rows.filter((r) => r.src === 'osv' && OSW_REGISTRY[r.ecosystem] && r.project).map((r) => [r.ecosystem + '|' + r.project, { system: r.ecosystem, name: r.project }])).values()];
  const cached = pkgs.length ? await sql(`SELECT system, name, ok, critical, rank, dependents, dependent_repos, downloads, checked_at FROM ti.pkg_reach
    WHERE (system || '|' || name) IN (SELECT jsonb_array_elements_text($1::jsonb))`, [pkgs.map((p) => p.system + '|' + p.name)]) : [];
  const reach = new Map(cached.map((c) => [c.system + '|' + c.name, c]));
  const stale = pkgs.filter((p) => { const c = reach.get(p.system + '|' + p.name); return !c || Date.now() - Date.parse(c.checked_at) > L.REACH_TTL_DAYS * 86400000; }).slice(0, L.REACH_MAX);
  const looked = await pool(stale, L.CONCURRENCY, async (p) => {
    if (deadline - Date.now() < 15000) return null;
    const r = await get(`${L.REACH_URL}${encodeURIComponent(OSW_REGISTRY[p.system])}/packages/${encodeURIComponent(p.name)}`, { as: 'json', timeout: 12000 });
    if (r.status === 404) return { ...p, ok: false };
    if (!r.ok || !r.json) return null;
    const j = r.json, rk = j.rankings && j.rankings.average;
    return { ...p, ok: true, critical: j.critical === true, rank: rk == null ? null : Number(rk), dependents: j.dependent_packages_count ?? null, dependent_repos: j.dependent_repos_count ?? null, downloads: j.downloads ?? null };
  });
  const got = looked.filter(Boolean);
  if (got.length) {
    await sql(`INSERT INTO ti.pkg_reach (system, name, ok, critical, rank, dependents, dependent_repos, downloads, checked_at)
      SELECT system, name, ok, critical, rank, dependents, dependent_repos, downloads, now() FROM jsonb_to_recordset($1::jsonb)
        AS x(system text, name text, ok boolean, critical boolean, rank real, dependents int, dependent_repos int, downloads bigint)
      ON CONFLICT (system, name) DO UPDATE SET ok = EXCLUDED.ok, critical = EXCLUDED.critical, rank = EXCLUDED.rank, dependents = EXCLUDED.dependents,
        dependent_repos = EXCLUDED.dependent_repos, downloads = EXCLUDED.downloads, checked_at = now()`, [got]);
    for (const g of got) reach.set(g.system + '|' + g.name, g);
  }
  sources.push({ kind: 'source', id: 'ecosystems', name: 'ecosyste.ms package usage', ok: !stale.length || got.length > 0, items: got.length, note: stale.length > got.length ? `${stale.length - got.length} lookups left for the next run` : null });
  for (const r of rows) {
    const fz = r.src === 'osv' && r.ecosystem === 'OSS-Fuzz' ? r.project : r.src === 'osv' ? null : ossFuzzMatch(r.src === 'hacktivity' ? `${r.project} ${(r.extra && r.extra.program) || ''}` : r.title, fuzzSet);
    if (r.src === 'osv' && r.ecosystem === 'OSS-Fuzz') { r.reach = 'wide'; r.reach_note = 'OSS-Fuzz project'; r.project = r.project || null; continue; }
    if (r.src === 'osv' && OSW_REGISTRY[r.ecosystem]) { const x = reachOf(reach.get(r.ecosystem + '|' + r.project)); r.reach = reach.has(r.ecosystem + '|' + r.project) ? x.reach : 'unmeasured'; r.reach_note = reach.has(r.ecosystem + '|' + r.project) ? x.note : 'usage not yet looked up'; continue; }
    if (fz && fuzzSet.has(fz) && r.src === 'hacktivity') r.oss = true;
    if (fz && fuzzSet.has(fz)) { r.reach = 'wide'; r.reach_note = `OSS-Fuzz project: ${fz}`; if (!r.project) r.project = fz; continue; }
    r.reach = 'unmeasured';
    r.reach_note = r.src === 'hacktivity' && r.oss ? `open-source program on HackerOne (${H1_OSS[String(r.project || '').toLowerCase()] || r.project}); reach not measured` : 'reach not measured';
  }
  // Store this run's rows (keeping the CVE columns already checked), then mark the OSV records seen. A record read twice
  // in one run (oss-security lists a post once per feed refresh) is stored once.
  const uniq = [...new Map(rows.map((r) => [r.id, r])).values()];
  rows.length = 0;
  rows.push(...uniq);
  if (rows.length) {
    await sql(`INSERT INTO ti.osw_item (id, src, ecosystem, project, title, link, published, modified, aliases, cwes, severity, oss, reach, reach_note, extra)
      SELECT id, src, ecosystem, project, title, link, published, modified, aliases, cwes, severity, oss, reach, reach_note, extra FROM jsonb_to_recordset($1::jsonb)
        AS x(id text, src text, ecosystem text, project text, title text, link text, published timestamptz, modified timestamptz, aliases jsonb, cwes jsonb, severity text,
             oss boolean, reach text, reach_note text, extra jsonb)
      ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, link = EXCLUDED.link, modified = EXCLUDED.modified, aliases = EXCLUDED.aliases, cwes = EXCLUDED.cwes,
        severity = EXCLUDED.severity, oss = EXCLUDED.oss, reach = EXCLUDED.reach, reach_note = EXCLUDED.reach_note, extra = EXCLUDED.extra,
        cve_checked_at = CASE WHEN ti.osw_item.aliases IS DISTINCT FROM EXCLUDED.aliases THEN NULL ELSE ti.osw_item.cve_checked_at END`,
    [rows.map((r) => ({ ...r, project: r.project || null }))]);
  }
  if (seenNow.length) {
    await sql(`INSERT INTO ti.osw_seen (id, modified, at) SELECT id, modified, now() FROM jsonb_to_recordset($1::jsonb) AS x(id text, modified text)
      ON CONFLICT (id) DO UPDATE SET modified = EXCLUDED.modified, at = now()`, [seenNow]);
  }
  // Reach for rows held from earlier runs whose package usage arrived this run.
  if (got.length) {
    const upd = got.map((g) => ({ system: g.system, name: g.name, ...reachOf(g) }));
    await sql(`UPDATE ti.osw_item o SET reach = x.reach, reach_note = x.note FROM jsonb_to_recordset($1::jsonb) AS x(system text, name text, reach text, note text)
      WHERE o.src = 'osv' AND o.ecosystem = x.system AND o.project = x.name`, [upd]);
  }
  // CVE records: kept open-source rows whose record is not yet complete, oldest check first.
  const due = await sql(`SELECT id, aliases FROM ti.osw_item WHERE oss AND reach <> 'limited' AND jsonb_array_length(aliases) > 0 AND published > now() - make_interval(days => $1)
      AND coalesce(cve_state, '') NOT IN ('complete', 'rejected') AND (cve_checked_at IS NULL OR cve_checked_at < now() - make_interval(hours => $2))
    ORDER BY cve_checked_at NULLS FIRST, published DESC LIMIT $3`, [L.WINDOW_DAYS, L.CVE_RECHECK_H, L.CVE_MAX]);
  let cveCalls = 0, cveFailed = 0;
  const checks = await pool(due, 4, async (d) => {
    if (deadline - Date.now() < 8000) return null;
    const cve = (d.aliases || [])[0];
    cveCalls++;
    const r = await get(L.CVE_URL + cve, { as: 'json', timeout: 10000 });
    let st;
    if (r.ok && r.json && r.json.cveMetadata) st = cveState(r.json, null);
    else if (r.status === 404) {
      cveCalls++;
      const i = await get(L.CVEID_URL + cve, { as: 'json', timeout: 10000 });
      if (!i.ok && i.status !== 404) { cveFailed++; return null; }
      st = cveState(null, i.ok ? i.json : null);
    } else { cveFailed++; return null; }
    return { id: d.id, cve, state: st.state, published: st.published, gaps: st.gaps };
  });
  const cv = checks.filter(Boolean);
  if (cv.length) {
    await sql(`UPDATE ti.osw_item o SET cve = x.cve, cve_state = x.state, cve_published = x.published, cve_gaps = x.gaps, cve_checked_at = now(),
        cve_complete_at = CASE WHEN x.state = 'complete' AND o.cve_complete_at IS NULL THEN now() ELSE o.cve_complete_at END
      FROM jsonb_to_recordset($1::jsonb) AS x(id text, cve text, state text, published timestamptz, gaps jsonb) WHERE o.id = x.id`, [cv]);
  }
  sources.push({ kind: 'source', id: 'cve-services', name: 'CVE Services (cveawg.mitre.org)', ok: !cveFailed || cv.length > 0, items: cv.length, note: cveFailed ? `${cveFailed} lookups failed` : null });
  // Retention, then the document.
  await sqlTx([
    [`DELETE FROM ti.osw_item WHERE coalesce(published, seen_at) < now() - make_interval(days => $1)`, [L.KEEP_DAYS]],
    [`DELETE FROM ti.osw_seen WHERE at < now() - make_interval(days => $1)`, [L.SEEN_DAYS]],
    [`DELETE FROM ti.pkg_reach WHERE checked_at < now() - interval '30 days'`, []],
  ]);
  const held = await sql(`SELECT id, src, ecosystem, project, title, link, published, aliases, cwes, severity, reach, reach_note, cve, cve_state, cve_published, cve_gaps,
      cve_checked_at, cve_complete_at, extra FROM ti.osw_item WHERE oss AND reach <> 'limited' AND published > now() - make_interval(days => $1)
    ORDER BY published DESC LIMIT $2`, [L.WINDOW_DAYS, L.MAX_ROWS]);
  const out = held.map((r) => {
    const state = (r.aliases || []).length ? (r.cve_state || 'pending') : 'none';
    // oss-security rows carry the CVE ids printed in the post title only: a title without one says nothing of the record.
    const titleOnly = r.src === 'oss-security' && state === 'none';
    const row = { kind: 'disclosure', id: r.id, source: r.src, ecosystem: r.ecosystem, project: r.project, title: r.title, link: r.link, published: r.published,
      cves: r.aliases || [], cve: r.cve || (r.aliases || [])[0] || null, cwes: r.cwes || [], severity: r.severity, reach: r.reach, reach_note: r.reach_note,
      cve_state: state, cve_label: titleOnly ? 'No CVE id in the post title' : state === 'pending' ? 'CVE record not yet checked' : OSW_STATE_LABEL[state], cve_published: r.cve_published, cve_gaps: r.cve_gaps || [],
      cve_checked_at: r.cve_checked_at, cve_complete_seen: r.cve_complete_at, lead_days: daysBetween(r.published, r.cve_published),
      age_days: daysBetween(r.published, new Date().toISOString()), program: (r.extra && r.extra.program) || null, weakness: (r.extra && r.extra.weakness) || null };
    row.ahead = state === 'pending' || titleOnly ? null : aheadOf({ cve_state: state, published: r.published, cve_published: r.cve_published });
    return row;
  });
  // Bug-bounty disclosures by weakness over the window: every program, counts only.
  const wk = await sql(`SELECT coalesce(extra->>'weakness', 'Not stated') AS weakness, (cwes->>0) AS cwe, count(*)::int AS n, count(*) FILTER (WHERE oss)::int AS oss
    FROM ti.osw_item WHERE src = 'hacktivity' AND published > now() - make_interval(days => $1) GROUP BY 1, 2 ORDER BY n DESC LIMIT 200`, [L.WINDOW_DAYS]);
  const weakRows = wk.map((w) => ({ kind: 'weakness', weakness: w.weakness, cwe: w.cwe, reports: w.n, oss_reports: w.oss }));
  const wide = out.filter((r) => r.reach === 'wide');
  const ahead = wide.filter((r) => r.ahead === true);
  // Leads where a CVE record exists: a day or more after the disclosure (the median is over these), within a day, or before.
  const withRec = wide.filter((r) => r.lead_days != null);
  const leads = withRec.map((r) => r.lead_days).filter((x) => x >= 1).sort((a, b) => a - b);
  const mid = leads.length >> 1;
  const median = !leads.length ? null : leads.length % 2 ? leads[mid] : Math.round(((leads[mid - 1] + leads[mid]) / 2) * 10) / 10;
  const byState = {};
  for (const r of wide) byState[r.cve_state] = (byState[r.cve_state] || 0) + 1;
  const doc = {
    source: 'Open-source disclosures from OSV.dev, the oss-security list and HackerOne Hacktivity, set against CVE Services records; reach from ecosyste.ms and OSS-Fuzz',
    terms: 'Titles, links, dates, identifiers and counts only. OSV.dev data is CC BY 4.0 under each source\'s own terms; ecosyste.ms data is CC BY-SA 4.0; oss-security posts belong to their authors; HackerOne reports belong to their reporters and programs (no report text or summary is kept); CVE records are the CVE Program\'s (terms of use at cve.org).',
    method: `Disclosures published in the last ${L.WINDOW_DAYS} days. Widely deployed: a package ecosyste.ms marks critical or ranks in the top ${L.RANK_MAX}% of its registry by usage, or a project integrated in OSS-Fuzz. CVE record: CVE Services' answer for the disclosure's first CVE id (no id, reserved, incomplete when CVSS, a CWE or affected versions are missing, complete), checked again every ${L.CVE_RECHECK_H} hours until complete. Ahead: no complete CVE record yet, or a record published at least a day after the disclosure; an oss-security post whose title names no CVE id is not judged. Lead: days from disclosure to the CVE record's publication; the median is over records published a day or more after their disclosure. Reach not measured (unmeasured) is listed but counted apart.`,
    generated: new Date().toISOString(), served_from: 'store', window_days: L.WINDOW_DAYS, disclosures: out.length, wide: wide.length, ahead_wide: ahead.length,
    median_lead_days: median, lead_n: leads.length, with_record: withRec.length, same_day: withRec.filter((r) => Math.abs(r.lead_days) < 1).length,
    cve_first: withRec.filter((r) => r.lead_days <= -1).length, by_state: byState, hacktivity_auth: h1Headers.authorization ? 'API token' : 'anonymous', cwe_map: cw.from,
    count: out.length, rows: [...out, ...weakRows, ...sources],
  };
  await recordVolume([['osswatch_wide_30d', wide.length], ['osswatch_ahead_30d', ahead.length]]);
  return { read: rows.length, osv_fetched: osvFetched, osv_failed: osvFailed, osv_queued: want.length - seenAt.size, reach_looked_up: got.length, cve_checked: cv.length, cve_calls: cveCalls,
    hacktivity: h1Read, hacktivity_auth: doc.hacktivity_auth, disclosures: out.length, wide: wide.length, ahead_wide: ahead.length,
    failed: sources.filter((s) => !s.ok).map((s) => ({ source: s.id, status: s.status || 0, note: s.note })), published: await putDoc('osswatch', doc), ms: Date.now() - t0 };
}
