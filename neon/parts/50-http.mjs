// ---------------------------------------------------------------- runner
const JOBS = { gdelt: jobGdelt, infra: jobInfra, health: jobHealth, snap: jobSnap, ioda: jobIoda, retention: jobRetention, lists: jobLists, fires: jobFires,
  maritime: jobMaritime, leaksites: jobLeaksites, ransompay: jobRansompay, unit42: jobUnit42, genioc: jobGenioc, lanesreg: jobLanesreg, blogs: jobBlogs, links: jobLinks, sec8k: jobSec8k };
const LEASE_S = { gdelt: 240, infra: 240, health: 120, snap: 120, ioda: 120, retention: 120, lists: 180, fires: 180, maritime: 120, leaksites: 120, ransompay: 240,
  unit42: 180, genioc: 240, lanesreg: 120, blogs: 240, links: 180, sec8k: 120 };
// Submarine cables (37e-cables.mjs) on the lease row reserved for them since G26: weekly, Sundays at 05:19 UTC.
JOBS.cables = jobCables;
LEASE_S.cables = 180;
// Advisory feeds every three hours at :19; machine triage hourly at :49 (after the blogs slice of the same run), with its
// evaluation run on demand only (37f-triage.mjs).
Object.assign(JOBS, { psirt: jobPsirt, triage: jobTriage, triageeval: jobTriageeval, news: jobNews });
Object.assign(LEASE_S, { psirt: 240, triage: 600, triageeval: 600, news: 180 });
// Source network and agentic reports (3.0, 37h-sources.mjs and 37i-report.mjs). The sources job replaces the news job and
// the blogs job's reading on the schedule; both stay callable by hand.
Object.assign(JOBS, { sources: jobSources, reports: jobReports });
Object.assign(LEASE_S, { sources: 240, reports: 900 });
// Entity graph (3.4.0, 37k-entities.mjs): every slot, after the sources job, so an entry is in the graph within the slot
// that collected it.
Object.assign(JOBS, { entities: jobEntities, watch: jobWatch, score: jobScore, cyphys: jobCyphys, sigma: jobSigma, foresight: jobForesight, translate: jobTranslate });
Object.assign(LEASE_S, { entities: 240, watch: 180, score: 120, cyphys: 120, sigma: 330, foresight: 330, translate: 160 });
export async function runJob(job, opts = {}) {
  const fn = JOBS[job];
  if (!fn) return { job, ok: false, error: 'unknown job' };
  if (!opts.keepCache) RUN_CACHE.clear();
  const holder = (opts.holder || 'run') + ':' + Math.random().toString(36).slice(2, 10);
  const started = new Date(), io0 = { calls: DB_IO.calls, bytes: DB_IO.bytes, sent: DB_IO.sent };
  let lease;
  try {
    lease = await sql(`UPDATE ti.lease SET holder = $1, until = now() + make_interval(secs => $2) WHERE job = $3 AND (until < now() OR holder = $1) RETURNING job`, [holder, LEASE_S[job], job]);
  } catch (e) { return { job, ok: false, error: 'lease: ' + String(e.message || e) }; }
  if (!lease.length) return { job, ok: false, skipped: true, error: 'another run holds the lease' };
  let result, ok = true;
  try { result = await fn(opts); } catch (e) { ok = false; result = { error: String((e && e.message) || e) }; }
  // A job can finish its work yet fail the run (the blogs job holding a shrunken document): it keeps its detail.
  if (ok && result && result.run_failed) { ok = false; result.error = String(result.run_failed); delete result.run_failed; }
  const ms = Date.now() - started.getTime();
  // Query results the job read (requests in flight on the same instance may add to it), for the transfer budget.
  if (result && typeof result === 'object') result.db = { calls: DB_IO.calls - io0.calls, kb: Math.round((DB_IO.bytes - io0.bytes) / 1024), sent_kb: Math.round((DB_IO.sent - io0.sent) / 1024) };
  try {
    await sqlTx([
      [`UPDATE ti.lease SET until = 'epoch' WHERE job = $1 AND holder = $2`, [job, holder]],
      // The collector version is kept with each run, so failures can be counted under the version that is running.
      [`INSERT INTO ti.run (job, started_at, ms, ok, detail) VALUES ($1, $2, $3, $4, $5::jsonb)`, [job, started, ms, ok, { ...result, version: VERSION }]],
    ]);
  } catch (e) { result.log_error = String(e.message || e); }
  console.log(JSON.stringify({ job, ok, ms, ...(ok ? {} : { error: result.error }) }));
  return { ...result, job, ok, ms };
}
// Which jobs a scheduled occurrence runs (UTC minute of the 15-minute grid).
// :04 and :34 refresh the map and the snapshots; :19 adds the hourly corroboration lists, the leak-site cross-check, a
// slice of the link checks and the daily sources at their hours (Unit 42 06 UTC, Gen Threat Labs 07, Lanes registry 09,
// Ransomwhere Mondays 08, SEC 8-K filings 12 and 22); :49 adds FIRMS, the maritime sources and a slice of the blogs.
export function plan(at) {
  const m = at.getUTCMinutes(), h = at.getUTCHours();
  const jobs = ['gdelt'];
  if (m < 15 || (m >= 30 && m < 45)) jobs.push('infra', 'snap');
  else jobs.push('health', 'ioda');
  // The source network reads its due feeds in every slot; at :49 it runs before triage, so triage reads the hour's titles.
  if (m < 45) jobs.push('sources');
  // Non-English titles are translated before the entities job reads them (37q-translate.mjs).
  if (m < 45) jobs.push('translate');
  // Machine triage in every quarter hour since 3.10.7 (:19 and :34 since 3.10.6), after the translation
  // (37f-triage.mjs: TRIAGE.EXTRA_SLOTS; a free-tier account holds these runs).
  if (m < 45) jobs.push('triage');
  if (m >= 15 && m < 30) {
    jobs.push('lists', 'leaksites', 'links');
    if (h === 6) jobs.push('unit42');
    if (h === 7) jobs.push('genioc');
    if (h === 9) jobs.push('lanesreg');
    if (h === 8 && at.getUTCDay() === 1) jobs.push('ransompay');
    if (h === 12 || h === 22) jobs.push('sec8k');
    if (h === 5 && at.getUTCDay() === 0) jobs.push('cables');
    if (h % 3 === 1) jobs.push('psirt');
    // One evaluation batch an hour until the gold set is scored; a complete evaluation makes no request. The operator
    // route answers within its own deadline and cannot hold a model request open, so the replay runs on the schedule.
    jobs.push('triageeval');
    // The track record (37m-score.mjs) hourly; the day's value is its last measurement.
    jobs.push('score');
  }
  // Cyber-physical coincidences (37n-cyphys.mjs) hourly, before the watch job reads them.
  if (m >= 45) jobs.push('retention', 'fires', 'maritime', 'sources', 'translate', 'triage', 'cyphys');
  jobs.push('entities', 'watch');
  // Sigma drafts (37o-sigma.mjs) in the lightest quarter hour, after the entities and watches it reads.
  if (m >= 30 && m < 45) jobs.push('sigma');
  // Threatcasting futures (37p-foresight.mjs) in the :04 quarter hour.
  if (m < 15) jobs.push('foresight');
  jobs.push('reports');
  return jobs;
}
export async function scheduled(at) {
  RUN_CACHE.clear();
  const jobs = plan(at), out = [];
  for (const j of jobs) out.push(await runJob(j, { holder: 'cron', keepCache: true, at: at.toISOString() }));
  // Run summaries stay small in the trigger log: counts and errors, not documents.
  return { scheduled_at: at.toISOString(), version: VERSION, jobs: out };
}

// ---------------------------------------------------------------- HTTP surface
// Callers: the schedule trigger (POST / with X-Neon-Trigger-Invocation-Id, a header Neon strips from client
// requests), and Vercel functions of the threat-feeds project, which present their Vercel OIDC token as a bearer token.
// The token is checked against Vercel's published keys for team skilfoys-projects: RS256 signature, issuer, audience,
// expiry, owner, project and environment. No shared secret is involved. TI_KEY, if set in this function's environment,
// is accepted as an operator override in the x-ti-key header.
const OIDC = () => ({
  team: ENV().TI_OIDC_TEAM || 'skilfoys-projects',
  owner: ENV().TI_OIDC_OWNER_ID || 'team_J1AYAuYaWSGEP7cjBp80rdJp',
  project: ENV().TI_OIDC_PROJECT_ID || 'prj_eISaKjcBNEHSxvuO7OvW6Nf94s5P',
  envs: String(ENV().TI_OIDC_ENVS || 'production,preview').split(','),
});
const JWKS = new Map();
const b64u = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
async function jwks(iss, force = false) {
  const hit = JWKS.get(iss);
  if (hit && Date.now() - hit.at < (force ? 60000 : 3600000)) return hit.keys;
  const r = await get(iss + '/.well-known/jwks', { as: 'json', timeout: 8000 });
  if (!r.ok || !r.json || !Array.isArray(r.json.keys)) throw new Error('JWKS fetch failed: HTTP ' + r.status);
  const keys = new Map();
  for (const k of r.json.keys) if (k && k.kty === 'RSA' && k.kid) { try { keys.set(k.kid, createPublicKey({ key: k, format: 'jwk' })); } catch { /* skip malformed key */ } }
  JWKS.set(iss, { at: Date.now(), keys });
  return keys;
}
export async function verifyVercelOidc(token, now = Date.now()) {
  const c = OIDC();
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  let head, claims;
  try { head = JSON.parse(b64u(parts[0]).toString('utf8')); claims = JSON.parse(b64u(parts[1]).toString('utf8')); } catch { return null; }
  if (!head || head.alg !== 'RS256' || !head.kid || !claims) return null;
  if (![`https://oidc.vercel.com/${c.team}`, 'https://oidc.vercel.com'].includes(claims.iss)) return null;
  let keys = await jwks(claims.iss);
  if (!keys.has(head.kid)) keys = await jwks(claims.iss, true);
  const key = keys.get(head.kid);
  if (!key || !verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), key, b64u(parts[2]))) return null;
  const t = Math.floor(now / 1000);
  if (!(claims.exp > t - 60) || (claims.nbf && claims.nbf > t + 60)) return null;
  if (![].concat(claims.aud || []).includes(`https://vercel.com/${c.team}`)) return null;
  if (claims.owner_id !== c.owner || claims.project_id !== c.project || !c.envs.includes(claims.environment)) return null;
  return claims;
}
async function authorize(req) {
  const want = ENV().TI_KEY || '';
  const got = req.headers.get('x-ti-key') || '';
  if (want && got.length === want.length && timingSafeEqual(Buffer.from(got), Buffer.from(want))) return 'key';
  const m = (req.headers.get('authorization') || '').match(/^Bearer\s+(\S+)$/i);
  if (!m) return null;
  try { const c = await verifyVercelOidc(m[1]); return c ? 'vercel:' + c.environment : null; } catch (e) { console.error('oidc:', e.message); return null; }
}
const PROBE_TARGETS = (t) => ({
  dshield_topips: 'https://isc.sans.edu/api/topips/records/10?json',
  dshield_sources: 'https://isc.sans.edu/api/sources/attacks/10?json',
  dshield_infocon: 'https://isc.sans.edu/api/infocon?json',
  urlhaus_online: 'https://urlhaus.abuse.ch/downloads/csv_online/',
  urlhaus_api: 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/',
  feodo: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
  threatfox: 'https://threatfox.abuse.ch/export/json/recent/',
  geojs: 'https://get.geojs.io/v1/ip/geo.json?ip=8.8.8.8,1.1.1.1',
  ipapi: 'http://ip-api.com/json/8.8.8.8?fields=status,country,countryCode,regionName,city,lat,lon,isp,as,asname',
  ioda_events: `https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events?from=${t - 2 * 86400}&until=${t}&entityType=country&includeAlerts=false&format=codf&limit=5`,
  ioda_summary: `https://api.ioda.inetintel.cc.gatech.edu/v2/outages/summary?from=${t - 86400}&until=${t}&entityType=country&limit=5`,
  ioda_alerts: `https://api.ioda.inetintel.cc.gatech.edu/v2/outages/alerts?from=${t - 86400}&until=${t}&entityType=country&limit=5`,
  // Diagnostic probes only, never a data source: the submarine cable job (lease 'cables', 37e-cables.mjs) uses open data
  // only, since TeleGeography's geocoded data is an annual paid licence. See docs/cables-open-data.md.
  cables: 'https://www.submarinecablemap.com/api/v3/cable/cable-geo.json',
  landing: 'https://www.submarinecablemap.com/api/v3/landing-point/landing-point-geo.json',
  gdelt_last: 'http://data.gdeltproject.org/gdeltv2/lastupdate.txt',
  ukmto_api: 'https://www.ukmto.org/api/incidents',
  ukmto_page: 'https://www.ukmto.org/recent-incidents',
  tc_victims: 'https://threatcluster.io/api/darkweb/public/victims.json?days=2',
  tc_stats: 'https://threatcluster.io/api/darkweb/stats',
  tc_iocs: 'https://threatcluster.io/api/iocs/public/feed.txt',
  ransomwhere: 'https://api.ransomwhe.re/export',
  lanes_outlets: 'https://lanes.news/data/outlets.csv',
  lanes_naming: 'https://lanes.news/data/naming.csv',
  ofac_action: 'https://ofac.treasury.gov/recent-actions/20261015',
  unit42_list: 'https://api.github.com/repos/PaloAltoNetworks/Unit42-timely-threat-intel/contents/',
  genioc_tree: 'https://api.github.com/repos/gendigitalinc/ioc/git/trees/master',
  spamhaus_drop: 'https://www.spamhaus.org/drop/drop_v4.json',
  blocklist_de: 'https://lists.blocklist.de/lists/all.txt',
  cins: 'https://cinsscore.com/list/ci-badguys.txt',
  threatview: 'https://threatview.io/Downloads/IP-High-Confidence-Feed.txt',
  et_compromised: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
  greensnow: 'https://blocklist.greensnow.co/greensnow.txt',
  sslbl: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
  tranco: 'https://tranco-list.eu/api/ranks/domain/example.com',
  orkl: 'https://orkl.eu/api/v1/library/search?query=APT28&full=false&limit=2',
  hashlookup: 'https://hashlookup.circl.lu/lookup/sha256/0000000000000000000000000000000000000000000000000000000000000000',
  bgpranking: 'https://bgpranking-ng.circl.lu/ipasn_history/?ip=8.8.8.8',
  cl0q_cross: 'https://cl0q.com/api/cross/asn/13335',
  cl0q_search: 'https://cl0q.com/search?q=ip%3A1.1.1.1&limit=2',
  marad: 'https://www.maritime.dot.gov/msci-advisories',
  nga_asam: ASAM_URL(new Date((t - 30 * 86400) * 1000).toISOString().slice(0, 10)),
  nga_warn: 'https://msi.nga.mil/api/publications/broadcast-warn?output=json&status=A&navArea=4',
  nga_warn_all: 'https://msi.nga.mil/api/publications/broadcast-warn?output=json&status=A',
  nga_web: 'https://msi.nga.mil/',
  c2if: 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv',
  ipsum: 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
  tor_exits: 'https://check.torproject.org/torbulkexitlist',
  blogs_readme: 'https://raw.githubusercontent.com/muchdogesec/awesome_threat_intel_blogs/main/README.md',
});
async function status() {
  const [runs, leases, files, size, geoN, infraN] = await sqlTx([
    [`SELECT job, started_at, ms, ok, left(detail::text, 400) AS detail FROM ti.run ORDER BY started_at DESC LIMIT 30`],
    [`SELECT job, holder, until FROM ti.lease ORDER BY job`],
    [`SELECT count(*)::int AS files, min(slot) AS first, max(slot) AS last, count(*) FILTER (WHERE status = 'ok')::int AS ok FROM ti.gdelt_file`],
    [`SELECT pg_database_size(current_database())::bigint AS bytes`],
    [`SELECT count(*)::int AS n, count(*) FILTER (WHERE ok)::int AS ok FROM ti.ip_geo`],
    [`SELECT layer, count(*)::int AS n, max(last_obs) AS last_obs FROM ti.infra GROUP BY layer ORDER BY layer`],
  ]);
  return { version: VERSION, now: new Date().toISOString(), gdelt_files: files[0], db_bytes: size[0].bytes, ip_geo: geoN[0], infra: infraN, leases, runs };
}

export default {
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    try {
      if (req.method === 'POST' && path === '/') {
        if (!req.headers.get('x-neon-trigger-invocation-id') && !(await authorize(req))) return json({ error: 'forbidden' }, 403);
        const body = await req.json().catch(() => ({}));
        const at = body && body.data && body.data.scheduled_at ? new Date(body.data.scheduled_at) : new Date();
        return json(await scheduled(isNaN(at) ? new Date() : at));
      }
      // The bucket's upload trigger for reports/queue/ (agentic reports): the trigger holds the request while the report is
      // written. The header is one Neon strips from client requests.
      if (req.method === 'POST' && path === '/report-run' && req.headers.get('x-neon-trigger-invocation-id')) {
        const body = await req.json().catch(() => ({}));
        const key = String((body && body.data && (body.data.key || body.data.object_key)) || (body && (body.key || body.object_key)) || JSON.stringify(body || {}));
        const m = key.match(/R-\d{8}-[0-9a-f]{8}/);
        console.log(JSON.stringify({ trigger: 'report-run', key: String(key).slice(0, 120) }));
        return json(m ? await runReport(m[0]) : await jobReports());
      }
      const who = await authorize(req);
      if (!who) return json({ error: 'unauthorized' }, 401);
      if (req.method === 'POST' && path === '/search') return json(await search(await req.json().catch(() => ({}))));
      if (req.method === 'POST' && path === '/report') {
        const r = await startReport(await req.json().catch(() => ({})));
        // The report starts at once in this instance (the long-running function keeps working after it answers); the
        // bucket's upload trigger and the scheduled reports job pick it up if this instance goes away first.
        if (r.id && !r.reused) runReport(r.id).catch((e) => console.log(JSON.stringify({ report: r.id, error: String((e && e.message) || e) })));
        return json(r, r.status && r.error ? r.status : 200);
      }
      if (req.method === 'GET' && path.startsWith('/report/')) { const r = await getReport(path.slice(8)); return r ? json(r) : json({ error: 'not found' }, 404); }
      if (req.method === 'GET' && path === '/reports') return json({ reports: await listReports(url.searchParams.get('limit')) });
      if (req.method === 'GET' && path === '/watch') {
        const r = await watchChanges(url.searchParams.get('ids'), url.searchParams.get('since'), url.searchParams.get('days'));
        return json(r, r.status && r.error ? r.status : 200);
      }
      if (req.method === 'GET' && path === '/graph') {
        const sp = url.searchParams, days = sp.get('days');
        const r = sp.get('id') ? await entityCard(sp.get('id'), days) : sp.get('a') ? await entityPair(sp.get('a'), sp.get('b'), days) : sp.get('q') ? await entitySearch(sp.get('q'), sp.get('t') || '', sp.get('limit'))
          : { error: 'id, a and b, or q required', status: 400 };
        return json(r, r.status && r.error ? r.status : 200);
      }
      if (req.method === 'GET' && path.startsWith('/doc/')) {
        const name = path.slice(5);
        if (!/^[a-z0-9-]{1,64}$/.test(name)) return json({ error: 'bad name' }, 400);
        const o = await s3Get(`docs/${name}.json.gz`);
        if (!o) return json({ error: 'missing', name }, 404);
        return new Response(o.buf, { status: 200, headers: { 'content-type': 'application/gzip', 'cache-control': 'no-store', 'x-doc-modified': o.modified || '' } });
      }
      if (req.method === 'POST' && path === '/run') {
        const body = await req.json().catch(() => ({}));
        const jobs = [].concat(body.job || url.searchParams.get('job') || []).flatMap((j) => String(j).split(',')).filter(Boolean);
        if (!jobs.length) return json({ error: 'job required', jobs: Object.keys(JOBS) }, 400);
        const out = [];
        for (const j of jobs) out.push(await runJob(j, { holder: 'manual', backfill: !!body.backfill, rebuild: !!body.rebuild, reprocess: !!body.reprocess,
          historyDays: +body.historyDays || 0, budgetMs: Math.min(+body.budgetMs || 40000, 600000) }));
        return json({ version: VERSION, jobs: out });
      }
      if (req.method === 'GET' && path === '/status') return json(await status());
      if (req.method === 'GET' && path === '/enrich') return json(await enrich(url.searchParams.get('type') || '', url.searchParams.get('q') || ''));
      if (req.method === 'GET' && path === '/probe') {
        const t = Math.floor(Date.now() / 1000), targets = PROBE_TARGETS(t), name = url.searchParams.get('target') || '';
        if (name === 'firms_status' || name === 'firms_sample') {
          // The FIRMS key travels in the request path; the probe reports the answer with the key redacted.
          const key = ENV().FIRMS_MAP_KEY || '';
          if (!key) return json({ target: name, ok: false, error: 'FIRMS_MAP_KEY is not set' });
          const u = name === 'firms_status' ? 'https://firms.modaps.eosdis.nasa.gov/mapserver/mapkey_status/?MAP_KEY=' + encodeURIComponent(key)
            : 'https://firms.modaps.eosdis.nasa.gov/api/area/csv/' + encodeURIComponent(key) + '/VIIRS_NOAA20_NRT/30,46,40,52/1';
          const r = await get(u, { timeout: 25000 });
          return json({ target: name, ok: r.ok, status: r.status, ms: r.ms, bytes: r.text ? r.text.length : 0, head: String(r.text || r.error || '').split(key).join('***').slice(0, 2500) });
        }
        if (name === 'sec_fts') {
          // EDGAR full-text search refuses requests without a declared User-Agent (SEC fair access).
          const ua = ENV().SEC_USER_AGENT || '';
          if (!ua) return json({ target: name, ok: false, error: 'SEC_USER_AGENT is not set' });
          const r = await get(SEC_FTS + '?q=%22Item%201.05%22&forms=8-K', { timeout: 20000, headers: { 'user-agent': ua, accept: 'application/json' } });
          return json({ target: name, ok: r.ok, status: r.status, ms: r.ms, bytes: r.text ? r.text.length : 0, head: String(r.text || r.error || '').slice(0, 2500) });
        }
        if (name === 'nga_bundle') {
          // The MSI web application's own scripts name the API paths it calls; this lists them and the text around
          // ?find= (default "asam") in each same-origin script the front page loads. Read-only, msi.nga.mil only.
          const page = await get(PROBE_TARGETS(t).nga_web, { timeout: 20000, headers: { accept: 'text/html' } });
          const srcs = [...new Set([...String(page.text || '').matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)].map((m) => { try { return new URL(m[1], 'https://msi.nga.mil/').href; } catch { return ''; } })
            .filter((u) => u && new URL(u).hostname === 'msi.nga.mil'))].slice(0, 12);
          const f = (url.searchParams.get('find') || 'asam').toLowerCase(), out = [];
          for (const s of srcs) {
            const r = await get(s, { timeout: 20000 });
            const body = String(r.text || ''), low = body.toLowerCase(), hits = [];
            for (let i = low.indexOf(f); i >= 0 && hits.length < 8; i = low.indexOf(f, i + f.length)) hits.push(body.slice(Math.max(0, i - 140), i + 140));
            const paths = [...new Set([...body.matchAll(/["'`]((?:https:\/\/msi\.nga\.mil)?\/?api\/[A-Za-z0-9/_-]{3,80})/g)].map((m) => m[1]))].slice(0, 60);
            out.push({ src: s, status: r.status, bytes: body.length, paths, hits });
          }
          return json({ target: name, page: page.status, scripts: srcs.length, out });
        }
        if (!targets[name]) return json({ error: 'unknown target', targets: Object.keys(targets).concat(['firms_status', 'firms_sample', 'sec_fts', 'nga_bundle']) }, 400);
        const r = await get(targets[name], { timeout: 20000 });
        // ?find=<text> shows the body around the first match, ?from=<n> from that offset; the head otherwise.
        const body = r.text || '', find = url.searchParams.get('find') || '', at = find ? Math.max(0, body.indexOf(find) - 200) : Math.max(0, +url.searchParams.get('from') || 0);
        return json({ target: name, url: targets[name], ok: r.ok, status: r.status, ms: r.ms, error: r.error, bytes: body.length, at, found: find ? body.indexOf(find) : undefined,
          content_type: r.headers ? r.headers.get('content-type') : null, ratelimit: r.headers ? { rl: r.headers.get('x-rl'), ttl: r.headers.get('x-ttl') } : null, head: body.slice(at, at + 3500) });
      }
      return json({ error: 'not found' }, 404);
    } catch (e) {
      console.error(e);
      return json({ error: String((e && e.message) || e) }, 500);
    }
  },
};
