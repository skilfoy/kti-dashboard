// ---------------------------------------------------------------- health
const PROBES = [
  ['gdelt_exports', 'http://data.gdeltproject.org/gdeltv2/lastupdate.txt'],
  ['gdelt_doc_api', 'https://api.gdeltproject.org/api/v2/doc/doc?query=cyber&mode=artlist&maxrecords=1&format=json'],
  ['threatfox', 'abuse:ioc'],
  ['feodo', 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'],
  ['urlhaus', 'abuse:url'],
  ['dshield', 'https://isc.sans.edu/api/infocon?json'],
  ['epss', 'https://api.first.org/data/v1/epss?envelope=false&limit=1'],
  ['ransomware_live', 'https://api.ransomware.live/v2/groups'],
  ['cisa_kev', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'],
  ['tor_exits', 'https://check.torproject.org/torbulkexitlist'],
  ['lanes', 'https://lanes.news/data/temperatures.csv'],
  ['ofac_recent_actions', 'https://ofac.treasury.gov/recent-actions'],
  ['threatcluster', 'https://threatcluster.io/api/darkweb/stats'],
  ['marad_msci', 'https://www.maritime.dot.gov/msci-advisories'],
  ['nga_msi', 'https://msi.nga.mil/api/publications/broadcast-warn?output=json&status=A&navArea=4'],
  ['ukmto', 'https://www.ukmto.org/recent-incidents'],
  ['ransomwhere', 'https://api.ransomwhe.re/export'],
  ['sec_edgar', 'sec:'],
  ['github_api', 'https://api.github.com/rate_limit'],
  ['spamhaus_drop', 'https://www.spamhaus.org/drop/drop_v4.json'],
  ['blocklist_de', 'https://lists.blocklist.de/lists/all.txt', [200, 206, 416], { range: 'bytes=0-1023' }],
  ['cins_army', 'https://cinsscore.com/list/ci-badguys.txt'],
  ['circl_bgpranking', 'https://bgpranking-ng.circl.lu/ipasn_history/?ip=8.8.8.8'],
  ['tranco', 'https://tranco-list.eu/api/ranks/domain/example.com'],
  ['ip_api', 'http://ip-api.com/json/8.8.8.8?fields=status'],
  ['geojs', 'https://get.geojs.io/v1/ip/country/8.8.8.8.json'],
  ['ioda', null],
];
// Documented gaps (runbook section 6): sources that refuse or no longer publish, recorded so they stay out of the down
// list. Each names the answer it gives while the gap holds; a feed whose answer departs from it is classed by its check
// again ("up" when it answers, "down" otherwise), so a lifted block or a new failure shows. Volume rows of the same
// sources hold at zero while the gap stands.
export const KNOWN_GAPS = {
  marad_msci: { expect: [403], note: "MARAD's Akamai edge refuses cloud addresses with HTTP 403 (since 22 Oct 2026); never worked around" },
  ukmto: { expect: [403], note: "UKMTO's Cloudflare rule refuses cloud addresses with HTTP 403 (since 22 Oct 2026); never worked around" },
  nga_msi: { expect: [200, 206, 503], stale: true, note: 'NGA broadcast warnings: the newest warning listed in force was issued 2024-05-10, and since November 2026 the endpoint also answers HTTP 503 at times; the maritime job counts the list as stale and keeps it off the map' },
  gdelt_doc_api: { expect: [429], note: 'The GDELT DOC API rate-limits cloud egress (HTTP 429) and feeds no layer' },
};
export const KNOWN_GAP_VOLUME = { marad: 'marad_msci', asam: 'nga_asam', navwarn_security: 'nga_msi' };
// Answer classes (3 November 2026). Some sources refuse cloud egress in more than one way: the GDELT DOC API alternates
// between HTTP 429 and a timeout. A 429, a timeout or a failed fetch (status 0)
// is one answer, "refused at cloud egress", so the gap holds while the answer stays in that class; any other answer, an
// HTTP 200 among them, lifts it. An entry already defined above keeps its own note and fields.
export const EGRESS_REFUSED = [429, 0];
KNOWN_GAPS.gdelt_doc_api = { ...KNOWN_GAPS.gdelt_doc_api, expect: EGRESS_REFUSED, answer_class: 'refused at cloud egress (429, timeout or failed fetch)' };
// The HIBP and GreyNoise probes left on 19 November 2026 with the exposure monitor they served (Sean: the platform is a
// public piece with no organizational estate).
// Open-data sources of the cables job (37e-cables.mjs): Overpass's status page and a one-line Wikidata SPARQL ASK, sent
// with the same identifying User-Agent and an Accept header (overpass-api.de answers a bare request with HTTP 406).
const OPEN_DATA_HEADERS = (accept) => () => ({ accept, 'user-agent': cableUserAgent(ENV().SEC_USER_AGENT || 'contact not set') });
// Overpass has no probe: its status page did not answer this host within the probe deadline from 14 November 2026 on,
// while the weekly cables job read the interpreter without trouble (8 and 15 November). That job's own run record is the
// check; a failed run raises the collector alert.
PROBES.push(['wikidata', WIKIDATA_SPARQL + '?format=json&query=' + encodeURIComponent('ASK {}'), [200, 206], OPEN_DATA_HEADERS('application/sparql-results+json')]);
// up | down | known_gap for one feed check ({feed, ok, status}). A known-gap feed whose check passes while the gap
// expects a refusal is "up" (the block lifted); one that fails with an unexpected answer is "down".
export function feedState(c) {
  const g = KNOWN_GAPS[c.feed];
  if (g && g.expect.includes(c.status) && (g.stale || !c.ok)) return 'known_gap';
  if (c.ok === true) return 'up';
  if (c.ok === false) return 'down';
  return null;
}
export async function jobHealth() {
  const t0 = Date.now(), at = new Date().toISOString();
  const now = Math.floor(Date.now() / 1000);
  let infocon = null;
  const checks = await pool(PROBES, 8, async ([feed, url, okc, hdrs]) => {
    // ThreatFox and URLhaus: the authenticated API with the key, else the gate (21 October 2026) without a request.
    if (url && url.startsWith('abuse:')) {
      const r = await abuseProbe(url.slice(6));
      const ok = r.ok && !(r.json && r.json.query_status && !['ok', 'no_results'].includes(r.json.query_status));
      return { feed, ok, status: r.status, ms: r.ms, error: ok ? null : r.gated ? 'needs an abuse.ch Auth-Key: keyless export closed 21 Oct 2026' : (r.error || `HTTP ${r.status}`) };
    }
    // EDGAR full-text search needs the declared User-Agent; without one the check reports that.
    if (url === 'sec:') {
      const ua = ENV().SEC_USER_AGENT || '';
      if (!ua) return { feed, ok: false, status: 0, ms: 0, error: 'SEC_USER_AGENT is not set' };
      const r = await get(SEC_FTS + '?q=%22Item%201.05%22&forms=8-K', { timeout: 12000, headers: { 'user-agent': ua, accept: 'application/json' } });
      return { feed, ok: r.ok, status: r.status, ms: r.ms, error: r.ok ? null : (r.error || `HTTP ${r.status}`) };
    }
    const u = url || `https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events?from=${now - 3600}&until=${now}&entityType=country&limit=1`;
    const r = await get(u, { timeout: 12000, headers: { range: 'bytes=0-4095', ...(typeof hdrs === 'function' ? hdrs() : hdrs || {}) } });
    const ok = okc ? okc.includes(r.status) : (r.status >= 200 && r.status < 300);
    if (feed === 'dshield' && ok) { try { infocon = JSON.parse(r.text).status || null; } catch { /* left null */ } }
    return { feed, ok, status: r.status, ms: r.ms, error: ok ? null : (r.error || `HTTP ${r.status}`) };
  });
  await sql(`INSERT INTO ti.feed_check (at, feed, ok, status, ms, error) SELECT $2::timestamptz, feed, ok, status, ms, error
    FROM jsonb_to_recordset($1::jsonb) AS x(feed text, ok boolean, status int, ms int, error text) ON CONFLICT DO NOTHING`, [checks, at]);
  const doc = await buildHealth({ checks, at, infocon });
  // Infocon is DShield's own published level, read from its API; no check of ours feeds it, so known gaps cannot move it.
  return { checked: checks.length, down: doc.down, known_gaps: doc.known_gaps, infocon, published: await putDoc('health', doc), ms: Date.now() - t0 };
}
// Volume baseline per feed over 30 days of ti.feed_volume: the all-hours median (median_30d) and the median of the runs
// in one UTC hour of the day (median_hour, hour_samples). The hour is $2 when given (a job judging the count it holds
// now), else the hour of the feed's latest row, whose own row is then left out of the hour median. $1 limits the feeds
// (null for all).
export const VOLUME_BASELINE_SQL = `WITH v AS (SELECT feed, at, n FROM ti.feed_volume WHERE at > now() - interval '30 days' AND ($1::text[] IS NULL OR feed = ANY($1::text[]))),
    last AS (SELECT DISTINCT ON (feed) feed, at, n, coalesce($2::int, extract(hour FROM at AT TIME ZONE 'UTC')::int) AS hour_utc FROM v ORDER BY feed, at DESC),
    allh AS (SELECT feed, (percentile_cont(0.5) WITHIN GROUP (ORDER BY n))::real AS median_30d, count(*)::int AS runs, min(at) AS first_at FROM v GROUP BY feed),
    hr AS (SELECT v.feed, (percentile_cont(0.5) WITHIN GROUP (ORDER BY v.n))::real AS median_hour, count(*)::int AS hour_samples FROM v JOIN last l ON l.feed = v.feed
      AND extract(hour FROM v.at AT TIME ZONE 'UTC')::int = l.hour_utc AND ($2::int IS NOT NULL OR v.at < l.at) GROUP BY v.feed)
  SELECT l.feed, l.n, l.at, a.median_30d, a.runs, a.first_at, l.hour_utc, h.median_hour, coalesce(h.hour_samples, 0)::int AS hour_samples
  FROM last l JOIN allh a USING (feed) LEFT JOIN hr h USING (feed) ORDER BY l.feed`;
export const HOUR_SAMPLES_MIN = 5;
// Spike when the latest snapshot is at least five times its baseline, silence when it is under a fifth of it (Arici
// 3.5.1, 7.3.1; Kuhn p80); judged once a feed has seven days of runs. The baseline is the median of the same UTC hour
// once that hour has HOUR_SAMPLES_MIN earlier runs (feeds that follow the clock, such as FIRMS detections that track
// satellite passes, are judged against their own hour), else the all-hours median. An empty snapshot is silence against
// the all-hours median; against an hour whose median is zero it is normal. median_30d keeps its earlier meaning (all
// hours); ratio is n over the baseline used, named in basis and baseline.
export function volumeFlag(v, now = Date.now()) {
  const days = v.first_at ? (now - Date.parse(v.first_at)) / 86400000 : 0;
  const num = (x) => (x == null ? null : Number(x));
  const med = num(v.median_30d), medH = num(v.median_hour), n = num(v.n), samples = +v.hour_samples || 0;
  const basis = medH != null && samples >= HOUR_SAMPLES_MIN ? 'hour' : 'all';
  const base = basis === 'hour' ? medH : med;
  let flag = 'normal';
  if (days < 7) flag = 'baseline building';
  else if (base > 0 ? n < base / 5 : basis === 'all' && n === 0) flag = 'silence';
  else if (base > 0 && n >= base * 5) flag = 'spike';
  const r1 = (x) => (x == null ? null : Math.round(x * 10) / 10);
  return { feed: v.feed, n, at: v.at, median_30d: r1(med), ratio: base ? Math.round((n / base) * 100) / 100 : null, runs: v.runs, baseline_days: Math.floor(days), flag,
    basis, baseline: r1(base), hour_utc: v.hour_utc == null ? null : +v.hour_utc, median_hour: r1(medH), hour_samples: samples };
}
export async function buildHealth({ checks, at, infocon }) {
  const [up, recent, runs, fails, vol] = await sqlTx([
    [`SELECT feed, count(*) FILTER (WHERE at > now() - interval '24 hours')::int AS n24, count(*) FILTER (WHERE at > now() - interval '24 hours' AND ok)::int AS ok24,
        count(*)::int AS n7, count(*) FILTER (WHERE ok)::int AS ok7, max(at) FILTER (WHERE ok) AS last_ok, max(at) FILTER (WHERE NOT ok) AS last_fail,
        (percentile_cont(0.5) WITHIN GROUP (ORDER BY ms) FILTER (WHERE ok AND at > now() - interval '24 hours'))::int AS p50_ms
      FROM ti.feed_check WHERE at > now() - interval '7 days' GROUP BY feed`],
    [`SELECT feed, ok FROM ti.feed_check WHERE at > now() - interval '12 hours' ORDER BY feed, at DESC`],
    [`SELECT DISTINCT ON (job) job, started_at, ms, ok, detail->>'error' AS error FROM ti.run ORDER BY job, started_at DESC`],
    // Failures under the running collector version: a fault a deploy has fixed stops counting at the deploy (16 November
    // 2026: the duplicate-link fault kept a psirt alert open for a day after the fix). failed_24h_all keeps every failure.
    [`SELECT job, count(*) FILTER (WHERE NOT ok AND detail->>'version' = $1)::int AS failed_24h, count(*) FILTER (WHERE NOT ok)::int AS failed_24h_all, count(*)::int AS runs_24h
      FROM ti.run WHERE started_at > now() - interval '24 hours' GROUP BY job`, [VERSION]],
    // Volume baseline (B5): latest snapshot size per feed against its 30-day median, by UTC hour once that hour has history.
    [VOLUME_BASELINE_SQL, [null, null]],
  ]);
  const streak = new Map();
  for (const r of recent) { const s = streak.get(r.feed) || { n: 0, done: false }; if (!s.done) { if (r.ok) s.done = true; else s.n++; } streak.set(r.feed, s); }
  const cur = new Map((checks || []).map((c) => [c.feed, c]));
  const fmap = new Map(fails.map((f) => [f.job, f]));
  const rows = up.map((u) => ({ kind: 'feed', feed: u.feed, ok: cur.has(u.feed) ? cur.get(u.feed).ok : null, status: cur.has(u.feed) ? cur.get(u.feed).status : null,
    ms: cur.has(u.feed) ? cur.get(u.feed).ms : null, uptime_24h: u.n24 ? r2((100 * u.ok24) / u.n24) : null, uptime_7d: u.n7 ? r2((100 * u.ok7) / u.n7) : null,
    checks_24h: u.n24, p50_ms: u.p50_ms, last_ok: u.last_ok, last_fail: u.last_fail, failing_streak: (streak.get(u.feed) || { n: 0 }).n }))
    .concat(runs.map((r) => ({ kind: 'job', job: r.job, last_run: r.started_at, ms: r.ms, ok: r.ok, error: r.error, runs_24h: (fmap.get(r.job) || {}).runs_24h || 0, failed_24h: (fmap.get(r.job) || {}).failed_24h || 0, failed_24h_all: (fmap.get(r.job) || {}).failed_24h_all || 0, version: VERSION })))
    .concat((vol || []).map((v) => ({ kind: 'volume', ...volumeFlag(v) })));
  // Additive fields: "state" on feed rows (up, down, known_gap) and on volume rows of gap sources, a "gap" note, and the
  // down and known_gaps lists. "ok" keeps its meaning (the raw check), so readers of the earlier shape are unaffected.
  for (const r of rows) {
    if (r.kind === 'feed') {
      r.state = feedState(r);
      if (r.state === 'known_gap') r.gap = KNOWN_GAPS[r.feed].note;
    } else if (r.kind === 'volume' && KNOWN_GAP_VOLUME[r.feed] && !(r.n > 0)) { r.state = 'known_gap'; r.gap = 'held at zero by a documented gap (' + KNOWN_GAP_VOLUME[r.feed] + ')'; }
  }
  const down = rows.filter((r) => r.kind === 'feed' && r.state === 'down').map((r) => r.feed);
  const known_gaps = rows.filter((r) => r.kind === 'feed' && r.state === 'known_gap').map((r) => r.feed);
  return { source: 'threat-feeds collector health checks', generated: new Date().toISOString(), checked_at: at, infocon, served_from: 'store', down, known_gaps, count: rows.length, rows };
}

// ---------------------------------------------------------------- last-good copies of the live endpoints
export async function jobSnap(opts = {}) {
  const t0 = Date.now(), out = {};
  // Lanes and OFAC change at most a few times a day: scheduled runs read them at the :04 run only (hourly), manual
  // runs always.
  const hourly = opts.holder !== 'cron' || new Date().getUTCMinutes() < 30;
  const ctxGet = (u) => get(u, { timeout: 25000, headers: { accept: 'text/html,application/xhtml+xml,text/csv,application/rss+xml;q=0.9,*/*;q=0.8' } });
  const tasks = {
    'snap-ransomware': async () => {
      const r = await get('https://api.ransomware.live/v2/recentvictims', { as: 'json', timeout: 25000 });
      if (!r.ok || !r.json) throw new Error('ransomware.live HTTP ' + r.status);
      const arr = Array.isArray(r.json) ? r.json : (r.json.data || []);
      const rows = arr.map((v) => ({ group: String(v.group_name || v.group || '').toLowerCase(), country: v.country || '', sector: v.activity || v.sector || '',
        discovered: String(v.discovered || v.published || '').slice(0, 19), published: String(v.published || '').slice(0, 19) }));
      return { source: 'ransomware.live', type: 'recentvictims', generated: new Date().toISOString(), count: rows.length, rows };
    },
    'snap-cyberattacks': async () => {
      // Normalized by 35-cyber.mjs, the same code /api/ransomware runs; an empty answer keeps the last good copy.
      const r = await get('https://api.ransomware.live/v2/recentcyberattacks', { as: 'json', timeout: 25000 });
      if (!r.ok || !r.json) throw new Error('ransomware.live HTTP ' + r.status);
      const doc = cyberattackDoc(Array.isArray(r.json) ? r.json : (r.json.data || []));
      if (!doc.count) throw new Error('ransomware.live recentcyberattacks returned no rows');
      return doc;
    },
    'snap-epss': async () => {
      const r = await get('https://api.first.org/data/v1/epss?envelope=false&limit=200&order=!epss', { as: 'json', timeout: 20000 });
      if (!r.ok || !r.json) throw new Error('EPSS HTTP ' + r.status);
      const data = Array.isArray(r.json) ? r.json : (r.json.data || []);
      const rows = data.map((d) => ({ cve: d.cve, epss: Number(d.epss), percentile: Number(d.percentile), date: d.date }));
      return { source: 'FIRST EPSS', generated: new Date().toISOString(), count: rows.length, rows };
    },
    'snap-threatfox': async () => {
      const r = await abuseFetch('ioc');
      if (r.gated) throw new Error(ABUSE_GATE);
      if (!r.ok || !r.json) throw new Error('ThreatFox HTTP ' + r.status);
      if (r.json.query_status && !['ok', 'no_results'].includes(r.json.query_status)) throw new Error('ThreatFox query_status ' + String(r.json.query_status).slice(0, 60));
      const items = Array.isArray(r.json.data) ? r.json.data.map((d) => [d && d.id, d]) : Object.entries(r.json).map(([id, arr]) => [id, Array.isArray(arr) ? arr[0] : arr]);
      const rows = [];
      for (const [id, d] of items) if (d) rows.push({ id: String(id), type: d.ioc_type, threat: d.threat_type, malware: d.malware_printable, confidence: d.confidence_level, first_seen: d.first_seen_utc || d.first_seen });
      rows.sort((a, b) => String(b.first_seen).localeCompare(String(a.first_seen)));
      return { source: 'abuse.ch ThreatFox (authenticated API, one day)', generated: new Date().toISOString(), total: rows.length, count: Math.min(400, rows.length), rows: rows.slice(0, 400) };
    },
    // Context feeds (36-context.mjs, shared with /api/context): Lanes relationship temperatures and OFAC Recent Actions.
    ...(hourly ? {
      'snap-lanes': () => fetchLanes(ctxGet),
      'snap-ofac': async () => enrichOfacDoc(await fetchOfac(ctxGet), ctxGet),
    } : {}),
  };
  await Promise.all(Object.entries(tasks).map(async ([name, fn]) => {
    try { const doc = await fn(); out[name] = { ok: true, rows: doc.count, ...(await putDoc(name, doc)) }; } catch (e) { out[name] = { ok: false, error: String(e.message || e) }; }
  }));
  await recordVolume(Object.entries(out).filter(([, v]) => v.ok).map(([k, v]) => [k, v.rows]));
  if (!Object.values(out).some((x) => x.ok)) throw new Error('no snapshot succeeded: ' + JSON.stringify(out));
  return { ...out, ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- IODA internet outages
// Events API: one record per detected outage on an entity (country) with start, duration and a score per signal.
export function parseIoda(j) {
  const arr = Array.isArray(j) ? j : j && Array.isArray(j.data) ? j.data : j && j.data && Array.isArray(j.data.events) ? j.data.events : [];
  const out = [];
  for (const e of arr) {
    const loc = String(e.location || e.entity || (e.entity_code ? 'country/' + e.entity_code : '') || '');
    const m = loc.match(/country[/:]([A-Za-z]{2})/) || (e.entityType === 'country' && e.entityCode ? [null, e.entityCode] : null);
    if (!m) continue;
    const start = +(e.start || e.from || e.time || 0), dur = +(e.duration || 0);
    if (!start) continue;
    out.push({ cc: m[1].toUpperCase(), name: e.location_name || e.entityName || e.name || '', start_at: new Date(start * 1000).toISOString(),
      end_at: dur ? new Date((start + dur) * 1000).toISOString() : null, score: +(e.score || e.overall_score || 0) || null, datasource: e.datasource || e.method || '',
      level: e.level || (e.score >= 10000 ? 'critical' : e.score >= 1000 ? 'warning' : 'normal') });
  }
  return out;
}
export async function jobIoda() {
  const t0 = Date.now(), until = Math.floor(Date.now() / 1000), from = until - 7 * 86400;
  const r = await get(`https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events?from=${from}&until=${until}&entityType=country&includeAlerts=false&format=codf&limit=2000`, { as: 'json', timeout: 30000 });
  if (!r.ok || !r.json) throw new Error('IODA HTTP ' + r.status + (r.error ? ' ' + r.error : ''));
  const seen = new Map();
  for (const e of parseIoda(r.json)) {
    const k = e.cc + '|' + e.datasource + '|' + e.start_at;
    const prev = seen.get(k);
    if (!prev || (e.score || 0) > (prev.score || 0)) seen.set(k, e);
  }
  const events = [...seen.values()];
  if (events.length) {
    await sql(`INSERT INTO ti.disruption (source, entity, start_at, end_at, cc, name, level, score, datasource, detail, last_obs)
      SELECT 'ioda', 'country/' || cc || '/' || coalesce(nullif(datasource, ''), 'all'), start_at, end_at, cc, name, level, score, datasource, NULL, now()
      FROM jsonb_to_recordset($1::jsonb) AS x(cc text, name text, start_at timestamptz, end_at timestamptz, score real, datasource text, level text)
      ON CONFLICT (source, entity, start_at) DO UPDATE SET end_at = EXCLUDED.end_at, score = EXCLUDED.score, level = EXCLUDED.level, datasource = EXCLUDED.datasource, last_obs = now()`, [events]);
  }
  const rows = (await sql(`SELECT cc, name, start_at, end_at, level, score, datasource FROM ti.disruption WHERE source = 'ioda' AND coalesce(end_at, now()) > now() - interval '7 days'
    ORDER BY start_at DESC LIMIT 400`)).map((x) => ({ kind: 'outage', ...x, ongoing: !x.end_at || Date.parse(x.end_at) > Date.now() - 900000 }));
  const doc = { source: 'IODA (Georgia Tech Internet Intelligence Lab) outage events, country level', generated: new Date().toISOString(), served_from: 'store', window_days: 7, count: rows.length, rows };
  return { events: events.length, rows: rows.length, published: await putDoc('ioda', doc), ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- retention
export async function jobRetention() {
  const t0 = Date.now();
  const r = await sqlTx([
    [`DELETE FROM ti.gdelt_cell WHERE slot < now() - make_interval(hours => $1)`, [KEEP_DETAIL_H]],
    [`DELETE FROM ti.gdelt_event WHERE slot < now() - make_interval(hours => $1)`, [KEEP_DETAIL_H]],
    [`DELETE FROM ti.gdelt_flow WHERE slot < now() - make_interval(hours => $1)`, [KEEP_DETAIL_H]],
    [`DELETE FROM ti.gdelt_country WHERE slot < now() - interval '120 days'`],
    [`DELETE FROM ti.gdelt_file WHERE slot < now() - interval '120 days'`],
    [`DELETE FROM ti.feed_check WHERE at < now() - interval '30 days'`],
    [`DELETE FROM ti.run WHERE started_at < now() - interval '30 days'`],
    [`DELETE FROM ti.infra WHERE last_obs < now() - interval '30 days'`],
    [`DELETE FROM ti.infra_daily WHERE day < (now() AT TIME ZONE 'UTC')::date - 400`],
    [`DELETE FROM ti.ip_geo WHERE fetched_at < now() - interval '60 days'`],
    [`DELETE FROM ti.disruption WHERE last_obs < now() - interval '90 days'`],
    [`DELETE FROM ti.fire_cell WHERE day < (now() AT TIME ZONE 'UTC')::date - 120`],
    [`DELETE FROM ti.feed_volume WHERE at < now() - interval '45 days'`],
    [`DELETE FROM ti.ip_list WHERE checked_at < now() - interval '7 days'`],
    [`DELETE FROM ti.blog_item WHERE seen_at < now() - interval '30 days'`],
    [`DELETE FROM ti.enrich WHERE at < now() - interval '7 days'`],
    [`DELETE FROM ti.mention WHERE published < now() - make_interval(days => $1)`, [ENTITY.KEEP_DAYS]],
    [`DELETE FROM ti.mdoc WHERE published < now() - make_interval(days => $1)`, [ENTITY.KEEP_DAYS]],
    [`SELECT pg_database_size(current_database())::bigint AS bytes`],
  ]);
  return { db_bytes: r[r.length - 1][0] && r[r.length - 1][0].bytes, ms: Date.now() - t0 };
}

// The ids of every upstream the health job checks (for the data sources registry check, pipeline/check_data_sources.mjs).
export const HEALTH_FEED_IDS = () => PROBES.map((p) => p[0]);
