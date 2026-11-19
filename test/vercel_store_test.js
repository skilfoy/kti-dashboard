// Offline test of the Vercel endpoints' store-first, live and stale paths with a mocked collector and upstreams.
// node test/vercel_store_test.js <repository root>
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const assert = require('assert/strict');
const TF = path.resolve(process.argv[2] || '.');
const OPERATOR = 'threat-feeds-skilfoys-projects.vercel.app', PUBLIC = 'intel.example.org';
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };

const COLLECTOR = 'https://br-summer-scene-b8t048y2-ti.compute.c-14.us-east-1.aws.neon.tech';
const now = Date.now();
const iso = (minAgo) => new Date(now - minAgo * 60000).toISOString();
const docs = {
  'gdelt-w24b48': { source: 'store', generated: iso(5), latest: iso(20), served_from: 'store', coverage: 1, coverage_live: 1, hours: 24, baseline: 48,
    rows: [{ kind: 'country', iso2: 'UA', h: 0, n: 5, m: 9 }, ...Array.from({ length: 80 }, (_, i) => ({ kind: 'event', id: String(i), mentions: 100 - i, url: 'u' + i })),
      ...Array.from({ length: 140 }, (_, i) => ({ kind: 'flow', m: 500 - i, n: 1 })), { kind: 'base30', iso2: 'UA', days: 9, mean: 4, sd: 1 }] },
  threatmap: { source: 'store', generated: iso(10), served_from: 'store', rows: [{ kind: 'node', layer: 'c2', ip: '185.220.101.7', lat: 52.5, lon: 13.4, asn: 'AS64500' }, { kind: 'trend', d: '2026-10-17', layer: 'c2', n: 1 }] },
  health: { source: 'h', generated: iso(3), checked_at: iso(3), infocon: 'green', rows: [{ kind: 'feed', feed: 'epss', ok: true, uptime_24h: 100 }, { kind: 'job', job: 'gdelt', ok: true }] },
  'gdelt-series30': { source: 's', generated: iso(8), rows: [{ kind: 'series', iso2: 'UA', d: '2026-10-17', n: 40 }] },
  ioda: { source: 'i', generated: iso(8), rows: [{ kind: 'outage', cc: 'IR' }] },
  'snap-ransomware': { source: 'ransomware.live', type: 'recentvictims', generated: iso(20), count: 1, rows: [{ group: 'qilin', country: 'US' }] },
  'snap-cyberattacks': { source: 'ransomware.live', type: 'recentcyberattacks', generated: iso(40), count: 1, placed: 1, rows: [{ victim: 'Svedala kommun', cc: 'SE', cc_basis: 'code+domain', cc_feed: 'SW' }] },
  'snap-epss': { source: 'FIRST EPSS', generated: iso(20), count: 1, rows: [{ cve: 'CVE-1', epss: 0.9 }] },
  'snap-threatfox': { source: 'abuse.ch ThreatFox', generated: iso(20), count: 2, rows: [{ id: '1' }, { id: '2' }] },
  'snap-lanes': { source: 'Lanes News open data', type: 'lanes', generated: iso(30), latest_date: '2026-10-06', count: 1, rows: [{ conflict: 'russia-ukraine', t7: 0.7 }] },
  alerts: { source: 'KTI standing watches', generated: iso(5), rows: [{ kind: 'watch', watch: 'W-2A', pir: 'PIR-2' }, { kind: 'alert', id: 'A-1', watch: 'W-2A', pir: 'PIR-2', subject: 'cve:CVE-2026-1111',
    headline: 'CVE-2026-1111 added to CISA KEV <Ivanti> & more', title: 'CVE added to CISA KEV', opened_at: iso(30), links: [{ link: 'https://a.example/1', title: 'T', host: 'a.example' }] },
    { kind: 'alert', id: 'A-2', watch: 'W-7A', pir: 'PIR-7', subject: 'actor:G1015', headline: 'Scattered Spider arrests', opened_at: iso(60), links: [] }] },
  'snap-ofac': { source: 'OFAC', type: 'ofac', generated: iso(400), count: 1, rows: [{ id: '20261001', title: 'Old stored action' }] },
};
const state = { collectorDown: false, upstreamDown: new Set(), seenAuth: [], puts: [], cyberEmpty: false, enrichUrls: [] };
const resp = (status, body, headers = {}) => new Response(Buffer.isBuffer(body) || typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
global.fetch = async (url, opts = {}) => {
  const u = String(url);
  const h = Object.fromEntries(Object.entries(opts.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
  if (u.startsWith(COLLECTOR)) {
    state.seenAuth.push(h.authorization);
    if (state.collectorDown) return resp(503, { error: 'down' });
    if (h.authorization !== 'Bearer test.oidc.token') return resp(401, { error: 'unauthorized' });
    const p = new URL(u).pathname;
    if (p.startsWith('/doc/')) { const d = docs[decodeURIComponent(p.slice(5))]; return d ? resp(200, zlib.gzipSync(Buffer.from(JSON.stringify(d))), { 'x-doc-modified': 'now' }) : resp(404, { error: 'missing' }); }
    if (p === '/run') return resp(200, { jobs: [{ job: JSON.parse(opts.body).job, ok: true }] });
    if (p === '/status') return resp(200, { version: 'v', runs: [] });
    if (p === '/watch') { state.watchUrl = u; return resp(200, { since: iso(100), ids: ['actor:G1015'], items: [{ id: 'actor:G1015', n: 'Scattered Spider' }], events: [{ at: iso(10), entity: 'actor:G1015', entity_name: 'Scattered Spider', kind: 'entry', title: 'Arrest', link: 'https://b.example/2', host: 'b.example', via: 'Scattered Spider' }] }); }
    if (p === '/enrich') {
      state.enrichUrls.push(u);
      return resp(200, { ok: true, type: 'hash', q: 'a'.repeat(64), at: iso(0), results: [{ analyzer: 'hashlookup', label: 'CIRCL hashlookup', ok: true, data: { known: false } },
        { analyzer: 'mbazaar', label: 'abuse.ch MalwareBazaar', ok: true, data: { found: true } }, { analyzer: 'cl0q_ip', label: 'cl0q', ok: true, data: {} }] });
    }
    return resp(404, { error: 'not found' });
  }
  if (u.includes('.storage.c-14.us-east-1.aws.neon.tech/ti-docs/')) { state.puts.push({ u, bytes: Buffer.from(opts.body).length, type: h['content-type'] }); return resp(200, ''); }
  for (const d of state.upstreamDown) if (u.includes(d)) return resp(503, 'down');
  if (u.startsWith('https://feodotracker.abuse.ch/downloads/ipblocklist.json')) return resp(200, [{ ip_address: '185.220.101.7', port: 443, status: 'online', country: 'DE', as_name: 'X', first_seen: '2026-10-01 10:00:00', last_online: '2026-10-17', malware: 'QakBot' }]);
  // abuse.ch closed the keyless ThreatFox export on 21 October 2026.
  if (u.startsWith('https://threatfox.abuse.ch/export/json/recent/')) return resp(410, 'Gone');
  if (u.startsWith('https://isc.sans.edu/api/topips/records/')) return resp(200, [{ rank: 1, source: '045.148.010.240', reports: 120000, targets: 45000 }]);
  if (u.startsWith('http://ip-api.com/batch')) return resp(200, JSON.parse(opts.body).map((ip) => ({ status: 'success', query: ip, countryCode: 'DE', city: 'Berlin', lat: 52.5, lon: 13.4, as: 'AS1 X', asname: 'X' })), { 'x-rl': '10' });
  if (u.startsWith('https://api.ransomware.live/v2/recentcyberattacks')) return resp(200, state.cyberEmpty ? [] : [{ added: '2026-10-18', claim_gang: false, claim_url: false, country: 'KO', date: '2026-10-17',
    domain: 'boryungbio.co.kr', has_infostealer_info: true, infostealer_data: { employees: 2 }, link: 'https://www.ransomware.live/id/Ym9yeXVuZw==', summary: 'résumé', description: '',
    title: '보령바이오파마, 랜섬웨어 감염', url: 'https://www.dailypharm.com/news/1', victim: 'Boryung Biopharma' }]);
  if (u.startsWith('https://api.ransomware.live/')) return resp(200, [{ group_name: 'Akira', country: 'CA', activity: 'Manufacturing', discovered: '2026-10-17 10:00:00' }]);
  if (u.startsWith('https://api.first.org/')) return resp(200, [{ cve: 'CVE-2', epss: '0.5', percentile: '0.9', date: '2026-10-17' }]);
  if (u === 'https://ofac.treasury.gov/recent-actions') { assert.match(h.accept, /text\/html/); return resp(200, '<a href="/recent-actions/20261015">Iran-related Designations</a> October 15, 2026 - <a href="/recent-actions/sanctions-list-updates">Sanctions List Updates</a>'); }
  if (u === 'https://ofac.treasury.gov/recent-actions?page=1') return resp(200, '<a href="/recent-actions/20261008">Cyber-related Designations</a>');
  if (u === 'https://lanes.news/data/temperatures.csv') return resp(200, 'date,conflict,country_a,country_a_name,country_b,country_b_name,events,articles,goldstein_mean,tone_mean,verbal_cooperation_share,material_cooperation_share,verbal_conflict_share,material_conflict_share,temperature\n2026-10-06,usa-iran,IRN,Iran,USA,United States,615,3918,0.082,-3.659,0.6759,0.0151,0.2078,0.1013,0.267\n');
  if (u === 'https://lanes.news/feed.xml') return resp(200, '<rss><channel></channel></rss>');
  if (u.startsWith('http://data.gdeltproject.org/gdeltv2/lastupdate.txt')) return state.upstreamDown.has('gdelt') ? resp(503, '') : resp(200, 'x y http://data.gdeltproject.org/gdeltv2/20261017180000.export.CSV.zip');
  if (u.includes('data.gdeltproject.org')) return resp(404, '');
  if (u.startsWith('https://')) return resp(200, 'ok');
  throw new Error('unexpected ' + u);
};

function call(file, query, headers = { 'x-vercel-oidc-token': 'test.oidc.token' }, host = OPERATOR, method = 'GET') {
  headers = { host, ...headers };
  for (const k of Object.keys(require.cache)) if (k.startsWith(TF) && !k.endsWith('countries.js')) delete require.cache[k];
  const handler = require(path.join(TF, 'api', file));
  const qs = new URLSearchParams(query).toString();
  return new Promise((resolve) => {
    const res = { headers: {}, setHeader(k, v) { this.headers[k] = v; }, status(c) { this.code = c; return this; }, send(b) { let body = null; try { body = JSON.parse(b); } catch { /* Atom and other text */ } resolve({ code: this.code, headers: this.headers, body, raw: String(b) }); }, end() { resolve({ code: this.code }); } };
    handler({ method, query, headers, url: '/api/' + file.replace('.js', '') + (qs ? '?' + qs : '') }, res);
  });
}

(async () => {
  // GDELT: fresh store doc, trimmed by ?top and ?flows.
  let r = await call('gdelt-events.js', { hours: '24', baseline: '48', top: '10', flows: '20' });
  ok(r.code === 200 && r.body.served_from === 'store' && r.body.rows.filter((x) => x.kind === 'event').length === 10 && r.body.rows.filter((x) => x.kind === 'flow').length === 20, 'gdelt store-first trimmed');
  ok(r.body.rows.some((x) => x.kind === 'base30') && /s-maxage=600/.test(r.headers['Cache-Control']), 'base30 kept, 10-minute edge cache');
  ok(state.seenAuth.every((a) => a === 'Bearer test.oidc.token'), 'collector called with the OIDC bearer token');
  // Stale doc + live failure -> store-stale. Make the doc old.
  docs['gdelt-w24b48'].latest = iso(200);
  state.upstreamDown.add('gdelt');
  r = await call('gdelt-events.js', { hours: '24', baseline: '48' });
  ok(r.code === 200 && r.body.served_from === 'store-stale' && r.body.stale === true, 'gdelt stale fallback ' + r.body.served_from);
  state.upstreamDown.clear();
  // Non-standard window always computes live (no store read needed).
  r = await call('gdelt-events.js', { hours: '6' });
  ok(r.code === 200 && r.body.served_from === 'live', 'non-standard window is live');
  // No OIDC token: store unavailable, live path still serves.
  r = await call('gdelt-events.js', {}, {});
  ok(r.code === 200 && r.body.served_from === 'live', 'no token falls back to live');

  // Threat map: store, then live fallback, then stale.
  r = await call('threatmap.js', {});
  ok(r.code === 200 && r.body.served_from === 'store' && r.body.age_min === 10, 'threatmap store-first');
  r = await call('threatmap.js', { format: 'compact' });
  ok(r.code === 200 && r.body.format === 'compact-1' && r.body.nodes.length === 1 && r.body.nodes[0][1] === '185.220.101.7' && r.body.cols.length === r.body.nodes[0].length
    && r.body.dict.cc && !r.body.rows.some((x) => x.kind === 'node') && r.body.rows.some((x) => x.kind === 'trend') && r.body.count === r.body.rows.length, 'threatmap compact form');
  const vm = require('vm'), wire = {}; vm.runInNewContext(fs.readFileSync(path.join(TF, 'public', 'js', 'tfwire.js'), 'utf8'), { window: wire, atob, TextDecoder });
  r = await call('threatmap.js', { format: 'compact' });
  ok(r.code === 200 && r.body.format === 'compact-1' && r.body.nodes.length === 1 && r.body.nodes[0].length === r.body.cols.length && r.body.rows.every((x) => x.kind !== 'node')
    && r.body.rows.some((x) => x.kind === 'trend'), 'threatmap compact keeps non-node rows');
  ok(r.body.cols.includes('asn') && wire.TI_WIRE.threatmapNodes(r.body)[0].asn === 'AS64500', 'AS number travels in the compact form');
  ok(['lb', 'ipsum', 'cred', 'rel', 'sc', 'rsit', 'obs'].every((c) => r.body.cols.includes(c)) && r.body.nodes[0].length === r.body.cols.length, 'corroboration, credibility, RSIT and observation columns');
  r = await call('threatmap.js', { format: 'compact', live: '1' });
  const full = await call('threatmap.js', { live: '1' });
  const dec = wire.TI_WIRE.threatmapNodes(r.body), want = full.body.rows.filter((x) => x.kind === 'node');
  ok(dec.length === want.length && dec.every((n, i) => n.ip === want[i].ip && n.layer === want[i].layer && n.family === want[i].family && n.ref === want[i].ref
    && n.first_seen === (want[i].first_seen ? new Date(Math.round(Date.parse(want[i].first_seen) / 60000) * 60000).toISOString() : null) && n.cc === (want[i].cc || '') && n.asn === (want[i].asn || '')),
    'compact round trip ' + JSON.stringify(dec[1]) + ' vs ' + JSON.stringify(want[1]));
  r = await call('threatmap.js', { format: 'compact', enc: 'deflate64' });
  const plain = await call('threatmap.js', { format: 'compact' });
  const un = wire.TI_WIRE.unpack(r.body);
  ok(r.code === 200 && r.body.enc === 'deflate-raw+base64' && r.body.served_from === 'store' && !r.body.rows && JSON.stringify(un) === JSON.stringify(plain.body), 'deflate64 round trip');
  r = await call('gdelt-events.js', { hours: '24', baseline: '48', enc: 'deflate64' });
  const g2 = wire.TI_WIRE.unpack(r.body);
  ok(r.code === 200 && g2.rows.filter((x) => x.kind === 'flow').length === 140 && r.body.data.length < JSON.stringify(g2).length, 'gdelt packed ' + r.body.data.length + ' < ' + JSON.stringify(g2).length);
  r = await call('history.js', { kind: 'nope', enc: 'deflate64' });
  ok(r.code === 400 && r.body.error && !r.body.enc, 'errors are never packed');
  r = await call('threatmap.js', { live: '1' });
  ok(r.code === 200 && r.body.served_from === 'live' && r.body.rows.filter((x) => x.kind === 'node').length === 2 && r.body.layers.c2.ok && r.body.layers.src.ok && !r.body.layers.ioc.ok && !r.body.layers.url.ok
    && /Auth-Key/.test(r.body.note), 'threatmap live path: Feodo and DShield, abuse.ch gate noted ' + JSON.stringify(r.body.layers.c2));
  r = await call('threatmap.js', { live: '1', format: 'compact' });
  const c2Node = r.body.nodes.find((a) => a[0] === 0), srcNode = r.body.nodes.find((a) => a[0] === 2);
  ok(r.code === 200 && r.body.served_from === 'live' && r.body.nodes.length === 2 && c2Node && srcNode && r.body.dict.family[c2Node[8]] === 'QakBot', 'threatmap live compact keeps layer and family');
  docs.threatmap.generated = iso(500);
  state.upstreamDown.add('feodotracker'); state.upstreamDown.add('isc.sans.edu');
  r = await call('threatmap.js', {});
  ok(r.code === 200 && r.body.served_from === 'store-stale' && r.body.stale && /Feodo HTTP 503/.test(r.body.live_error), 'threatmap stale fallback');
  state.collectorDown = true;
  r = await call('threatmap.js', {});
  ok(r.code === 502, 'threatmap 502 when everything is down');
  state.collectorDown = false; state.upstreamDown.clear(); docs.threatmap.generated = iso(10);

  // History.
  for (const [kind, n] of [['conflict', 1], ['infra', 1], ['uptime', 2], ['outages', 1]]) {
    r = await call('history.js', { kind });
    ok(r.code === 200 && r.body.rows.length === n && r.body.kind === kind, 'history ' + kind);
  }
  ok((await call('history.js', { kind: 'nope' })).code === 400, 'history kind validated');

  // Health merges the collector record.
  r = await call('health.js', {});
  ok(r.code === 200 && r.body.collector.ok && r.body.collector.infocon === 'green' && r.body.collector.feeds.length === 1 && r.body.oidc === true && r.body.upstreams.feodo && !('gdelt_doc_api' in r.body.upstreams)
    && r.body.upstreams.threatfox.status === 410 && /21 Oct 2026/.test(r.body.upstreams.threatfox.error), 'health with collector, no DOC API probe, ThreatFox closure stated');
  ok(r.body.collector.down === null && r.body.collector.known_gaps === null, 'a collector record without the gap lists reads null for both');
  docs.health.down = ['epss']; docs.health.known_gaps = ['marad_msci'];
  docs.health.rows.push({ kind: 'feed', feed: 'marad_msci', ok: false, status: 403, state: 'known_gap', gap: 'refused (HTTP 403)' });
  r = await call('health.js', {});
  ok(JSON.stringify(r.body.collector.down) === '["epss"]' && JSON.stringify(r.body.collector.known_gaps) === '["marad_msci"]'
    && r.body.collector.feeds.find((f) => f.feed === 'marad_msci').state === 'known_gap' && r.body.collector.feeds.find((f) => f.feed === 'epss').ok === true,
    'health passes the down and known_gaps lists and feed states through, other fields unchanged');
  docs.health.rows = docs.health.rows.filter((f) => f.feed !== 'marad_msci'); delete docs.health.down; delete docs.health.known_gaps;
  docs.health.rows.push({ kind: 'feed', feed: 'threatfox', ok: true, status: 200, ms: 240, last_ok: iso(3), failing_streak: 0 });
  r = await call('health.js', {});
  ok(r.body.upstreams.threatfox.ok === true && r.body.upstreams.threatfox.via === 'collector (Auth-Key)', 'ThreatFox status from the collector\'s authenticated check');
  docs.health.checked_at = iso(200);
  r = await call('health.js', {});
  ok(r.body.upstreams.threatfox.ok === false && r.body.upstreams.threatfox.status === 410, 'a stale collector check falls back to the closure note');
  docs.health.checked_at = iso(3); docs.health.rows.pop();
  // Uptime monitors probe with HEAD; it answers as GET does (Node drops the body), and writes stay refused.
  r = await call('health.js', {}, undefined, OPERATOR, 'HEAD');
  ok(r.code === 200 && r.body.service === 'threat-feeds', 'HEAD on health answers as GET');
  r = await call('health.js', {}, undefined, OPERATOR, 'POST');
  ok(r.code === 405 && r.body.error === 'method_not_allowed', 'POST is refused with 405');

  // Stale fallbacks for the dashboard's default live calls.
  state.upstreamDown.add('api.ransomware.live'); state.upstreamDown.add('api.first.org'); state.upstreamDown.add('threatfox.abuse.ch');
  r = await call('ransomware.js', { type: 'recentvictims' });
  ok(r.code === 200 && r.body.served_from === 'store-stale' && r.body.rows[0].group === 'qilin', 'ransomware stale');
  r = await call('epss.js', { limit: '200' });
  ok(r.code === 200 && r.body.served_from === 'store-stale', 'epss stale');
  r = await call('epss.js', { cve: 'CVE-2026-1' });
  ok(r.code === 502, 'epss named-CVE lookups have no stale copy');
  r = await call('abusech.js', { feed: 'threatfox', limit: '1', summary: '1' });
  ok(r.code === 200 && r.body.served_from === 'store' && r.body.rows.length === 1, 'threatfox from the collector copy, limit honoured');
  const tfGen = docs['snap-threatfox'].generated;
  docs['snap-threatfox'].generated = iso(2000);
  r = await call('abusech.js', { feed: 'threatfox' });
  ok(r.code === 503 && r.body.gated && /Auth-Key/.test(r.body.error), 'a day-old ThreatFox copy is not served as current');
  docs['snap-threatfox'].generated = tfGen;
  state.upstreamDown.clear();
  r = await call('ransomware.js', { type: 'recentvictims' });
  ok(r.code === 200 && !r.body.served_from && r.body.rows[0].group === 'akira', 'ransomware live when up');
  // Press-reported cyberattacks: normalized live, last-good copy when the upstream fails or returns nothing.
  r = await call('ransomware.js', { type: 'recentcyberattacks' });
  ok(r.code === 200 && !r.body.served_from && r.body.count === 1 && r.body.rows[0].cc === 'KR' && r.body.rows[0].cc_basis === 'code+domain' && r.body.rows[0].cc_feed === 'KO'
    && r.body.placed === 1 && /s-maxage=600/.test(r.headers['Cache-Control']) && !/infostealer|résumé|boryungbio/.test(JSON.stringify(r.body)), 'cyberattacks live and normalized');
  const packed = await call('ransomware.js', { type: 'recentcyberattacks', enc: 'deflate64' });
  ok(packed.code === 200 && packed.body.enc === 'deflate-raw+base64' && wire.TI_WIRE.unpack(packed.body).rows[0].cc === 'KR', 'cyberattacks packed');
  state.cyberEmpty = true;
  r = await call('ransomware.js', { type: 'recentcyberattacks' });
  ok(r.code === 200 && r.body.served_from === 'store-stale' && r.body.upstream_note === 'upstream returned no rows' && r.body.rows[0].cc === 'SE', 'cyberattacks empty answer keeps the last good copy');
  state.cyberEmpty = false; state.upstreamDown.add('api.ransomware.live');
  r = await call('ransomware.js', { type: 'recentcyberattacks' });
  ok(r.code === 200 && r.body.served_from === 'store-stale' && r.body.age_min === 40 && r.body.rows[0].victim === 'Svedala kommun', 'cyberattacks stale');
  r = await call('ransomware.js', { type: 'groups' });
  ok(r.code === 502, 'groups have no stale copy');
  state.upstreamDown.clear();

  // Context feeds through the index function (/api/context is rewritten to /api/index?route=context).
  r = await call('index.js', { route: 'context', type: 'lanes' });
  ok(r.code === 200 && r.body.served_from === 'store' && r.body.age_min === 30 && r.body.rows[0].conflict === 'russia-ukraine' && /s-maxage=300/.test(r.headers['Cache-Control']), 'lanes store-first');
  r = await call('index.js', { route: 'context', type: 'ofac' });
  ok(r.code === 200 && r.body.served_from === 'live' && r.body.count === 2 && r.body.rows[0].id === '20261015' && r.body.rows[0].theaters === 'T-HRM' && r.body.rows[1].cyber === 'Yes' && r.body.pages_read === 2, 'ofac read live when the stored copy is past its window ' + JSON.stringify(r.body).slice(0, 200));
  state.upstreamDown.add('ofac.treasury.gov');
  r = await call('index.js', { route: 'context', type: 'ofac' });
  ok(r.code === 200 && r.body.served_from === 'store-stale' && r.body.stale && r.body.age_min === 400 && /HTTP 503/.test(r.body.upstream_note), 'ofac stale copy when OFAC is down');
  state.upstreamDown.add('lanes.news');
  r = await call('index.js', { route: 'context', type: 'lanes', live: '1' });
  ok(r.code === 200 && r.body.served_from === 'store-stale' && r.body.rows[0].conflict === 'russia-ukraine', 'lanes live=1 falls back to the stored copy');
  const keep = docs['snap-ofac']; delete docs['snap-ofac'];
  r = await call('index.js', { route: 'context', type: 'ofac' });
  ok(r.code === 502 && r.body.store === 'missing', 'no copy and no upstream is a 502');
  docs['snap-ofac'] = keep; state.upstreamDown.clear();
  r = await call('index.js', { route: 'context', type: 'lanes', live: '1' });
  ok(r.code === 200 && r.body.served_from === 'live' && r.body.rows[0].a2 === 'IR' && r.body.license === 'CC BY 4.0', 'lanes live');
  r = await call('index.js', {});
  ok(r.code === 200 && r.body.endpoints.some((e) => e.startsWith('/api/context?type=lanes|ofac|fires')) && r.body.endpoints.some((e) => e.startsWith('/api/enrich')), 'index lists the context and enrich routes');
  // Store-only context types: served from the collector's document, marked stale past their window, 502 when never collected.
  docs.fires = { source: 'NASA FIRMS', generated: new Date(Date.now() - 20 * 60000).toISOString(), aois: [], count: 0, rows: [] };
  r = await call('index.js', { route: 'context', type: 'fires' });
  ok(r.code === 200 && r.body.served_from === 'store' && r.body.source === 'NASA FIRMS', 'fires served from the store');
  docs.fires.generated = new Date(Date.now() - 600 * 60000).toISOString();
  r = await call('index.js', { route: 'context', type: 'fires' });
  ok(r.code === 200 && r.body.served_from === 'store-stale' && r.body.stale === true, 'old fires copy marked stale');
  r = await call('index.js', { route: 'context', type: 'maritime' });
  ok(r.code === 502 && r.body.error === 'not collected yet', 'uncollected store-only type is a 502');
  r = await call('index.js', { route: 'enrich', type: 'nope', q: 'x' });
  ok(r.code === 400, 'enrich refuses an unknown type before calling the collector');

  // Admin.
  r = await call('admin.js', { op: 'whoami' }, { 'x-vercel-oidc-token': 'e30.' + Buffer.from(JSON.stringify({ iss: 'https://oidc.vercel.com/skilfoys-projects', project_id: 'prj_x', environment: 'production' })).toString('base64url') + '.sig' });
  ok(r.code === 200 && r.body.oidc && r.body.claims.environment === 'production' && /no-store/.test(r.headers['Cache-Control']), 'admin whoami');
  r = await call('admin.js', { op: 'sha' });
  const built = require('crypto').createHash('sha256').update(fs.readFileSync(path.join(TF, 'neon', 'collector.mjs'))).digest('hex');
  ok(r.code === 200 && r.body.assets.code.sha256 === built && r.body.assets.atlas.bytes > 500000, 'admin sha is the joined parts, identical to the tested build');
  r = await call('admin.js', { op: 'push', asset: 'code', u: 'https://evil.example/ti-docs/code/collector.mjs?sig=1' });
  ok(r.code === 400, 'push refuses foreign hosts');
  r = await call('admin.js', { op: 'push', asset: 'code', u: 'https://br-summer-scene-b8t048y2.storage.c-14.us-east-1.aws.neon.tech/ti-docs/ref/num2iso.json?sig=1' });
  ok(r.code === 400, 'push refuses a URL for a different object');
  r = await call('admin.js', { op: 'push', asset: 'code', u: 'https://br-summer-scene-b8t048y2.storage.c-14.us-east-1.aws.neon.tech/ti-docs/code/collector.mjs?X-Amz-Signature=abc' });
  ok(r.code === 200 && r.body.sha256 === built && state.puts.length === 1 && state.puts[0].type === 'text/javascript', 'push uploads the collector');
  r = await call('admin.js', { op: 'run', job: 'gdelt', backfill: '1' });
  ok(r.code === 200 && r.body.jobs[0].job === 'gdelt', 'run relayed');
  r = await call('admin.js', { op: 'doc', name: 'threatmap', kind: 'node', n: '5' });
  ok(r.code === 200 && r.body.kinds.node === 1 && r.body.sample.length === 1 && !r.body.rows, 'doc summary');

  // ---------------------------------------------------------------- the public host
  r = await call('admin.js', { op: 'whoami' }, undefined, PUBLIC);
  ok(r.code === 404 && r.body.error === 'not_found', 'admin does not exist on the public host');
  r = await call('admin.js', { op: 'push', asset: 'code', u: 'https://br-summer-scene-b8t048y2.storage.c-14.us-east-1.aws.neon.tech/ti-docs/code/collector.mjs?X-Amz-Signature=abc' }, undefined, PUBLIC);
  ok(r.code === 404 && state.puts.length === 1, 'admin push refused on the public host, nothing uploaded');
  r = await call('admin.js', { op: 'whoami' }, undefined, 'threat-feeds.vercel.app.example.org');
  ok(r.code === 404, 'a host that only contains vercel.app is public');
  r = await call('index.js', {}, undefined, PUBLIC);
  ok(r.code === 200 && !r.body.endpoints.some((e) => e.startsWith('/api/admin')), 'public index lists no operator route');
  r = await call('index.js', {});
  ok(r.body.endpoints.some((e) => e.startsWith('/api/admin')), 'operator index lists admin');
  ok(r.headers['Access-Control-Allow-Origin'] === '*', 'responses readable from any origin');
  docs.threatmap.generated = iso(10);
  docs.threatmap.rows.push({ kind: 'node', layer: 'ioc', ip: '203.0.113.9', port: 8080, lat: 1, lon: 2, family: 'Lumma', ref: 'https://threatfox.abuse.ch/ioc/1500000/' },
    { kind: 'node', layer: 'url', ip: '198.51.100.4', lat: 3, lon: 4, ref: 'https://urlhaus.abuse.ch/url/3300000/' });
  r = await call('threatmap.js', { format: 'compact' }, undefined, PUBLIC);
  ok(['203.0.113.9', '198.51.100.4', '185.220.101.7'].every((ip) => r.body.nodes.some((n) => n[1] === ip)), 'public threatmap carries every address');
  r = await call('index.js', { route: 'enrich', type: 'hash', q: 'a'.repeat(64) }, undefined, PUBLIC);
  ok(r.code === 200 && !/keyless/.test(state.enrichUrls.at(-1)) && r.body.results.length === 3, 'public enrichment reads every analyzer');
  // Standing watches (3.5.0): alerts as JSON filtered by PIR and as Atom; a visitor's watchlist relayed to the collector.
  r = await call('index.js', { route: 'alerts', pir: 'pir-2' }, undefined, PUBLIC);
  ok(r.code === 200 && r.body.rows.filter((x) => x.kind === 'alert').length === 1 && r.body.rows.some((x) => x.kind === 'watch'), 'alerts filtered by PIR, watches kept');
  r = await call('index.js', { route: 'alerts', format: 'atom' }, undefined, PUBLIC);
  ok(r.code === 200 && /^<\?xml/.test(r.raw) && (r.raw.match(/<entry>/g) || []).length === 2 && r.raw.includes('&lt;Ivanti&gt; &amp; more') && /application\/atom\+xml/.test(r.headers['Content-Type']), 'alerts as an Atom feed, escaped');
  r = await call('index.js', { route: 'watch', ids: 'actor:G1015,not an id', since: '2026-11-01T00:00:00Z' }, undefined, PUBLIC);
  ok(r.code === 200 && /ids=actor%3AG1015&days=30&since=2026-11-01/.test(state.watchUrl) && r.body.events.length === 1, 'watchlist relayed with valid ids only ' + state.watchUrl);
  r = await call('index.js', { route: 'watch', ids: 'actor:G1015', format: 'atom' }, undefined, PUBLIC);
  ok(r.code === 200 && r.raw.includes('<title>KTI watchlist: Scattered Spider</title>') && r.raw.includes('Scattered Spider: Arrest'), 'watchlist as an Atom feed');
  r = await call('index.js', { route: 'watch', ids: 'nope' }, undefined, PUBLIC);
  ok(r.code === 400, 'watchlist needs entity ids');
  console.log(`PASS ${pass} checks`);
})().catch((e) => { console.error(e); process.exit(1); });
