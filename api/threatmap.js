const { handle, sendJson, q } = require('./_lib');
const store = require('../lib/store');

// Cyber threat map layers: reported malicious infrastructure placed by IP geolocation, for defenders' situational
// awareness. Nothing here touches the listed hosts; every row comes from a public blocklist or sensor report.
//   1. The collector's threatmap document (refreshed every 30 minutes): abuse.ch Feodo Tracker botnet C2, ThreatFox
//      ip:port indicators, SANS ISC DShield top attacking sources and URLhaus online malware hosts, with geolocation
//      from a persistent cache (ip-api.com, GeoJS), first-observed times and 30 days of daily counts.
//   2. If that document is missing or older than two hours, a smaller live map: Feodo and DShield only, at most 200
//      addresses geolocated through ip-api.com.
//   3. If the live map fails too, the last stored document, marked stale.
// ?live=1 skips the stored document. ?format=compact sends map nodes as arrays against a column list, with repeated
// strings (country, city, AS name, family, threat, status, AS number) as indexes into dictionaries, times as epoch
// minutes and the abuse.ch record number in place of the reference URL; the dashboard map reads that form.
const LAYERS = ['c2', 'ioc', 'src', 'url'];
// Since collector 2026-10-22.1 each node also carries its corroboration lists (lb, comma-joined list ids), the IPsum
// count, Admiralty credibility (cred 1-3) and reliability (rel), the item score (sc), the RSIT classification (rsit) and
// the collector's first observation (obs, epoch minutes); flags bit 4 marks a Tor exit relay.
const DICT = ['cc', 'city', 'as_name', 'family', 'threat', 'status', 'asn', 'lb', 'rel', 'rsit'];
const COLS = ['layer', 'ip', 'port', 'lat', 'lon', 'cc', 'city', 'as_name', 'family', 'threat', 'status', 'confidence', 'count', 'first_seen', 'last_seen', 'flags', 'rec', 'tags', 'asn',
  'lb', 'ipsum', 'cred', 'rel', 'sc', 'rsit', 'obs'];

function compact(doc) {
  const dict = Object.fromEntries(DICT.map((k) => [k, []])), idx = Object.fromEntries(DICT.map((k) => [k, new Map()]));
  const code = (k, v) => {
    if (v == null || v === '') return -1;
    let i = idx[k].get(v);
    if (i == null) { i = dict[k].length; dict[k].push(v); idx[k].set(v, i); }
    return i;
  };
  const minutes = (s) => { const t = s ? Date.parse(s) : NaN; return isFinite(t) ? Math.round(t / 60000) : null; };
  const nodes = [], rows = [];
  for (const r of doc.rows || []) {
    if (r.kind !== 'node') { rows.push(r); continue; }
    const m = String(r.ref || '').match(/\/(?:ioc|url)\/(\d+)\/?$/);
    nodes.push([LAYERS.indexOf(r.layer), r.ip, r.port || 0, r.lat, r.lon, code('cc', r.cc), code('city', r.city), code('as_name', r.as_name), code('family', r.family),
      code('threat', r.threat), code('status', r.status), r.confidence ?? null, r.count ?? null, minutes(r.first_seen), minutes(r.last_seen),
      (r.new ? 1 : 0) | (r.stale ? 2 : 0) | (r.tor ? 4 : 0), m ? +m[1] : null, r.tags || null, code('asn', r.asn),
      code('lb', r.lb), r.ipsum ?? null, r.cred ?? null, code('rel', r.rel), r.sc ?? null, code('rsit', r.rsit), minutes(r.obs)]);
  }
  const { rows: _all, count: _c, ...head } = doc;
  return { ...head, format: 'compact-1', layer_codes: LAYERS, cols: COLS, dict, nodes, count: rows.length, rows };
}

module.exports = handle(async (req, res) => {
  const fmt = q(req, 'format', '') === 'compact' ? compact : (d) => d;
  let stale = null;
  if (q(req, 'live', '') !== '1') {
    const s = await store.getDoc(req, 'threatmap');
    if (s.ok && store.ageMin(s.doc.generated) <= 120) return sendJson(res, 200, fmt({ ...s.doc, age_min: Math.round(store.ageMin(s.doc.generated)) }), 300, 1800);
    if (s.ok) stale = s.doc;
  }
  try {
    const C = await require('../lib/collector').load();
    // abuse.ch closed the keyless ThreatFox and URLhaus exports on 21 October 2026, and their keys stay off Vercel, so the
    // live fallback draws the two keyless layers: Feodo Tracker C2 and DShield top sources.
    const fetched = { ioc: { ok: false, status: 410, rows: [], gated: true }, url: { ok: false, status: 410, rows: [], gated: true } };
    await Promise.all([['c2', 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', C.parseFeodo], ['src', 'https://isc.sans.edu/api/topips/records/100?json', C.parseDShield]]
      .map(async ([layer, url, parse]) => {
        const r = await C.get(url, { as: 'json', timeout: 20000 });
        const rows = r.ok ? parse(r.json) : [];
        fetched[layer] = { ok: r.ok && rows.length > 0, status: r.status, rows };
      }));
    if (!fetched.c2.ok && !fetched.src.ok) throw new Error(`Feodo HTTP ${fetched.c2.status}, DShield HTTP ${fetched.src.status}`);
    const listed = [...fetched.c2.rows, ...fetched.src.rows];
    const ips = [...new Set(listed.map((x) => x.ip))].slice(0, 200);
    const g = await C.geolocate(ips, { maxIpApi: 2 });
    const nodes = listed.map(({ as_feed, ...x }) => {
      const geo = g.geo.get(x.ip) || {};
      return { ...x, cc: geo.cc || x.cc_feed || '', lat: geo.ok ? geo.lat : null, lon: geo.ok ? geo.lon : null, city: geo.city || '', asn: geo.asn || '', as_name: geo.as_name || as_feed || '', first_obs: null, stale: false };
    });
    const doc = C.buildThreatmap({ nodes, fetched, trend: [], geoStats: { cached: 0, looked_up: g.geo.size, ipapi_calls: g.ipapi_calls, rate_limited: g.limited, pending: Math.max(0, ips.length - g.geo.size) } });
    return sendJson(res, 200, fmt({ ...doc, served_from: 'live', note: 'Live fallback: Feodo C2 and DShield sources only. ThreatFox and URLhaus need an abuse.ch Auth-Key since 21 October 2026 and come from the collector when one is set.', store_error: stale ? undefined : 'no stored document' }), 300, 1800);
  } catch (e) {
    if (stale) return sendJson(res, 200, fmt({ ...stale, served_from: 'store-stale', stale: true, age_min: Math.round(store.ageMin(stale.generated)), live_error: String(e.message || e) }), 120, 600);
    return sendJson(res, 502, { error: 'threatmap unavailable', detail: String(e.message || e) }, 0);
  }
});
module.exports.compact = compact;
