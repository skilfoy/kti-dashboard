// ---------------------------------------------------------------- submarine cables (open data), weekly
// The reserved lease row 'cables' (planned since G26) now runs this job on Sundays at 05:19 UTC. Sources, open data only
// (TeleGeography's geocoded data is an annual paid licence and is not used or called):
//   OSM       OpenStreetMap through Overpass: ways tagged communication=line + location=underwater, and nodes tagged
//             telecom=cable_landing_station. ODbL 1.0, attribution "© OpenStreetMap contributors". Coverage is partial
//             (on 2 November 2026: 374 ways, 189 named, 12 landing stations).
//   Wikidata  SPARQL, items of class Q506572 (submarine communications cable): owner (P127), length (P2043), service
//             entry (P729) or inception (P571). CC0. Joined onto OSM ways by exact normalised name only; an unmatched or
//             ambiguous name stays unmatched, and nothing approximate is shown as fact.
// One Overpass request a run, 90-second timeout, an identifying User-Agent (SEC_USER_AGENT's contact) and an Accept
// header (overpass-api.de answered a bare request with HTTP 406). Mirrors are tried in order only when the previous one
// fails; a 429 or 504 records its Retry-After (or a day) and ends the attempt without another request. Geometry is
// validated, made antimeridian-safe and simplified to a bounded payload; OSM user, uid and edit metadata are never
// kept. A new snapshot replaces the stored one only when it holds at least half the previous way count; otherwise the
// last good snapshot stays and the run fails with the reason (as the blogs job does).
export const OVERPASS_MIRRORS = ['https://overpass-api.de/api/interpreter', 'https://overpass.private.coffee/api/interpreter'];
export const WIKIDATA_SPARQL = 'https://query.wikidata.org/sparql';
export const CABLE_LIMITS = { TIMEOUT_MS: 90000, WD_TIMEOUT_MS: 45000, MAX_POINTS_PER_WAY: 400, MAX_POINTS: 60000, KEEP_RATIO: 0.5, BACKOFF_S: 86400 };
export const CABLE_TERMS = {
  licence: 'ODbL-1.0', licence_url: 'https://opendatacommons.org/licenses/odbl/1-0/', attribution: '© OpenStreetMap contributors',
  attribution_url: 'https://www.openstreetmap.org/copyright', share_alike: 'The derived cable database is offered under the ODbL 1.0; see /open-data/cables-LICENSE.txt',
  wikidata_licence: 'CC0-1.0', coverage: 'partial',
};
export const CABLE_QUERY = '[out:json][timeout:80];(way["communication"="line"]["location"="underwater"];node["telecom"="cable_landing_station"];);out tags geom qt;';
export const WIKIDATA_QUERY = `SELECT ?item ?label ?owner ?ownerLabel ?length ?service ?inception WHERE {
  ?item wdt:P31 wd:Q506572 ; rdfs:label ?label . FILTER(LANG(?label) = "en")
  OPTIONAL { ?item wdt:P127 ?owner . ?owner rdfs:label ?ownerLabel . FILTER(LANG(?ownerLabel) = "en") }
  OPTIONAL { ?item wdt:P2043 ?length } OPTIONAL { ?item wdt:P729 ?service } OPTIONAL { ?item wdt:P571 ?inception } }`;
// Tags kept from OSM; anything else (and any user, uid, version, changeset or timestamp field) is dropped.
const KEEP_TAGS = ['name', 'name:en', 'operator', 'owner', 'ref', 'start_date', 'wikidata', 'wikipedia', 'location', 'submarine', 'communication', 'telecom', 'seamark:type'];

export const cableUserAgent = (contact) => `threat-feeds-collector/1.0 (submarine cable layer, open data; +https://intel.kilfoycyber.com/data-sources; contact: ${contact})`;
export const normName = (s) => String(s || '').normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

// ---------------------------------------------------------------- geometry
const okCoord = (lat, lon) => Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180;
// Unwrap a ring of [lon, lat] so consecutive points never jump more than 180 degrees of longitude.
function unwrap(pts) {
  const out = [];
  let off = 0;
  for (let i = 0; i < pts.length; i++) {
    if (i) { const d = pts[i][0] + off - out[i - 1][0]; if (d > 180) off -= 360; else if (d < -180) off += 360; }
    out.push([pts[i][0] + off, pts[i][1]]);
  }
  return out;
}
// Douglas-Peucker on the unwrapped line (degrees).
function simplify(pts, tol) {
  if (pts.length < 3 || tol <= 0) return pts.slice();
  const keep = new Uint8Array(pts.length); keep[0] = keep[pts.length - 1] = 1;
  const stack = [[0, pts.length - 1]];
  while (stack.length) {
    const [a, b] = stack.pop();
    const [x1, y1] = pts[a], [x2, y2] = pts[b], dx = x2 - x1, dy = y2 - y1, l2 = dx * dx + dy * dy;
    let best = -1, bi = -1;
    for (let i = a + 1; i < b; i++) {
      const [x, y] = pts[i];
      let t = l2 ? ((x - x1) * dx + (y - y1) * dy) / l2 : 0; t = t < 0 ? 0 : t > 1 ? 1 : t;
      const ex = x1 + t * dx - x, ey = y1 + t * dy - y, d = ex * ex + ey * ey;
      if (d > best) { best = d; bi = i; }
    }
    if (bi > 0 && best > tol * tol) { keep[bi] = 1; stack.push([a, bi], [bi, b]); }
  }
  return pts.filter((_, i) => keep[i]);
}
// Split an unwrapped line where it crosses ±180 into parts that stay within [-180, 180], adding the crossing point.
export function splitAntimeridian(pts) {
  const parts = [];
  let cur = [], shift = 0;
  const norm = (lon) => lon - 360 * Math.round(lon / 360);
  for (let i = 0; i < pts.length; i++) {
    const [lon, lat] = pts[i];
    const s = Math.round(lon / 360) * 360;
    if (i && s !== shift) {
      const [plon, plat] = pts[i - 1], edge = s > shift ? shift + 180 : shift - 180;
      const t = (edge - plon) / (lon - plon), clat = plat + t * (lat - plat);
      cur.push([edge - shift, clat]);
      parts.push(cur);
      cur = [[edge - s, clat]];
      shift = s;
    } else if (!i) shift = s;
    cur.push([norm(lon), lat]);
  }
  if (cur.length) parts.push(cur);
  return parts.filter((p) => p.length >= 2).map((p) => p.map(([x, y]) => [Math.round(x * 1e4) / 1e4, Math.round(y * 1e4) / 1e4]));
}
// One way's geometry (Overpass [{lat, lon}]) to validated, simplified, antimeridian-safe parts of [lon, lat].
export function wayParts(geometry, tol, maxPts = CABLE_LIMITS.MAX_POINTS_PER_WAY) {
  const raw = (geometry || []).map((g) => [Number(g && g.lon), Number(g && g.lat)]).filter(([lon, lat]) => okCoord(lat, lon));
  if (raw.length < 2) return [];
  let u = unwrap(raw), t = tol, s = simplify(u, t);
  while (s.length > maxPts) { t = t ? t * 2 : 0.001; s = simplify(u, t); }
  return splitAntimeridian(s);
}

// ---------------------------------------------------------------- parsing and the join
// Overpass answer to cable rows and station rows; tags whitelisted, metadata dropped, payload capped by raising the
// simplification tolerance until the total point count fits.
export function parseOverpass(j, { maxPoints = CABLE_LIMITS.MAX_POINTS } = {}) {
  const els = (j && Array.isArray(j.elements)) ? j.elements : [];
  const pick = (tags) => { const o = {}; for (const k of KEEP_TAGS) if (tags && typeof tags[k] === 'string' && tags[k]) o[k] = tags[k].slice(0, 200); return o; };
  const waysIn = els.filter((e) => e && e.type === 'way' && Number.isSafeInteger(e.id));
  const stations = els.filter((e) => e && e.type === 'node' && Number.isSafeInteger(e.id) && okCoord(Number(e.lat), Number(e.lon)))
    .map((e) => { const tags = pick(e.tags); return { osm_id: e.id, name: tags.name || tags['name:en'] || null, lat: Math.round(e.lat * 1e5) / 1e5, lon: Math.round(e.lon * 1e5) / 1e5, tags }; });
  let tol = 0, ways = [], total = 0, rounds = 0;
  do {
    ways = waysIn.map((e) => { const tags = pick(e.tags); const parts = wayParts(e.geometry, tol); return { osm_id: e.id, name: tags.name || tags['name:en'] || null, tags, parts,
      points: parts.reduce((s, p) => s + p.length, 0) }; }).filter((w) => w.parts.length);
    total = ways.reduce((s, w) => s + w.points, 0);
    tol = tol ? tol * 2 : 0.005;
  } while (total > maxPoints && ++rounds < 12);
  const osmBase = j && j.osm3s && j.osm3s.timestamp_osm_base ? String(j.osm3s.timestamp_osm_base) : null;
  return { ways, stations, points: total, tolerance: rounds ? tol / 2 : 0, osm_base: osmBase, dropped_ways: waysIn.length - ways.length };
}
// Wikidata SPARQL bindings to one record per item: label, owners, length (km), service entry or inception.
export function parseWikidata(j) {
  const by = new Map();
  for (const b of (j && j.results && j.results.bindings) || []) {
    const qid = String((b.item && b.item.value) || '').split('/').pop();
    if (!/^Q\d+$/.test(qid)) continue;
    const r = by.get(qid) || { qid, label: b.label ? b.label.value : '', owners: new Set(), length_km: null, service: null, inception: null };
    if (b.ownerLabel && b.ownerLabel.value) r.owners.add(b.ownerLabel.value);
    if (b.length && isFinite(+b.length.value)) r.length_km = Math.round(+b.length.value);
    if (b.service && b.service.value) r.service = String(b.service.value).slice(0, 10);
    if (b.inception && b.inception.value) r.inception = String(b.inception.value).slice(0, 10);
    by.set(qid, r);
  }
  return [...by.values()].map((r) => ({ ...r, owners: [...r.owners].sort() }));
}
// Exact normalised-name join. An OSM name that matches one Wikidata item gets its record; a name that matches several
// items is ambiguous and stays unmatched.
export function joinWikidata(ways, items) {
  const idx = new Map();
  for (const it of items) { const k = normName(it.label); if (!k) continue; idx.set(k, (idx.get(k) || []).concat(it)); }
  let matched = 0, ambiguous = 0;
  const names = new Set();
  for (const w of ways) {
    const k = normName(w.name);
    const hit = k ? idx.get(k) : null;
    if (hit && hit.length === 1) {
      const it = hit[0];
      w.wikidata = { qid: it.qid, owners: it.owners, length_km: it.length_km, ready_for_service: it.service || it.inception || null,
        ready_for_service_basis: it.service ? 'service entry (P729)' : it.inception ? 'inception (P571)' : null, match: 'exact normalised name' };
      matched++; names.add(k);
    } else { w.wikidata = null; if (hit && hit.length > 1) ambiguous++; }
  }
  return { matched_ways: matched, matched_names: names.size, ambiguous_ways: ambiguous };
}
export const keepNewSnapshot = (prev, next, ratio = CABLE_LIMITS.KEEP_RATIO) => (prev > 0 ? next >= Math.ceil(prev * ratio) : next > 0);

// ---------------------------------------------------------------- fetch
// One Overpass request a run: the first mirror, and the next only when that one could not answer. 429 and 504 end the
// attempt (no further request) and set a back-off from Retry-After, else a day.
export async function fetchOverpass({ ua, mirrors = OVERPASS_MIRRORS, timeout = CABLE_LIMITS.TIMEOUT_MS } = {}) {
  const tried = [];
  for (const m of mirrors) {
    const r = await get(m, { method: 'POST', as: 'json', timeout, body: 'data=' + encodeURIComponent(CABLE_QUERY),
      headers: { 'user-agent': ua, accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' } });
    tried.push({ mirror: m, status: r.status, ms: r.ms, error: r.ok ? undefined : (r.error || 'HTTP ' + r.status) });
    if (r.ok && r.json && Array.isArray(r.json.elements)) return { ok: true, json: r.json, mirror: m, tried };
    if (r.status === 429 || r.status === 504) {
      const ra = r.headers && +r.headers.get('retry-after');
      return { ok: false, tried, backoff_s: ra > 0 ? Math.min(ra, 7 * 86400) : CABLE_LIMITS.BACKOFF_S, reason: `Overpass answered HTTP ${r.status} at ${m}; backing off` };
    }
  }
  return { ok: false, tried, reason: 'no Overpass mirror answered: ' + tried.map((t) => t.mirror.split('/')[2] + ' ' + (t.error || t.status)).join(', ') };
}

// ---------------------------------------------------------------- the job
export async function jobCables(opts = {}) {
  const t0 = Date.now(), contact = ENV().SEC_USER_AGENT || '';
  if (!contact) throw new Error('SEC_USER_AGENT is not set: Overpass and Wikidata ask for an identifying User-Agent with a contact');
  const ua = cableUserAgent(contact);
  const meta0 = (await kvGet('cables:meta')) || {};
  if (meta0.next_after && Date.parse(meta0.next_after) > Date.now() && !opts.force) {
    return { skipped: true, reason: 'backing off until ' + meta0.next_after + ' after a 429 or 504', run_failed: undefined, ms: Date.now() - t0 };
  }
  const o = await (opts.fetchOverpass || fetchOverpass)({ ua });
  if (!o.ok) {
    if (o.backoff_s) await kvPut('cables:meta', { ...meta0, next_after: new Date(Date.now() + o.backoff_s * 1000).toISOString(), last_error: o.reason });
    return { tried: o.tried, run_failed: o.reason, ms: Date.now() - t0 };
  }
  const p = parseOverpass(o.json);
  // Wikidata metadata, joined by exact normalised name; a failure leaves the cables unjoined and says so.
  let items = [], wdNote = null;
  const w = await get(WIKIDATA_SPARQL + '?format=json&query=' + encodeURIComponent(WIKIDATA_QUERY), { as: 'json', timeout: CABLE_LIMITS.WD_TIMEOUT_MS,
    headers: { 'user-agent': ua, accept: 'application/sparql-results+json' } });
  if (w.ok && w.json) items = parseWikidata(w.json); else wdNote = 'Wikidata not joined: ' + (w.error || 'HTTP ' + w.status);
  const join = joinWikidata(p.ways, items);
  const [prevRow] = await sql(`SELECT count(*)::int AS n FROM ti.cable`);
  const prev = prevRow ? prevRow.n : 0;
  const counts = { ways: p.ways.length, named: p.ways.filter((x) => x.name).length, stations: p.stations.length, points: p.points, dropped_ways: p.dropped_ways,
    wikidata_items: items.length, ...join };
  if (!keepNewSnapshot(prev, p.ways.length)) {
    return { counts, previous_ways: prev, mirror: o.mirror, tried: o.tried, held: true,
      run_failed: `cables snapshot held: ${p.ways.length} ways against ${prev} in the last good snapshot (needs at least ${Math.ceil(prev * CABLE_LIMITS.KEEP_RATIO)})`, ms: Date.now() - t0 };
  }
  const meta = { osm_base: p.osm_base, fetched_at: new Date().toISOString(), counts, source_url: o.mirror, query: CABLE_QUERY, wikidata_url: WIKIDATA_SPARQL, wikidata_note: wdNote,
    tolerance_deg: p.tolerance, ...CABLE_TERMS, next_after: null, last_error: null };
  await sqlTx([
    [`DELETE FROM ti.cable`], [`DELETE FROM ti.cable_station`],
    [`INSERT INTO ti.cable (osm_id, name, tags, parts, points, wikidata, seen_at) SELECT osm_id, name, tags, parts, points, wikidata, now()
      FROM jsonb_to_recordset($1::jsonb) AS x(osm_id bigint, name text, tags jsonb, parts jsonb, points int, wikidata jsonb)`, [p.ways]],
    [`INSERT INTO ti.cable_station (osm_id, name, lat, lon, tags, seen_at) SELECT osm_id, name, lat, lon, tags, now()
      FROM jsonb_to_recordset($1::jsonb) AS x(osm_id bigint, name text, lat real, lon real, tags jsonb)`, [p.stations]],
    [`INSERT INTO ti.kv (k, v, at) VALUES ('cables:meta', $1::jsonb, now()) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, at = now()`, [meta]],
  ]);
  const doc = cablesDoc({ ways: p.ways, stations: p.stations, meta });
  await recordVolume([['cables_ways', p.ways.length], ['cables_stations', p.stations.length]]);
  return { counts, previous_ways: prev, mirror: o.mirror, tried: o.tried, wikidata_note: wdNote || undefined, published: await putDoc('cables', doc), ms: Date.now() - t0 };
}
// The published document: licence and attribution first, then one row per cable way and per landing station.
export function cablesDoc({ ways, stations, meta }) {
  const rows = ways.map((x) => ({ kind: 'cable', id: x.osm_id, name: x.name, operator: x.tags.operator || x.tags.owner || null, parts: x.parts, wikidata: x.wikidata || null,
    osm: 'https://www.openstreetmap.org/way/' + x.osm_id }))
    .concat(stations.map((s) => ({ kind: 'station', id: s.osm_id, name: s.name, lat: s.lat, lon: s.lon, operator: s.tags.operator || null, osm: 'https://www.openstreetmap.org/node/' + s.osm_id })));
  return { source: 'OpenStreetMap through Overpass (submarine communication cables, landing stations); metadata joined from Wikidata by exact name',
    ...CABLE_TERMS, osm_base: meta.osm_base, fetched_at: meta.fetched_at, source_url: meta.source_url, counts: meta.counts, wikidata_note: meta.wikidata_note || undefined,
    method: 'Ways tagged communication=line and location=underwater, nodes tagged telecom=cable_landing_station; geometry simplified to a bounded size and split at the antimeridian. Wikidata owner, length and service date are attached only where the OSM name and the Wikidata label match exactly after case, accent and punctuation are removed; other cables carry no Wikidata record.',
    generated: new Date().toISOString(), served_from: 'store', count: rows.length, rows };
}
