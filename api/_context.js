const path = require('path');
const { pathToFileURL } = require('url');
const { handle, sendJson, upstream, q } = require('./_lib');
const store = require('../lib/store');

// Context feeds for the theater assessments, normalized by the collector's context part (neon/parts/36-context.mjs,
// no imports), which this route imports on its own:
//   ?type=lanes  Lanes relationship temperatures (lanes.news open data, CC BY 4.0, derived from GDELT) with each
//                pair's latest daily page.
//   ?type=ofac   OFAC Recent Actions: the two newest listing pages, with programs, action types and theaters read
//                from OFAC's titles, and (from the collector) each action page's SDN entries: vessels, cyber tags.
// The collector refreshes both hourly (snap-lanes, snap-ofac). A stored copy inside its freshness window is served as
// is; otherwise the upstream is read live, and if that fails the stored copy is served marked stale. ?live=1 skips
// the stored copy.
// Store-only types (collected by the collector alone; no live read here, since some need keys held only there):
//   fires (NASA FIRMS, hourly), maritime (MARAD advisories, NGA ASAM and navigational warnings, hourly), leaksites (ThreatCluster cross-check, hourly), lists
//   (corroboration lists, hourly), blogs (CTI blog candidates, every six hours a sixth), links (link health, daily),
//   unit42 (daily), genioc (daily), lanesreg (daily), ransompay (weekly), sec8k (SEC 8-K cybersecurity filings, twice a day).
//   Older than its window, a copy is served marked stale.
const TYPES = { lanes: { snap: 'snap-lanes', freshMin: 180 }, ofac: { snap: 'snap-ofac', freshMin: 150 },
  fires: { snap: 'fires', freshMin: 150, store: true }, maritime: { snap: 'maritime', freshMin: 150, store: true }, leaksites: { snap: 'leaksites', freshMin: 150, store: true },
  lists: { snap: 'lists', freshMin: 150, store: true }, blogs: { snap: 'blogs', freshMin: 480, store: true }, links: { snap: 'links', freshMin: 1560, store: true },
  unit42: { snap: 'unit42', freshMin: 1560, store: true }, genioc: { snap: 'genioc', freshMin: 1560, store: true }, lanesreg: { snap: 'lanes-registry', freshMin: 1560, store: true },
  ransompay: { snap: 'ransompay', freshMin: 10200, store: true }, sec8k: { snap: 'sec-8k', freshMin: 900, store: true }, sources: { snap: 'sources', freshMin: 90, store: true } };
// cables (added 2026-11-03): submarine cables and landing stations from OpenStreetMap (ODbL 1.0) with Wikidata metadata
// (CC0), collected weekly; partial coverage. Every answer carries the licence and attribution fields; &format=geojson
// (also served as /open-data/cables.geojson) returns the derived open dataset as a GeoJSON FeatureCollection.
TYPES.psirt = { snap: 'psirt', freshMin: 300, store: true };
TYPES.triage = { snap: 'triage', freshMin: 180, store: true };
TYPES.news = { snap: 'news', freshMin: 150, store: true };
TYPES.cables = { snap: 'cables', freshMin: 8 * 1440 + 120, store: true };
// The entity graph's summary (3.4.0): rising and new entities, the most named per type and the strongest co-mentions.
TYPES.entities = { snap: 'entities', freshMin: 120, store: true };
// Standing watches and change alerts (3.5.0).
TYPES.alerts = { snap: 'alerts', freshMin: 60, store: true };
// Track record (3.6.0).
TYPES.scorecard = { snap: 'scorecard', freshMin: 150, store: true };
// Cyber-physical coincidences (3.7.0).
TYPES.cyphys = { snap: 'cyphys', freshMin: 150, store: true };
// Sigma detection drafts (3.8.0); the job publishes the document hourly, drafting or not.
TYPES.sigma = { snap: 'sigma', freshMin: 150, store: true };
// Threatcasting futures (3.9.0); published in the :04 slot every hour, drafting or not.
TYPES.foresight = { snap: 'foresight', freshMin: 150, store: true };
// Open-source disclosure watch (3.14.0); every three hours.
TYPES.osswatch = { snap: 'osswatch', freshMin: 300, store: true };
const CABLE_TERMS = { licence: 'ODbL-1.0', licence_url: 'https://opendatacommons.org/licenses/odbl/1-0/', attribution: '© OpenStreetMap contributors',
  attribution_url: 'https://www.openstreetmap.org/copyright', licence_note: '/open-data/cables-LICENSE.txt', coverage: 'partial' };
function cablesGeojson(doc) {
  const features = (doc.rows || []).map((r) => (r.kind === 'cable'
    ? { type: 'Feature', id: 'way/' + r.id, geometry: { type: 'MultiLineString', coordinates: r.parts || [] }, properties: { kind: 'cable', name: r.name, operator: r.operator, osm: r.osm, wikidata: r.wikidata || null } }
    : { type: 'Feature', id: 'node/' + r.id, geometry: { type: 'Point', coordinates: [r.lon, r.lat] }, properties: { kind: 'station', name: r.name, operator: r.operator, osm: r.osm } }));
  return { type: 'FeatureCollection', ...CABLE_TERMS, osm_base: doc.osm_base, generated: doc.generated, counts: doc.counts, features };
}
let CTX = null;
const ctx = () => CTX || (CTX = import(pathToFileURL(path.join(__dirname, '..', 'neon', 'parts', '36-context.mjs')).href));
const fetchText = (u) => upstream(u, { timeout: 20000, accept: 'text/html,application/xhtml+xml,text/csv,application/rss+xml;q=0.9,*/*;q=0.8' })
  .catch((e) => ({ ok: false, status: 0, text: '', error: String(e.message || e) }));

module.exports = handle(async (req, res) => {
  const type = TYPES[q(req, 'type', 'lanes')] ? q(req, 'type', 'lanes') : 'lanes';
  const T = TYPES[type];
  const s = await store.getDoc(req, T.snap);
  const age = s.ok ? Math.round(store.ageMin(s.doc.generated)) : null;
  if (T.store) {
    if (!s.ok) return sendJson(res, 502, { error: 'not collected yet', type, store: s.reason || 'missing', ...(type === 'cables' ? CABLE_TERMS : {}) }, 0);
    const stale = age > T.freshMin;
    if (type === 'cables') {
      const doc = { ...s.doc, ...CABLE_TERMS, served_from: stale ? 'store-stale' : 'store', stale: stale || undefined, age_min: age };
      return sendJson(res, 200, q(req, 'format', '') === 'geojson' ? cablesGeojson(doc) : doc, stale ? 300 : 3600, stale ? 900 : 21600);
    }
    return sendJson(res, 200, { ...s.doc, served_from: stale ? 'store-stale' : 'store', stale: stale || undefined, age_min: age }, stale ? 60 : 300, stale ? 300 : 1800);
  }
  if (s.ok && q(req, 'live', '') !== '1' && age <= T.freshMin) return sendJson(res, 200, { ...s.doc, served_from: 'store', age_min: age }, 300, 1800);
  const m = await ctx();
  let doc = null, why = '';
  try { doc = type === 'lanes' ? await m.fetchLanes(fetchText) : await m.fetchOfac(fetchText); } catch (e) { why = String(e.message || e); }
  if (doc && doc.count) return sendJson(res, 200, { ...doc, served_from: 'live' }, 300, 1800);
  if (s.ok) return sendJson(res, 200, { ...s.doc, served_from: 'store-stale', stale: true, age_min: age, upstream_note: why }, 60, 300);
  return sendJson(res, 502, { error: 'upstream', note: why, store: s.reason || 'missing' }, 0);
});
