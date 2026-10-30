const { handle, sendJson, q, UA } = require('./_lib');
const { firstEntry } = require('../lib/unzip');
const { isoAt } = require('../lib/countries');
const store = require('../lib/store');

// GDELT 2.0 event exports: one machine-coded file of world news events every 15 minutes, published as static
// files (no API quota). This reads the last N hours, keeps root events in the requested CAMEO quad classes,
// and returns them aggregated for a map and a tempo chart:
//   kind "cell"    1-degree cell x hour bucket (sub-national geocodes only), events and mentions
//   kind "country" ISO-2 x hour bucket, events and mentions (all geocodes)
//   kind "event"   the most-mentioned events, with place, CAMEO codes, actors and the source article URL
//   kind "base"    ISO-2 totals over the baseline window before the live window, for an anomaly ratio
//   kind "flow"    actor1 location -> action location, aggregated, for animated great-circle arcs, with the number of
//                  distinct articles behind each pair (single-article pairs are the ones GDELT most often misplaces)
// ?hours=1..24 (default 24), ?baseline=0..48 hours before that (default 48), ?quad=4 (material conflict) or 3,4,
// ?actors=armed (default: an actor typed MIL, REB, INS, SEP, UAF or SPY) or all, ?top=1..150 (default 80),
// ?flows=0..200 arcs (default 140).
// The standard window (24h, 48h baseline, quad 4, armed actors) is served from the collector's document when it is
// under 75 minutes old with full coverage; that document is built incrementally from the same exports every 15 minutes
// and adds kind "base30" (each country's daily mean and standard deviation over the prior 30 days). Otherwise the
// window is computed live from the exports, and if that fails the stored document is returned marked stale.
// ?live=1 forces the live path.
// Column positions follow the GDELT 2.0 Event codebook (61 tab-separated fields).
const ARMED = new Set(['MIL', 'REB', 'INS', 'SEP', 'UAF', 'SPY']);
const TYPES = [12, 13, 14, 22, 23, 24]; // Actor1Type1-3Code, Actor2Type1-3Code
const C = { id: 0, a1: 6, a1cc: 7, a2: 16, a2cc: 17, root: 25, code: 26, rootCode: 28, quad: 29, gold: 30, mentions: 31, sources: 32, articles: 33,
  a1geoType: 35, a1place: 36, a1lat: 40, a1lon: 41, geoType: 51, place: 52, lat: 56, lon: 57, added: 59, url: 60 };
const BASE = 'http://data.gdeltproject.org/gdeltv2/';

function stamp(d) { return d.toISOString().replace(/[-:T]/g, '').slice(0, 14); }

// Great-circle distance in km (haversine).
function gcKm(la1, lo1, la2, lo2) {
  const r = Math.PI / 180, dLa = (la2 - la1) * r, dLo = (lo2 - lo1) * r;
  const a = Math.sin(dLa / 2) ** 2 + Math.cos(la1 * r) * Math.cos(la2 * r) * Math.sin(dLo / 2) ** 2;
  return 12742 * Math.asin(Math.min(1, Math.sqrt(a)));
}
const popcount = (x) => { let c = 0; while (x) { x &= x - 1; c++; } return c; };

async function fetchBuf(url, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': UA } });
    if (!r.ok) return { status: r.status };
    return { status: r.status, buf: Buffer.from(await r.arrayBuffer()) };
  } catch (e) { return { status: 0, error: String(e.message || e) }; } finally { clearTimeout(t); }
}

module.exports = handle(async (req, res) => {
  const started = Date.now();
  const hours = Math.max(1, Math.min(24, parseInt(q(req, 'hours', '24'), 10) || 24));
  const quads = new Set(String(q(req, 'quad', '4')).split(',').map((s) => s.trim()).filter((s) => ['1', '2', '3', '4'].includes(s)));
  if (!quads.size) quads.add('4');
  const top = Math.max(1, Math.min(150, parseInt(q(req, 'top', '80'), 10) || 80));
  const maxFlows = Math.max(0, Math.min(200, parseInt(q(req, 'flows', '140'), 10)));
  const baseline = Math.max(0, Math.min(48, parseInt(q(req, 'baseline', '48'), 10) || 0));
  const armedOnly = q(req, 'actors', 'armed') !== 'all';
  const debug = q(req, 'debug', '') === '1';
  let sample = null;

  const standard = hours === 24 && baseline === 48 && quads.size === 1 && quads.has('4') && armedOnly && !debug;
  let stored = null;
  if (standard && q(req, 'live', '') !== '1') {
    const s = await store.getDoc(req, 'gdelt-w24b48');
    if (s.ok) {
      stored = s.doc;
      if (store.ageMin(stored.latest) <= 75 && stored.coverage_live >= 0.95 && stored.coverage >= 0.9) return sendJson(res, 200, trim(stored, top, maxFlows), 600, 3600);
    }
  }
  try {
    // Latest export timestamp from lastupdate.txt; fall back to the last quarter hour minus 15 minutes.
    let latest = null;
    const lu = await fetchBuf(BASE + 'lastupdate.txt', 8000);
    if (lu.buf) {
      const m = lu.buf.toString().match(/(\d{14})\.export\.CSV\.zip/);
      if (m) latest = new Date(Date.UTC(+m[1].slice(0, 4), +m[1].slice(4, 6) - 1, +m[1].slice(6, 8), +m[1].slice(8, 10), +m[1].slice(10, 12)));
    }
    if (!latest) { const n = new Date(); n.setUTCSeconds(0, 0); n.setUTCMinutes(n.getUTCMinutes() - (n.getUTCMinutes() % 15) - 15); latest = n; }

    const slots = [];
    for (let i = 0; i < (hours + baseline) * 4; i++) slots.push(new Date(latest.getTime() - i * 15 * 60000));

    const cells = new Map(), countries = new Map(), base = new Map(), events = [], flows = new Map();
    let ok = 0, missing = 0, failed = 0, scanned = 0, kept = 0;
    const deadline = started + 45000;

    async function one(slot) {
      if (Date.now() > deadline) { failed++; return; }
      const r = await fetchBuf(BASE + stamp(slot) + '.export.CSV.zip', 12000);
      if (!r.buf) { if (r.status === 404) missing++; else failed++; return; }
      let text;
      try { text = firstEntry(r.buf).toString('utf8'); } catch { failed++; return; }
      ok++;
      if (debug && !sample) { const f0 = text.split('\n')[0].split('\t'); sample = { fields: f0.length, root: f0[C.root], quad: f0[C.quad], rootCode: f0[C.rootCode], geoType: f0[C.geoType], lat: f0[C.lat], lon: f0[C.lon], added: f0[C.added], url: f0[C.url] }; }
      const h = Math.floor((latest.getTime() - slot.getTime()) / 3600000);
      for (const line of text.split('\n')) {
        if (!line) continue;
        scanned++;
        const f = line.split('\t');
        if (f.length < 61 || f[C.root] !== '1' || !quads.has(f[C.quad])) continue;
        if (armedOnly && !TYPES.some((i) => ARMED.has(f[i]))) continue;
        const lat = parseFloat(f[C.lat]), lon = parseFloat(f[C.lon]);
        if (!isFinite(lat) || !isFinite(lon)) continue;
        kept++;
        const mentions = parseInt(f[C.mentions], 10) || 0;
        const iso = isoAt(lon, lat);
        if (h >= hours) { if (iso) { const b = base.get(iso) || { kind: 'base', iso2: iso, hours: baseline, n: 0, m: 0 }; b.n++; b.m += mentions; base.set(iso, b); } continue; }
        if (iso) {
          const ck = iso + '|' + h;
          const c = countries.get(ck) || { kind: 'country', iso2: iso, h, n: 0, m: 0 };
          c.n++; c.m += mentions; countries.set(ck, c);
        }
        // Country-level geocodes (type 1) sit on the country centroid; keep them out of the cell grid.
        if (f[C.geoType] !== '1') {
          const la = Math.floor(lat) + 0.5, lo = Math.floor(lon) + 0.5;
          const k = la + '|' + lo + '|' + h;
          const c = cells.get(k) || { kind: 'cell', lat: la, lon: lo, h, n: 0, m: 0 };
          c.n++; c.m += mentions; cells.set(k, c);
        }
        events.push({ kind: 'event', id: f[C.id], h, added: f[C.added], lat: Math.round(lat * 100) / 100, lon: Math.round(lon * 100) / 100, iso2: iso,
          place: f[C.place], root: f[C.rootCode], code: f[C.code], quad: +f[C.quad], goldstein: parseFloat(f[C.gold]) || 0,
          actor1: f[C.a1], actor2: f[C.a2], mentions, sources: parseInt(f[C.sources], 10) || 0, url: f[C.url] });

        // Flow: where GDELT geocodes Actor 1 to where it geocodes the action. Both ends are the coder's own
        // coordinates; pairs closer than 100 km are local events and get no arc. Pairs are bucketed on whole
        // degrees at both ends and the most-mentioned event in a bucket supplies the drawn coordinates and links.
        if (!maxFlows) continue;
        const a1lat = parseFloat(f[C.a1lat]), a1lon = parseFloat(f[C.a1lon]);
        if (!isFinite(a1lat) || !isFinite(a1lon) || (a1lat === 0 && a1lon === 0)) continue;
        if (gcKm(a1lat, a1lon, lat, lon) < 100) continue;
        const fk = Math.round(a1lat) + '|' + Math.round(a1lon) + '>' + Math.round(lat) + '|' + Math.round(lon);
        let fl = flows.get(fk);
        if (!fl) { fl = { n: 0, m: 0, h, hs: 0, roots: {}, best: -1, rep: null, urls: new Set() }; flows.set(fk, fl); }
        fl.n++; fl.m += mentions; fl.hs |= 1 << h; if (h < fl.h) fl.h = h; fl.urls.add(f[C.url]);
        fl.roots[f[C.rootCode]] = (fl.roots[f[C.rootCode]] || 0) + Math.max(1, mentions);
        if (mentions > fl.best) {
          fl.best = mentions;
          fl.rep = { src_lat: Math.round(a1lat * 100) / 100, src_lon: Math.round(a1lon * 100) / 100, src_type: +f[C.a1geoType] || 0, src_place: f[C.a1place],
            dst_lat: Math.round(lat * 100) / 100, dst_lon: Math.round(lon * 100) / 100, dst_type: +f[C.geoType] || 0, dst_place: f[C.place], dst_iso2: iso,
            actor1: f[C.a1], actor2: f[C.a2], code: f[C.code], url: f[C.url], id: f[C.id] };
        }
      }
    }

    // Bounded concurrency over the slots.
    const queue = slots.slice();
    await Promise.all(Array.from({ length: 16 }, async () => { while (queue.length) await one(queue.shift()); }));

    // Top events: most mentioned, one per source URL.
    events.sort((a, b) => b.mentions - a.mentions || b.sources - a.sources);
    const seen = new Set(), topEvents = [];
    for (const e of events) { if (seen.has(e.url)) continue; seen.add(e.url); topEvents.push(e); if (topEvents.length >= top) break; }

    // Flows: the most-mentioned buckets first, capped. Dominant CAMEO root by mentions; hours_seen counts the
    // distinct hour buckets of the live window in which the pair recurred.
    const flowRows = [...flows.values()].sort((a, b) => b.m - a.m || b.n - a.n).slice(0, maxFlows).map((fl) => {
      const root = Object.entries(fl.roots).sort((a, b) => b[1] - a[1])[0][0];
      return { kind: 'flow', ...fl.rep, src_iso2: isoAt(fl.rep.src_lon, fl.rep.src_lat), root, n: fl.n, m: fl.m, articles: fl.urls.size, h: fl.h, hours_seen: popcount(fl.hs) };
    });

    const rows = [...cells.values(), ...countries.values(), ...base.values(), ...topEvents, ...flowRows];
    if (!ok && stored) return sendJson(res, 200, { ...trim(stored, top, maxFlows), served_from: 'store-stale', stale: true, live_error: `no exports read (${missing} missing, ${failed} failed)` }, 120, 600);
    sendJson(res, 200, {
      source: 'GDELT 2.0 Event exports (15-minute files)', generated: new Date().toISOString(), served_from: 'live',
      latest: latest.toISOString(), hours, baseline, actors: armedOnly ? 'armed' : 'all', quads: [...quads].join(','), files_requested: slots.length, files_ok: ok, files_missing: missing, files_failed: failed,
      events_scanned: scanned, events_kept: kept, flows: flowRows.length, ms: Date.now() - started, sample: sample || undefined, count: rows.length, rows: debug ? rows.slice(0, 5) : rows,
    }, 900, 3600);
  } catch (e) {
    if (stored) return sendJson(res, 200, { ...trim(stored, top, maxFlows), served_from: 'store-stale', stale: true, live_error: String((e && e.message) || e) }, 120, 600);
    throw e;
  }
});

// The stored document holds the top 80 events and 140 flows; honour smaller ?top and ?flows.
function trim(doc, top, maxFlows) {
  let ev = 0, fl = 0;
  const rows = doc.rows.filter((r) => (r.kind === 'event' ? ++ev <= top : r.kind === 'flow' ? ++fl <= maxFlows : true));
  return { ...doc, rows, count: rows.length, age_min: Math.round(store.ageMin(doc.generated)) };
}