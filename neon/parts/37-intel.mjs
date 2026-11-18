// ---------------------------------------------------------------- public collection added 2026-10-22 (G53, G55-G57, G60-G63, G66, B5)
// Each job reads public sources only, keeps history in Postgres where a baseline needs it, and publishes one document
// that carries its source, the reuse terms found on 22 October 2026 and its method. No job publishes leak-site victim
// names, onion addresses or bulk indicators; counts, links to the publisher and titles only.
//   fires      NASA FIRMS VIIRS thermal anomalies in the kinetic theaters' areas of interest; novel 0.1-degree cells are
//              cells with a detection in the last 48 hours and none in the 30 days before (G60)
//   maritime   MARAD advisories, NGA ASAM reports and GNSS-interference warnings; UKMTO where reachable (G60)
//   leaksites  ThreatCluster first-party leak-site claims cross-checked against ransomware.live, aggregates only (G53)
//   ransompay  Ransomwhere ransom-payment addresses aggregated by family, CC BY 4.0 (G55)
//   unit42     Palo Alto Networks Unit 42 timely threat notes: date, title, indicator counts (G56)
//   genioc     Gen Threat Labs per-family reference sets: file and hash counts with attribution (G63)
//   lanesreg   Lanes outlet registry and naming choices, CC BY 4.0 (G66)
//   blogs      first-party CTI blogs from awesome_threat_intel_blogs as candidate items (G57)
//   links      link health of the source registry, the OSINT toolkit and the pivot patterns (G62)
// OFAC action pages (G61) are read inside the snap job; feed volumes feed the health job's 30-day baseline (B5).

const IX_DAY = 86400000;
const IX_CR = String.fromCharCode(13);
// Text of the first <name ...>...</name> element in s, case-insensitive, without building a RegExp from the name.
export function feedTag(s, name) {
  const low = s.toLowerCase(), n = name.toLowerCase();
  let i = low.indexOf('<' + n);
  while (i >= 0) {
    const c = low[i + n.length + 1];
    if (c === '>' || c === ' ' || c === '/' || c === '\t' || c === '\n') break;
    i = low.indexOf('<' + n, i + 1);
  }
  if (i < 0) return '';
  const open = low.indexOf('>', i);
  if (open < 0 || low[open - 1] === '/') return '';
  const close = low.indexOf('</' + n + '>', open);
  return close < 0 ? '' : ixText(s.slice(open + 1, close));
}
const ixNum = (v) => { const n = Number(v); return v === '' || v == null || !isFinite(n) ? null : n; };
const ixText = (s) => unent(String(s || '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
const isoDay = (t) => new Date(t).toISOString().slice(0, 10);
const ixHash = (s) => { let h = 2166136261; for (const ch of String(s)) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619) >>> 0; } return h; };
export const ixMedian = (xs) => { const a = xs.filter((x) => x != null && isFinite(x)).slice().sort((p, q) => p - q); if (!a.length) return null; const m = a.length >> 1; return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2; };

export async function kvGet(k) { const r = await sql(`SELECT v FROM ti.kv WHERE k = $1`, [k]); return r.length ? r[0].v : null; }
export async function kvPut(k, v) { await sql(`INSERT INTO ti.kv (k, v, at) VALUES ($1, $2::jsonb, now()) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, at = now()`, [k, v]); }
// Snapshot sizes per feed for the volume baseline (one row per feed per run).
export async function recordVolume(entries) {
  const rows = entries.filter(([f, n]) => f && Number.isFinite(n)).map(([feed, n]) => ({ feed, n: Math.round(n) }));
  if (!rows.length) return;
  try { await sql(`INSERT INTO ti.feed_volume (at, feed, n) SELECT now(), feed, n FROM jsonb_to_recordset($1::jsonb) AS x(feed text, n int) ON CONFLICT DO NOTHING`, [rows]); }
  catch (e) { console.error('volume:', e.message); }
}

// ---------------------------------------------------------------- NASA FIRMS (G60)
// Areas of interest: a box around each kinetic theater, kept to the theater's own countries by point-in-polygon, so a
// box edge reaching a neighbour adds nothing. Russia is cut to the box west of 50E that holds the front, the border
// oblasts and the refinery belt Ukraine's long-range drones reach. Egypt (T-HOA) is left out: its detections are
// flares and fields, not the Horn's conflicts.
export const FIRMS_AOI = [
  { id: 'T-UKR', name: 'Russia and Ukraine', bbox: [22, 43.5, 50, 57.5], cc: ['UA', 'RU'] },
  { id: 'T-LEV', name: 'Israel, Lebanon and Syria', bbox: [34.2, 29.4, 42.4, 37.4], cc: ['IL', 'PS', 'LB', 'SY'] },
  { id: 'T-RSY', name: 'Red Sea, Yemen and Saudi Arabia', bbox: [36, 12, 54, 20.5], cc: ['YE', 'SA'] },
  { id: 'T-HRM', name: 'Strait of Hormuz and the Gulf', bbox: [47, 22, 60, 32], cc: ['IR', 'AE', 'OM', 'QA', 'SA', 'BH', 'KW'] },
  { id: 'T-SDN', name: 'Sudan', bbox: [21.8, 8.6, 38.7, 22.3], cc: ['SD'] },
  { id: 'T-SAH', name: 'Sahel and West Africa', bbox: [-12.3, 9.4, 16, 25], cc: ['ML', 'BF', 'NE'] },
  { id: 'T-AFP', name: 'Afghanistan and Pakistan border', bbox: [60.5, 24, 75.5, 38.5], cc: ['AF', 'PK'] },
  { id: 'T-HOA', name: 'Horn of Africa', bbox: [33, -2, 51.5, 18.1], cc: ['ET', 'ER', 'SO'] },
];
export const FIRMS_SOURCES = ['VIIRS_NOAA20_NRT', 'VIIRS_NOAA21_NRT', 'VIIRS_SNPP_NRT'];
export const FIRMS_CREDIT = "We acknowledge the use of data and/or imagery from NASA's Fire Information for Resource Management System (FIRMS) (https://www.earthdata.nasa.gov/firms), part of NASA's Earth Science Data and Information System (ESDIS).";
export const firmsCell = (lat, lon) => Math.floor(lat * 10) + ':' + Math.floor(lon * 10);
export function parseFirmsCsv(text) {
  const lines = String(text || '').split(IX_CR).join('').split('\n').filter((l) => l.trim());
  if (!lines.length) return { ok: false, error: 'empty response', rows: [] };
  const head = lines[0].split(',').map((h) => h.trim().toLowerCase());
  const at = (n) => head.indexOf(n);
  const iLat = at('latitude'), iLon = at('longitude');
  if (iLat < 0 || iLon < 0) return { ok: false, error: 'not a FIRMS CSV: ' + lines[0].slice(0, 120), rows: [] };
  const iFrp = at('frp'), iConf = at('confidence'), iDate = at('acq_date'), iTime = at('acq_time'), iDn = at('daynight'), iSat = at('satellite');
  const rows = [];
  for (let k = 1; k < lines.length; k++) {
    const c = lines[k].split(',');
    const lat = Number(c[iLat]), lon = Number(c[iLon]);
    if (!isFinite(lat) || !isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) continue;
    const day = /^\d{4}-\d{2}-\d{2}$/.test(String(c[iDate] || '')) ? c[iDate] : null;
    const tm = String(c[iTime] == null ? '' : c[iTime]).trim().padStart(4, '0');
    rows.push({ lat, lon, frp: ixNum(c[iFrp]), conf: (String(c[iConf] == null ? '' : c[iConf]).trim().toLowerCase().slice(0, 1)) || null, day,
      at: day && /^\d{4}$/.test(tm) ? `${day}T${tm.slice(0, 2)}:${tm.slice(2)}:00Z` : null, dn: c[iDn] ? String(c[iDn]).trim() : null, sat: c[iSat] ? String(c[iSat]).trim() : null });
  }
  return { ok: true, rows };
}
// Rolls a day's detections into cells and judges novelty against the prior cells; pure, for tests.
export function firmsDoc({ per, prior, series, firstDay, now = Date.now() }) {
  const priorSet = new Set((prior || []).map((p) => p.aoi + '|' + p.cell));
  const today = isoDay(now), yday = isoDay(now - IX_DAY);
  const rows = [], aois = [];
  for (const a of per) {
    const first = (firstDay || {})[a.aoi.id] || null;
    const baselineDays = first ? Math.max(0, Math.round((Date.parse(yday) - Date.parse(first)) / IX_DAY)) : 0;
    const judged = baselineDays >= 7;
    const ser = (series || []).filter((s) => s.aoi === a.aoi.id).map((s) => ({ d: s.d, n: s.n, frp: s.frp, cells: s.cells }));
    const prev = ser.filter((s) => s.d < yday).map((s) => s.n);
    const ydayRow = ser.find((s) => s.d === yday) || null;
    const med = ixMedian(prev);
    const st = { id: a.aoi.id, name: a.aoi.name, bbox: a.aoi.bbox, countries: a.aoi.cc, ok: a.ok, source: a.source || null, error: a.ok ? null : a.error,
      detections: 0, high: 0, frp: 0, by_cc: {}, cells: 0, novel_cells: 0, novel_detections: 0, yesterday: ydayRow ? ydayRow.n : null, median_daily: med,
      ratio: med && ydayRow ? Math.round((ydayRow.n / med) * 100) / 100 : null, baseline_days: baselineDays, novelty_judged: judged, series: ser };
    if (a.ok) {
      const cells = new Set(), novelCells = new Set();
      for (const p of a.pts) {
        st.detections++;
        if (p.conf === 'h') st.high++;
        st.frp += p.frp || 0;
        st.by_cc[p.cc] = (st.by_cc[p.cc] || 0) + 1;
        cells.add(p.cell);
        p.novel = judged && !priorSet.has(a.aoi.id + '|' + p.cell);
        if (p.novel) { novelCells.add(p.cell); st.novel_detections++; }
      }
      st.cells = cells.size; st.novel_cells = novelCells.size; st.frp = Math.round(st.frp);
      const novel = a.pts.filter((p) => p.novel).sort((x, y) => (y.frp || 0) - (x.frp || 0)).slice(0, 300);
      const top = a.pts.filter((p) => !p.novel).sort((x, y) => (y.frp || 0) - (x.frp || 0)).slice(0, 200);
      for (const p of novel.concat(top)) rows.push({ kind: 'fire', aoi: a.aoi.id, lat: Math.round(p.lat * 1000) / 1000, lon: Math.round(p.lon * 1000) / 1000, cc: p.cc,
        frp: p.frp, conf: p.conf, at: p.at, dn: p.dn, novel: p.novel || undefined });
    }
    aois.push(st);
  }
  return { source: 'NASA FIRMS active fire data, VIIRS near real time (NOAA-20, falling back to NOAA-21 or S-NPP)', credit: FIRMS_CREDIT,
    terms: 'NASA Earth science data are open for use; FIRMS asks users to acknowledge the source with the credit line above.',
    method: 'Detections in the last 24 hours inside each area of interest, kept to the theater countries by point-in-polygon. A cell is 0.1 degree. Novel means a cell with a detection in the last 48 hours and none in the 30 days before; it is judged once the collector holds 7 days of cells. Thermal anomalies have many causes (agricultural burning, wildfire, gas flares, industry); a detection is a fire or hot spot of any cause, and only corroboration ties one to a strike.',
    generated: new Date(now).toISOString(), served_from: 'store', today, aois, count: rows.length, rows };
}
async function firmsArea(key, aoi, src) {
  const r = await get(`https://firms.modaps.eosdis.nasa.gov/api/area/csv/${encodeURIComponent(key)}/${src}/${aoi.bbox.join(',')}/1`, { timeout: 30000 });
  const redact = (s) => String(s || '').split(key).join('***');
  if (!r.ok) return { ok: false, error: redact(r.error || `HTTP ${r.status}: ${(r.text || '').slice(0, 160)}`) };
  const p = parseFirmsCsv(r.text);
  return p.ok ? p : { ok: false, error: redact(p.error) };
}
export async function jobFires() {
  const t0 = Date.now(), key = ENV().FIRMS_MAP_KEY;
  if (!key) throw new Error('FIRMS_MAP_KEY is not set');
  const G = await geo();
  const per = await pool(FIRMS_AOI, 3, async (aoi) => {
    let res = null, used = null;
    for (const src of FIRMS_SOURCES) { res = await firmsArea(key, aoi, src); used = src; if (res.ok) break; }
    if (!res.ok) return { aoi, ok: false, error: res.error, source: used, pts: [] };
    const allow = new Set(aoi.cc), pts = [];
    for (const p of res.rows) { const cc = isoAt(G, p.lon, p.lat); if (allow.has(cc)) pts.push({ ...p, cc, cell: firmsCell(p.lat, p.lon) }); }
    return { aoi, ok: true, source: used, raw: res.rows.length, pts };
  });
  if (!per.some((a) => a.ok)) throw new Error('FIRMS: no area answered: ' + per.map((a) => a.aoi.id + ' ' + a.error).join('; ').slice(0, 400));
  const agg = new Map();
  for (const a of per) for (const p of a.pts) {
    if (!p.day) continue;
    const k = a.aoi.id + '|' + p.cell + '|' + p.day;
    const c = agg.get(k) || { aoi: a.aoi.id, cell: p.cell, day: p.day, n: 0, frp: 0, cc: p.cc };
    c.n++; c.frp += p.frp || 0; agg.set(k, c);
  }
  const cellRows = [...agg.values()];
  const [, prior, series, firsts] = await sqlTx([
    [`INSERT INTO ti.fire_cell (aoi, cell, day, n, frp, cc) SELECT aoi, cell, day, n, frp, cc FROM jsonb_to_recordset($1::jsonb) AS x(aoi text, cell text, day date, n int, frp real, cc text)
      ON CONFLICT (aoi, cell, day) DO UPDATE SET n = GREATEST(ti.fire_cell.n, EXCLUDED.n), frp = GREATEST(ti.fire_cell.frp, EXCLUDED.frp)`, [cellRows]],
    // Novelty needs only the prior cells that today's detections touch; the full 30-day set ran to 9,000 rows an hour of
    // Postgres transfer (3.0.4).
    [`SELECT DISTINCT f.aoi, f.cell FROM ti.fire_cell f JOIN (SELECT DISTINCT aoi, cell FROM jsonb_to_recordset($1::jsonb) AS x(aoi text, cell text)) t ON t.aoi = f.aoi AND t.cell = f.cell
      WHERE f.day >= (now() AT TIME ZONE 'UTC')::date - 31 AND f.day < (now() AT TIME ZONE 'UTC')::date - 1`, [per.flatMap((a) => a.pts.map((p) => ({ aoi: a.aoi.id, cell: p.cell })))]],
    [`SELECT aoi, to_char(day, 'YYYY-MM-DD') AS d, sum(n)::int AS n, round(sum(frp))::int AS frp, count(*)::int AS cells FROM ti.fire_cell
      WHERE day > (now() AT TIME ZONE 'UTC')::date - 31 GROUP BY 1, 2 ORDER BY 1, 2`],
    [`SELECT aoi, to_char(min(day), 'YYYY-MM-DD') AS first FROM ti.fire_cell GROUP BY 1`],
  ]);
  const doc = firmsDoc({ per, prior, series, firstDay: Object.fromEntries(firsts.map((f) => [f.aoi, f.first])) });
  await recordVolume([['firms', doc.aois.reduce((s, a) => s + a.detections, 0)]]);
  return { aois: doc.aois.map((a) => ({ id: a.id, ok: a.ok, n: a.detections, novel: a.novel_cells, error: a.error || undefined })), cells: cellRows.length,
    published: await putDoc('fires', doc), ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- ThreatCluster leak-site cross-check (G53)
// ThreatCluster's public dark-web feed (CC BY 4.0, no key, 60 requests a minute; its feeds page invites cron and SIEM
// polling) marks rows it read off the leak site itself (first_party) and posts that stopped being reachable (delisted).
// The cross-check matches its claims against ransomware.live's recent victims over ransomware.live's window, by group
// and by normalized organisation name or website. Only per-group counts are published.
export const TC_URL = { victims: 'https://threatcluster.io/api/darkweb/public/victims.json?days=30', groups: 'https://threatcluster.io/api/darkweb/public/groups.csv',
  stats: 'https://threatcluster.io/api/darkweb/stats', group: 'https://threatcluster.io/dark-web/group/', rl: 'https://api.ransomware.live/v2/recentvictims' };
const LEGAL = /\b(incorporated|inc|llc|l\.l\.c|ltd|limited|gmbh|ag|sa|s\.a|sas|sarl|srl|spa|s\.p\.a|bv|b\.v|nv|plc|corp|corporation|co|company|group|holdings?|pty|oy|ab|as|a\/s|kg|kft|sp z o\.?o|sl|s\.l|lp|llp|pc|pllc)\b\.?/g;
export function tcNormName(s) { return String(s || '').toLowerCase().replace(/&amp;/g, '&').replace(/https?:\/\//, '').replace(/^www\./, '').replace(LEGAL, ' ').replace(/[^a-z0-9]+/g, ''); }
export function tcNormGroup(s) { return String(s || '').toLowerCase().replace(/ransomware|ransom|team|group|leaks?|blog/g, '').replace(/[^a-z0-9]+/g, ''); }
const siteOf = (s) => { const m = String(s || '').toLowerCase().match(/([a-z0-9-]+\.)+[a-z]{2,}/); return m ? m[0].replace(/^www\./, '') : ''; };
export function leakCrossCheck(tc, rl, groupsCsv = [], now = Date.now()) {
  const rlRows = rl.map((v) => ({ g: tcNormGroup(v.group_name || v.group), group: String(v.group_name || v.group || '').toLowerCase(), n: tcNormName(v.post_title || v.victim || v.name),
    site: siteOf(v.website || v.domain), at: Date.parse(String(v.discovered || v.attackdate || v.published || '').replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(String(v.discovered || '')) ? '' : 'Z')) }))
    .filter((v) => v.g && v.n && isFinite(v.at));
  const tcRows = tc.map((v) => ({ g: tcNormGroup(v.group), group: String(v.group || '').toLowerCase(), n: tcNormName(v.victim), site: siteOf(v.website), at: Date.parse(v.discovered),
    status: String(v.status || '').toLowerCase(), fp: v.first_party === true || String(v.first_party).toLowerCase() === 'yes' || String(v.first_party) === 'true',
    country: v.country || '', sector: v.sector || '' })).filter((v) => v.g && v.n && isFinite(v.at));
  const lo = rlRows.length ? Math.min(...rlRows.map((v) => v.at)) : now - 3 * IX_DAY, hi = rlRows.length ? Math.max(...rlRows.map((v) => v.at)) : now;
  const slack = 2 * IX_DAY;
  const same = (a, b) => a.g === b.g && (a.n === b.n || (a.site && a.site === b.site) || (a.n.length >= 6 && b.n.length >= 6 && (a.n.includes(b.n) || b.n.includes(a.n))));
  const tcWin = tcRows.filter((v) => v.at >= lo - slack && v.at <= hi + slack);
  const groups = new Map();
  const G = (g, label) => { if (!groups.has(g)) groups.set(g, { group: label, tc_30d: 0, tc_first_party_30d: 0, tc_delisted_30d: 0, tc_window: 0, rl_window: 0, both: 0, both_first_party: 0, tc_only: 0, rl_only: 0 }); return groups.get(g); };
  for (const v of tcRows) { const s = G(v.g, v.group); s.tc_30d++; if (v.fp) s.tc_first_party_30d++; if (v.status === 'delisted') s.tc_delisted_30d++; }
  const usedTc = new Set();
  for (const r of rlRows) {
    const s = G(r.g, r.group); s.rl_window++;
    // A row ThreatCluster read off the leak site itself is preferred; its other rows may come from the same aggregators.
    let k = tcWin.findIndex((t, i) => !usedTc.has(i) && t.fp && same(r, t));
    if (k < 0) k = tcWin.findIndex((t, i) => !usedTc.has(i) && same(r, t));
    if (k >= 0) { usedTc.add(k); s.both++; if (tcWin[k].fp) s.both_first_party++; } else s.rl_only++;
  }
  tcWin.forEach((t, i) => { const s = G(t.g, t.group); s.tc_window++; if (!usedTc.has(i) && t.at >= lo && t.at <= hi) s.tc_only++; });
  const gmeta = new Map(groupsCsv.map((g) => [tcNormGroup(g.group), g]));
  const rows = [...groups.entries()].map(([g, s]) => {
    const m = gmeta.get(g) || {};
    return { kind: 'group', ...s, active: m.active ? String(m.active).toLowerCase() === 'yes' : null, mirrors_up: ixNum(m.mirrors_up), last_seen: m.last_seen || null,
      corroboration: s.rl_window ? Math.round((100 * s.both) / s.rl_window) : null, corroboration_first_party: s.rl_window ? Math.round((100 * s.both_first_party) / s.rl_window) : null,
      tc_url: TC_URL.group + encodeURIComponent(s.group) };
  }).sort((x, y) => (y.rl_window + y.tc_window) - (x.rl_window + x.tc_window) || y.tc_30d - x.tc_30d);
  const tot = rows.reduce((t, r) => { for (const k of ['tc_30d', 'tc_first_party_30d', 'tc_delisted_30d', 'tc_window', 'rl_window', 'both', 'both_first_party', 'tc_only', 'rl_only']) t[k] = (t[k] || 0) + r[k]; return t; }, {});
  return { window: { from: new Date(lo).toISOString(), to: new Date(hi).toISOString() }, totals: tot, rows };
}
export async function jobLeaksites() {
  const t0 = Date.now();
  const [v, g, s, r] = await Promise.all([get(TC_URL.victims, { as: 'json', timeout: 30000 }), get(TC_URL.groups, { timeout: 30000 }), get(TC_URL.stats, { as: 'json', timeout: 15000 }),
    cachedGet(TC_URL.rl, { as: 'json', timeout: 25000 })]);
  if (!v.ok || !v.json) throw new Error('ThreatCluster victims HTTP ' + v.status + (v.error ? ' ' + v.error : ''));
  const tc = Array.isArray(v.json) ? v.json : (v.json.victims || v.json.data || []);
  const rl = r.ok && r.json ? (Array.isArray(r.json) ? r.json : (r.json.data || [])) : [];
  const groupsCsv = g.ok ? parseCsv(g.text) : [];
  const x = leakCrossCheck(tc, rl, groupsCsv);
  const doc = { source: 'ThreatCluster dark-web victims (first-party leak-site crawl) cross-checked against ransomware.live recent victims',
    terms: (v.json && v.json.license) || 'CC BY 4.0, attribution ThreatCluster (https://threatcluster.io)', caveat: (v.json && v.json.note) || 'Claims published by extortion groups on their own leak sites.',
    method: 'Groups and organisation names are normalized (case, punctuation, legal suffixes); a claim matches when the group agrees and the name or website agrees. The window is ransomware.live\'s recent-victims span with two days of slack for ThreatCluster dates. ThreatCluster marks the rows it read off the leak site itself (first party); its other rows may come from aggregators that ransomware.live also feeds, so only a match against a first-party row counts as independent corroboration (corroboration_first_party); corroboration counts any match. Delisted means the post stopped being reachable, an observation only. Counts only; no victim names or leak-site addresses are kept.',
    tc_stats: s.ok ? s.json : null, rl_ok: r.ok, generated: new Date().toISOString(), served_from: 'store', ...x, count: x.rows.length };
  await recordVolume([['threatcluster_victims', tc.length]]);
  return { tc: tc.length, rl: rl.length, groups: x.rows.length, totals: x.totals, published: await putDoc('leaksites', doc), ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- Ransomwhere (G55)
// Crowdsourced ransomware payment addresses (Cable, J. 2024, Ransomwhere: A Crowdsourced Ransomware Payment Dataset,
// Zenodo, doi:10.5281/zenodo.6512122, CC BY 4.0). Reports are verified before they appear; amounts in USD use the rate
// at each transaction's time. Aggregated by family; addresses stay out of the document.
export const RW_URL = 'https://api.ransomwhe.re/export';
export function ransomAgg(result, now = Date.now()) {
  const fam = new Map();
  let maxT = 0;
  for (const a of result || []) {
    const f = String(a.family || 'Unknown').trim() || 'Unknown';
    const s = fam.get(f) || { family: f, addresses: 0, transactions: 0, usd: 0, usd_365d: 0, usd_90d: 0, first: null, last: null, chains: {} };
    s.addresses++;
    s.chains[a.blockchain || 'unknown'] = (s.chains[a.blockchain || 'unknown'] || 0) + 1;
    for (const t of a.transactions || []) {
      const ms = Number(t.time) * 1000, usd = Number(t.amountUSD) || 0;
      if (!isFinite(ms) || ms <= 0) continue;
      s.transactions++; s.usd += usd;
      if (now - ms < 365 * IX_DAY) s.usd_365d += usd;
      if (now - ms < 90 * IX_DAY) s.usd_90d += usd;
      if (!s.first || ms < s.first) s.first = ms;
      if (!s.last || ms > s.last) s.last = ms;
      if (ms > maxT) maxT = ms;
    }
    fam.set(f, s);
  }
  const rows = [...fam.values()].map((s) => ({ kind: 'family', ...s, usd: Math.round(s.usd), usd_365d: Math.round(s.usd_365d), usd_90d: Math.round(s.usd_90d),
    first: s.first ? new Date(s.first).toISOString().slice(0, 10) : null, last: s.last ? new Date(s.last).toISOString().slice(0, 10) : null })).sort((x, y) => y.usd - x.usd);
  return { rows, newest_tx: maxT ? new Date(maxT).toISOString().slice(0, 10) : null, families: rows.length,
    totals: rows.reduce((t, r) => ({ addresses: t.addresses + r.addresses, transactions: t.transactions + r.transactions, usd: t.usd + r.usd }), { addresses: 0, transactions: 0, usd: 0 }) };
}
export async function jobRansompay() {
  const t0 = Date.now();
  const r = await get(RW_URL, { as: 'json', timeout: 55000 });
  if (!r.ok || !r.json) throw new Error('Ransomwhere export HTTP ' + r.status + (r.error ? ' ' + r.error : ''));
  const result = Array.isArray(r.json) ? r.json : (r.json.result || []);
  const x = ransomAgg(result);
  const doc = { source: 'Ransomwhere crowdsourced ransomware payment dataset (ransomwhe.re)', terms: 'CC BY 4.0. Cite: Cable, J. (2024). Ransomwhere: A Crowdsourced Ransomware Payment Dataset. Zenodo. https://doi.org/10.5281/zenodo.6512122',
    caveat: 'Reports are crowdsourced and verified before they appear, and addresses are published some time after submission, so recent months are undercounted. USD uses the rate at each transaction. A floor on payments, not a total.',
    generated: new Date().toISOString(), served_from: 'store', ...x, count: x.rows.length };
  await recordVolume([['ransomwhere_addresses', x.totals.addresses]]);
  return { families: x.families, addresses: x.totals.addresses, newest_tx: x.newest_tx, published: await putDoc('ransompay', doc), ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- Unit 42 timely threat notes (G56)
// GPL-3.0 repository; the document keeps the date, title, link and indicator counts by type, never the indicators.
export const U42 = { list: 'https://api.github.com/repos/PaloAltoNetworks/Unit42-timely-threat-intel/contents/', blob: 'https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/' };
export function parseU42(text, name) {
  const lines = String(text || '').split(IX_CR).join('').split('\n');
  const firstLine = (lines.find((l) => l.trim()) || '').trim();
  const m = firstLine.match(/^(\d{4}-\d{2}-\d{2})\s*(?:\([^)]*\))?\s*[:-]?\s*(.*)$/);
  const date = m ? m[1] : String(name || '').slice(0, 10);
  const title = ((m && m[2]) || String(name || '').slice(11).replace(/\.txt$/, '').replace(/-/g, ' ')).trim();
  const counts = { domain: 0, ip: 0, url: 0, sha256: 0, sha1: 0, md5: 0, email: 0 };
  let sec = '', refs = 0;
  const sections = [];
  for (const raw of lines.slice(1)) {
    const l = raw.trim();
    const h = l.match(/^([A-Z][A-Z0-9 /&-]{2,40}):\s*$/);
    if (h) { sec = h[1]; sections.push(sec); continue; }
    if (!l) continue;
    if (/^REFERENCES?/.test(sec)) { if (/https?:\/\//.test(l)) refs++; continue; }
    for (const tok of l.split(/\s+/)) {
      const t = tok.replace(/^[-*([]+|[),.;\]]+$/g, '');
      if (/^[a-f0-9]{64}$/i.test(t)) counts.sha256++;
      else if (/^[a-f0-9]{40}$/i.test(t)) counts.sha1++;
      else if (/^[a-f0-9]{32}$/i.test(t)) counts.md5++;
      else if (!/^INDICATORS?/.test(sec) && !/IOC/.test(sec)) continue;
      else if (/^hxxps?\[?:\]?\/\//i.test(t) || /^https?:\/\//i.test(t)) counts.url++;
      else if (/^[^\s@]+(@|\[@\])[a-z0-9-]+(\[\.\]|\.)[a-z.[\]]+$/i.test(t)) counts.email++;
      else if (/^\d{1,3}(\[\.\]|\.)\d{1,3}(\[\.\]|\.)\d{1,3}(\[\.\]|\.)\d{1,3}(:\d+)?$/.test(t) && t.includes('[.]')) counts.ip++;
      else if (/^([a-z0-9-]+(\[\.\]|\.))+[a-z]{2,}(\/\S*)?$/i.test(t) && t.includes('[.]')) counts.domain++;
    }
  }
  return { date, title, counts, references: refs, sections };
}
export async function jobUnit42() {
  const t0 = Date.now();
  const r = await get(U42.list, { as: 'json', timeout: 20000, headers: { accept: 'application/vnd.github+json' } });
  if (!r.ok || !Array.isArray(r.json)) throw new Error('GitHub contents HTTP ' + r.status + ' ' + (r.text || '').slice(0, 160));
  const files = r.json.filter((f) => f.type === 'file' && /^\d{4}-\d{2}-\d{2}-.+\.txt$/.test(f.name)).sort((a, b) => b.name.localeCompare(a.name)).slice(0, 60);
  const cache = (await kvGet('unit42')) || {};
  const next = {};
  let fetched = 0;
  await pool(files, 6, async (f) => {
    const hit = cache[f.name];
    if (hit && hit.sha === f.sha) { next[f.name] = hit; return; }
    const t = await get(f.download_url, { timeout: 20000 });
    if (!t.ok) { if (hit) next[f.name] = hit; return; }
    fetched++;
    next[f.name] = { sha: f.sha, ...parseU42(t.text, f.name) };
  });
  await kvPut('unit42', next);
  const rows = files.filter((f) => next[f.name]).map((f) => ({ kind: 'note', file: f.name, url: U42.blob + encodeURIComponent(f.name), ...next[f.name], sha: undefined }));
  const posts2026 = r.json.filter((f) => /^2026-/.test(f.name)).length;
  const doc = { source: 'Palo Alto Networks Unit 42 Timely Threat Intel (GitHub)', terms: 'GPL-3.0 repository; facts, titles, dates and counts are shown with attribution and link, without the indicators.',
    method: 'Newest 60 notes. Indicator counts by type are read from each note\'s indicator section (defanged domains, addresses and URLs) and from hashes anywhere in it.',
    generated: new Date().toISOString(), served_from: 'store', posts_2026: posts2026, newest: files[0] ? files[0].name.slice(0, 10) : null, count: rows.length, rows };
  await recordVolume([['unit42_notes', files.length]]);
  return { notes: rows.length, fetched, published: await putDoc('unit42', doc), ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- Gen Threat Labs reference sets (G63)
// Detection Rule License 1.1: use with attribution. Per family: files, hash counts and network indicator counts.
export const GEN = { tree: 'https://api.github.com/repos/gendigitalinc/ioc/git/trees/master?recursive=1', commits: 'https://api.github.com/repos/gendigitalinc/ioc/commits?per_page=1',
  raw: 'https://raw.githubusercontent.com/gendigitalinc/ioc/master/', web: 'https://github.com/gendigitalinc/ioc/tree/master/' };
export const genKey = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
export function genFamilies(tree) {
  const fam = new Map();
  for (const n of tree || []) {
    const parts = String(n.path || '').split('/');
    if (parts.length < 2 || parts[0].startsWith('.')) continue;
    const f = fam.get(parts[0]) || { family: parts[0], files: 0, hash_files: [], network_files: [], yara: 0, bytes: 0 };
    if (n.type === 'blob') {
      f.files++; f.bytes += n.size || 0;
      const leaf = parts[parts.length - 1].toLowerCase();
      if (/\.(sha256|sha1|md5)$/.test(leaf) || /^samples?\b/.test(leaf) && /(sha|md5)/.test(leaf)) f.hash_files.push(n.path);
      else if (/network|domains?|urls?|ips?|c2/.test(leaf) && /\.(txt|csv)$/.test(leaf)) f.network_files.push(n.path);
      else if (/\.(yar|yara)$/.test(leaf)) f.yara++;
    }
    fam.set(parts[0], f);
  }
  return [...fam.values()];
}
export function countLines(text, kind) {
  let n = 0;
  for (const raw of String(text || '').split(IX_CR).join('').split('\n')) {
    const l = raw.trim();
    if (!l || l.startsWith('#')) continue;
    if (kind === 'sha256' ? /^[a-f0-9]{64}\b/i.test(l) : kind === 'sha1' ? /^[a-f0-9]{40}\b/i.test(l) : kind === 'md5' ? /^[a-f0-9]{32}\b/i.test(l) : true) n++;
  }
  return n;
}
export async function jobGenioc() {
  const t0 = Date.now();
  const [tr, cm] = await Promise.all([get(GEN.tree, { as: 'json', timeout: 25000, headers: { accept: 'application/vnd.github+json' } }),
    get(GEN.commits, { as: 'json', timeout: 15000, headers: { accept: 'application/vnd.github+json' } })]);
  if (!tr.ok || !tr.json || !Array.isArray(tr.json.tree)) throw new Error('GitHub tree HTTP ' + tr.status + ' ' + (tr.text || '').slice(0, 160));
  const prev = (await kvGet('genioc')) || {};
  const lastCommit = cm.ok && Array.isArray(cm.json) && cm.json[0] ? (cm.json[0].commit && cm.json[0].commit.committer && cm.json[0].commit.committer.date) || null : null;
  let fams = genFamilies(tr.json.tree);
  if (prev.sha === tr.json.sha && Array.isArray(prev.rows)) fams = prev.rows;
  else {
    await pool(fams, 8, async (f) => {
      f.sha256 = 0; f.sha1 = 0; f.md5 = 0; f.network = 0;
      for (const p of f.hash_files) { const t = await get(GEN.raw + p.split('/').map(encodeURIComponent).join('/'), { timeout: 20000 }); if (t.ok) { const kind = /sha256/i.test(p) ? 'sha256' : /sha1/i.test(p) ? 'sha1' : 'md5'; f[kind] += countLines(t.text, kind); } }
      for (const p of f.network_files) { const t = await get(GEN.raw + p.split('/').map(encodeURIComponent).join('/'), { timeout: 20000 }); if (t.ok) f.network += countLines(t.text, 'any'); }
    });
    fams = fams.map(({ hash_files, network_files, ...f }) => ({ ...f, key: genKey(f.family), url: GEN.web + encodeURIComponent(f.family) }));
    await kvPut('genioc', { sha: tr.json.sha, rows: fams });
  }
  const doc = { source: 'Gen Threat Labs indicators of compromise (github.com/gendigitalinc/ioc)', terms: 'Detection Rule License (DRL) 1.1: use with attribution to Gen Digital Inc. (Gen Threat Labs).',
    attribution: 'Indicators by Gen Threat Labs, Gen Digital Inc., licensed under DRL 1.1.', method: 'One row per family folder: files, YARA rules, and counts of SHA-256, SHA-1 and MD5 hashes and network indicators read from the folder\'s files. Families match the map by name with case and punctuation removed; no fuzzy matching.',
    last_commit: lastCommit, tree: tr.json.sha, generated: new Date().toISOString(), served_from: 'store', count: fams.length, rows: fams.map((f) => ({ kind: 'family', ...f })) };
  return { families: fams.length, reused: prev.sha === tr.json.sha, published: await putDoc('genioc', doc), ms: Date.now() - t0 };
}

