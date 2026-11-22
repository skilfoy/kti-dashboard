// Maritime security (split from 37-intel.mjs, whose helpers it uses).
// ---------------------------------------------------------------- maritime security (G60)
// Public government sources, read in one job:
//   MARAD    U.S. Maritime Administration MSCI advisories: the advisories in force by region and threat, with effective
//            and expiry dates (maritime.dot.gov/msci-advisories; U.S. government work). The site's Akamai edge refused
//            the collector's cloud address with HTTP 403 on 22 October 2026; the job still asks and records the answer.
//   ASAM     NGA Maritime Safety Information Anti-Shipping Activity Messages: dated, positioned reports of hostile acts
//            against ships (msi.nga.mil; U.S. government work). On 22 October 2026 the API answered 404 to the query the
//            MSI web application itself builds, so the service appears withdrawn; the job keeps asking, and probe
//            nga_bundle reads the application's script for any new path.
//   NAVWARN  NGA broadcast navigational warnings in force (NAVAREA IV and XII, HYDROLANT, HYDROPAC, HYDROARC), sorted by
//            their wording into security categories and placed by the positions they give. On 22 October 2026 the list
//            held no warning issued after May 2024, so the staleness check below keeps it off the map. From November 2026
//            the whole MSI portal answered 503 with a maintenance page; while the API does not answer, the job reads the
//            same warnings from NGA's daily memoranda (one plain-text file per area, linked from that page).
//   UKMTO    its incident page sits behind a Cloudflare rule that refused the collector's address with HTTP 403 on
//            22 October 2026; the job still asks and records the answer, so a lifted block shows up in the document.
// Blocked sources are recorded as refused; the job sends its ordinary request and nothing meant to get around a block.
export const MARAD_URL = 'https://www.maritime.dot.gov/msci-advisories';
// The query as the MSI web application builds it (read from its script on 22 October 2026): a filter clause (filter=none
// when no reference, area or subregion is chosen) and both ends of the date range.
export const ASAM_URL = (from, to) => 'https://msi.nga.mil/api/publications/asam?filter=none&minOccurDate=' + from + '&maxOccurDate=' + (to || new Date().toISOString().slice(0, 10)) + '&sort=date&output=json';
export const NAVWARN_URL = 'https://msi.nga.mil/api/publications/broadcast-warn?output=json&status=A';
// NGA's daily memoranda: the broadcast warnings in force for each area as plain text, one file per area. During the MSI
// portal outage that began in November 2026 (every /api/publications route answering 503 with a maintenance page) NGA
// links these files from the maintenance page itself; the download route is where the portal serves them when it is up.
// The job reads them only when the broadcast-warning API does not answer.
export const NGA_MEMO_AREAS = [['IV', '4'], ['XII', '12'], ['LAN', 'A'], ['PAC', 'P'], ['ARC', 'C']];
export const NGA_MEMO_URLS = (code) => ['https://msi.nga.mil/api/publications/apology_objects/DailyMem' + code + '.txt',
  'https://msi.nga.mil/api/publications/download?type=view&key=16920957/SFH00000/DailyMem' + code + '.txt'];
export const UKMTO_URL = { api: 'https://www.ukmto.org/api/incidents', page: 'https://www.ukmto.org/recent-incidents', origin: 'https://www.ukmto.org' };
const pickF = (o, ...ks) => { for (const k of ks) if (o && o[k] != null && o[k] !== '') return o[k]; return null; };
// Advisory titles and positions to the dashboard's theaters; the first match wins, so Houthi and Red Sea wording takes
// an advisory that also names the Gulf of Aden, and piracy advisories for the Gulf of Aden and Somali Basin fall to T-HOA.
const SEA_THEATER = [[/Houthi|Red Sea|Bab el Mandeb/i, 'T-RSY'], [/Black Sea|Sea of Azov/i, 'T-UKR'], [/Persian Gulf|Hormuz|Gulf of Oman/i, 'T-HRM'],
  [/Gulf of Aden|Somali|Indian Ocean|Arabian Sea/i, 'T-HOA'], [/Taiwan/i, 'T-TWN'], [/South China Sea|Spratly|Scarborough/i, 'T-SCS'],
  [/Eastern Mediterranean|Israel|Lebanon|Syria/i, 'T-LEV'], [/Venezuela|Caribbean/i, 'T-VEN'], [/Baltic|North Sea/i, 'T-EUH']];
export const seaTheater = (text) => { for (const [re, t] of SEA_THEATER) if (re.test(String(text || ''))) return t; return null; };
// Boxes [w, s, e, n] for positioned reports, checked in order: the Gulf before the Red Sea box, which reaches east to
// the Gulf of Aden; the Taiwan Strait before the South China Sea.
const SEA_BOX = [['T-TWN', [117, 21, 125, 27]], ['T-SCS', [105, 0, 122, 23]], ['T-KOR', [124, 33, 132, 43.5]], ['T-HRM', [47, 22, 60, 30.5]],
  ['T-RSY', [32, 11, 51.5, 30]], ['T-HOA', [41, -12, 70, 11]], ['T-UKR', [27, 40, 42, 48]], ['T-LEV', [31, 31, 36.5, 37]],
  ['T-EUH', [9, 53, 31, 66.5]], ['T-VEN', [-75, 8, -59, 16]]];
export const seaBox = (lat, lon) => { if (lat == null || lon == null) return null; for (const [t, [w, s, e, n]] of SEA_BOX) if (lon >= w && lon <= e && lat >= s && lat <= n) return t; return null; };
const mdy = (s) => { const m = String(s).match(/^(\d{2})\/(\d{2})\/(\d{4})$/); return m ? `${m[3]}-${m[1]}-${m[2]}` : null; };
export function parseMarad(html, now = Date.now()) {
  const s = String(html || ''), today = isoDay(now), rows = [], seen = new Set();
  const take = (href, id, inner, ctx) => {
    if (seen.has(id)) return;
    seen.add(id);
    const title = ixText(inner), text = ixText(ctx);
    const status = /\bCancell?ed\b/i.test(text) ? 'cancelled' : /\bActive\b/i.test(text) ? 'active' : /\bExpired\b/i.test(text) ? 'expired' : null;
    const dates = (text.match(/\b\d{2}\/\d{2}\/\d{4}\b/g) || []).map(mdy).filter(Boolean);
    const body = title.replace(/^\d{4}-\d{3}\s*-\s*/, '');
    const cut = body.indexOf('-');
    const region = (cut > 0 ? body.slice(0, cut) : body).trim();
    let threat = cut > 0 ? body.slice(cut + 1).trim() : '';
    if (threat.toLowerCase().startsWith(region.toLowerCase() + '-')) threat = threat.slice(region.length + 1).trim();
    const effective = dates[0] || null, expires = dates[1] || null;
    let url = href;
    try { url = new URL(unent(href), MARAD_URL).href; } catch { /* keep */ }
    rows.push({ kind: 'advisory', id, title, region, threat, status, effective, expires,
      in_force: status === 'active' && (!expires || expires >= today), lapsed: status === 'active' && !!expires && expires < today, theater: seaTheater(title), url });
  };
  const A = /<a\b[^>]*href\s*=\s*["']([^"']*\/msci\/(\d{4}-\d{3})[^"']*)["'][^>]*>([\s\S]*?)<\/a>/i;
  for (const tr of s.split(/<tr\b/i).slice(1)) {
    const seg = tr.split(/<\/tr>/i)[0], a = seg.match(A);
    if (a) take(a[1], a[2], a[3], seg);
  }
  if (!rows.length) {
    const re = new RegExp(A.source, 'gi');
    let m;
    while ((m = re.exec(s))) take(m[1], m[2], m[3], m[0]);
  }
  return rows;
}
export function parseAsam(j) {
  const arr = Array.isArray(j) ? j : j && typeof j === 'object' ? (j.asam || j.asams || j.data || Object.values(j).find(Array.isArray)) : null;
  if (!Array.isArray(arr)) return [];
  return arr.map((r) => {
    const lat = ixNum(pickF(r, 'latitude', 'lat')), lon = ixNum(pickF(r, 'longitude', 'lon', 'lng'));
    return { kind: 'asam', id: String(pickF(r, 'reference', 'id') || ''), date: String(pickF(r, 'date', 'occurDate') || '').slice(0, 10), lat, lon,
      navarea: pickF(r, 'navArea', 'navarea'), subreg: pickF(r, 'subreg', 'subregion'), hostility: ixText(pickF(r, 'hostility', 'aggressor') || ''),
      victim: ixText(pickF(r, 'victim') || ''), text: ixText(pickF(r, 'description', 'desc') || '').slice(0, 320), theater: seaBox(lat, lon) };
  }).filter((r) => r.id || r.date);
}
const GNSS = /\b(GPS|GNSS)\b[\s\S]{0,160}\b(INTERFERENCE|JAMMING|SPOOFING|UNRELIABLE|DEGRADED|DENIAL)\b|\b(INTERFERENCE|JAMMING|SPOOFING)\b[\s\S]{0,160}\b(GPS|GNSS)\b/i;
// Security categories read from the warning's own wording, first match wins: hostile acts against shipping, mines and
// explosive ordnance, GNSS interference, then military activity (firing, exercises, missile and rocket launches and their
// debris). Navigation warnings outside these (drilling units, cables, aids to navigation, search and rescue) are counted
// as other and not listed.
export const NAVWARN_CAT = [
  ['hostile', /\b(PIRACY|PIRATES?|ARMED ROBBERY|HIJACK(ED|ING)?|BOARDED|ATTACK(ED|S)?|SUSPICIOUS APPROACH|HOSTILE|UNMANNED (AERIAL|SURFACE) VEHICLES?|UAVS?|USVS?|DRONES?|PROJECTILES?|KIDNAPP(ED|ING))\b/],
  ['mines', /\b(MINES?|MINEFIELDS?|MINE DANGER|UNEXPLODED ORDNANCE|UXO|EXPLOSIVE ORDNANCE|EXPLOSIVE HAZARD)\b/],
  ['gnss', GNSS],
  ['military', /\b(GUNNERY|MISSILES?|ROCKETS?|LIVE FIR(E|ING)|FIRING EXERCISES?|MILITARY (EXERCISES?|OPERATIONS)|NAVAL (EXERCISES?|OPERATIONS)|HAZARDOUS OPERATIONS|SPACE DEBRIS|WEAPONS? (FIRING|TESTING)|AIR DEFEN[CS]E)\b/],
];
export const NAVAREA_LABEL = { 4: 'NAVAREA IV', 12: 'NAVAREA XII', A: 'HYDROLANT', P: 'HYDROPAC', C: 'HYDROARC' };
// NGA writes positions as degrees-minutes(-seconds) with a hemisphere: 19-23.0N 092-03.1W or 35-10-30N 129-05-00E.
const NW_POS = /(\d{1,2})-(\d{1,2}(?:\.\d+)?)(?:-(\d{1,2}(?:\.\d+)?))?\s*([NS])\s*,?\s+(\d{1,3})-(\d{1,2}(?:\.\d+)?)(?:-(\d{1,2}(?:\.\d+)?))?\s*([EW])/g;
export function navPositions(text) {
  const out = [];
  for (const m of String(text || '').matchAll(NW_POS)) {
    const lat = (+m[1] + +m[2] / 60 + (+m[3] || 0) / 3600) * (m[4] === 'S' ? -1 : 1), lon = (+m[5] + +m[6] / 60 + (+m[7] || 0) / 3600) * (m[8] === 'W' ? -1 : 1);
    if (Math.abs(lat) <= 90 && Math.abs(lon) <= 180 && +m[2] < 60 && +m[6] < 60) out.push([Math.round(lat * 1000) / 1000, Math.round(lon * 1000) / 1000]);
  }
  return out;
}
// One marker per warning: the mean of its positions when they lie within 5 degrees of each other (an area or a track),
// otherwise its first position, flagged spread (a list of separate places).
export function navPoint(pos) {
  if (!pos.length) return null;
  const lats = pos.map((p) => p[0]), lons = pos.map((p) => p[1]);
  const spread = Math.max(...lats) - Math.min(...lats) > 5 || Math.max(...lons) - Math.min(...lons) > 5;
  if (spread) return { lat: pos[0][0], lon: pos[0][1], spread: true };
  const avg = (a) => Math.round((a.reduce((s, x) => s + x, 0) / a.length) * 1000) / 1000;
  return { lat: avg(lats), lon: avg(lons), spread: false };
}
// NGA date-time groups: 101515Z MAY 2024 (day, hour, minute, month, year) to ISO.
const MON = { JAN: '01', FEB: '02', MAR: '03', APR: '04', MAY: '05', JUN: '06', JUL: '07', AUG: '08', SEP: '09', OCT: '10', NOV: '11', DEC: '12' };
export function ngaDtg(s) {
  // The daily memoranda write the year with two digits (181530Z NOV 26), the API with four.
  const m = String(s || '').toUpperCase().match(/(\d{2})(\d{2})(\d{2})Z\s+([A-Z]{3})\s+(\d{4}|\d{2})(?!\d)/);
  return m && MON[m[4]] ? `${m[5].length === 2 ? '20' + m[5] : m[5]}-${MON[m[4]]}-${m[1]}T${m[2]}:${m[3]}:00Z` : null;
}
// A source whose newest record is older than this is reported stale and kept off the map and the theater counts:
// broadcast warnings are issued daily, ASAM reports a few times a month worldwide.
export const SEA_STALE_DAYS = 45;
export const ASAM_STALE_DAYS = 120;
export function parseNavwarn(j) {
  const arr = Array.isArray(j) ? j : j && typeof j === 'object' ? (j['broadcast-warn'] || j.broadcastWarn || j.data || Object.values(j).find(Array.isArray)) : null;
  if (!Array.isArray(arr)) return null;
  const out = { total: arr.length, newest: null, gnss: 0, by_area: {}, by_category: { hostile: 0, mines: 0, gnss: 0, military: 0, other: 0 }, by_theater: {}, rows: [] };
  for (const w of arr) {
    const text = String(pickF(w, 'text', 'msgText') || '');
    const at = ngaDtg(pickF(w, 'issueDate', 'issued'));
    if (at && (!out.newest || at > out.newest)) out.newest = at;
    const up = text.toUpperCase();
    const cat = (NAVWARN_CAT.find(([, re]) => re.test(up)) || ['other'])[0];
    out.by_category[cat]++;
    if (cat === 'other') continue;
    const area = String(pickF(w, 'navArea', 'navarea', 'area') || '?');
    if (cat === 'gnss') { out.gnss++; out.by_area[area] = (out.by_area[area] || 0) + 1; }
    const pos = navPositions(text), pt = navPoint(pos), theater = pt ? seaBox(pt.lat, pt.lon) : null;
    if (theater) { const t = (out.by_theater[theater] = out.by_theater[theater] || { hostile: 0, mines: 0, gnss: 0, military: 0 }); t[cat]++; }
    out.rows.push({ kind: 'navwarn', category: cat, area, area_label: NAVAREA_LABEL[area] || area, id: [pickF(w, 'msgNumber', 'number'), pickF(w, 'msgYear', 'year')].filter((x) => x != null).join('/'),
      issued: String(pickF(w, 'issueDate', 'issued') || '').slice(0, 25), issued_at: at, subregion: pickF(w, 'subregion', 'subreg'), lat: pt ? pt.lat : null, lon: pt ? pt.lon : null,
      spread: pt ? pt.spread : undefined, positions: pos.length, theater, text: ixText(text).slice(0, 320) });
  }
  return out;
}
// A daily memorandum to the records parseNavwarn reads. Each warning opens with its area, number and year
// (HYDROPAC 3456/26(98). or NAVAREA IV 1234/26.); its date-time group is the first one in the warning or on the line
// just above its header. A file that is not plain text (the maintenance page, an error page) gives null.
const MEMO_HEAD = /^[ \t]*(NAVAREA[ \t]+(?:IV|XII)|HYDROLANT|HYDROPAC|HYDROARC)[ \t]+(\d{1,5})\/(\d{2,4})\b/gm;
const MEMO_AREA = { 'NAVAREA IV': '4', 'NAVAREA XII': '12', HYDROLANT: 'A', HYDROPAC: 'P', HYDROARC: 'C' };
const DTG_RE = /\d{6}Z\s+[A-Z]{3}\s+(?:\d{4}|\d{2})(?!\d)/;
export function parseDailyMem(text, area) {
  const s = String(text || '').replace(/\r\n?/g, '\n');
  if (!s.trim() || /<(?:!doctype|html|head|body)\b/i.test(s.slice(0, 2000))) return null;
  const heads = [...s.matchAll(MEMO_HEAD)];
  return heads.map((h, i) => {
    const body = s.slice(h.index, i + 1 < heads.length ? heads[i + 1].index : s.length).trim();
    const above = s.slice(Math.max(0, h.index - 40), h.index).split('\n').filter((l) => l.trim()).pop() || '';
    const dtg = (body.toUpperCase().match(DTG_RE) || above.toUpperCase().match(DTG_RE) || [null])[0];
    const yr = h[3].length === 2 ? 2000 + +h[3] : +h[3];
    return { msgNumber: +h[2], msgYear: yr, navArea: MEMO_AREA[h[1].replace(/[ \t]+/, ' ')] || area || '?', text: body, issueDate: dtg };
  });
}
export function parseUkmto(j) {
  let arr = Array.isArray(j) ? j : j && (j.incidents || j.data || j.items || j.results || j.features || (j.props && j.props.pageProps && (j.props.pageProps.incidents || j.props.pageProps.data)));
  if (arr && !Array.isArray(arr) && Array.isArray(arr.items)) arr = arr.items;
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const row of arr) {
    const p = row && row.properties ? { ...row.properties, ...(row.geometry && Array.isArray(row.geometry.coordinates) ? { lon: row.geometry.coordinates[0], lat: row.geometry.coordinates[1] } : {}) } : row || {};
    const lat = Number(pickF(p, 'lat', 'latitude', 'Lat', 'Latitude', 'locationLatitude'));
    const lon = Number(pickF(p, 'lon', 'lng', 'longitude', 'Lon', 'Lng', 'Longitude', 'locationLongitude'));
    const date = String(pickF(p, 'date', 'incidentDate', 'incident_date', 'dateOfIncident', 'date_of_incident', 'createdAt', 'Date') || '');
    out.push({ kind: 'ukmto', id: String(pickF(p, 'incidentNumber', 'reference', 'ref', 'id', 'incident_id', 'slug') || ''), title: ixText(pickF(p, 'title', 'name', 'incidentTitle', 'Name') || 'Maritime incident'),
      type: ixText(pickF(p, 'type', 'category', 'incidentType', 'incident_type', 'Type') || ''), date: date.slice(0, 25), lat: isFinite(lat) ? lat : null, lon: isFinite(lon) ? lon : null,
      region: ixText(pickF(p, 'region', 'area', 'location', 'locationName') || ''), url: (() => { const s = pickF(p, 'url', 'link', 'slug'); return s ? (/^https?:/.test(s) ? s : UKMTO_URL.origin + '/recent-incidents/' + String(s).replace(/^\//, '')) : UKMTO_URL.page; })() });
  }
  return out;
}
// Press-reported incidents (3.13.0). Since 21 November 2026 none of the four official sources has answered the collector
// (MARAD 403 at the Akamai edge, NGA 503 on the API and the memoranda, UKMTO 403), while the source network keeps
// collecting the maritime trade press and UKMTO's own feed. Entries of the last 14 days whose title or summary reports a
// security incident are placed in a theater by the same wording rules as advisories, else by the feed's theater. They
// are reports, not advisories: counted apart, and listed with the publisher.
export const SEA_PRESS_RE = /\b(attack(?:ed|s)?|hijack\w*|boarded|boarding|pirac\w*|pirates?|armed robbery|robbers?|seiz(?:ed|ure|es)|detain(?:ed|s)?|missiles?|drones?|UAVs?|USVs?|explosions?|explosives?|limpet|sea ?mines?|naval mines?|GNSS|GPS (?:jamming|interference)|jamming|spoof\w*|suspicious approach|skiffs?|UKMTO|JMIC|ReCAAP|Houthis?|stowaways?|shadow fleet|dark fleet|(?:drone|missile|air|naval|bridge|tanker|vessel|ship)[- ]?strikes?|airstrikes?)\b/i;
// Places the trade press names that the advisory wording rules do not, checked after them.
const PRESS_PLACES = [[/Hodeida|Yemen|Mokha|Ras Isa|Salif|Eritrea|Jeddah|Yanbu/i, 'T-RSY'], [/\bIran|Bandar Abbas|Fujairah|Khor Fakkan|Kharg|IRGC/i, 'T-HRM'],
  [/Somali|Puntland|\bEyl\b|Mogadishu|Djibouti|Berbera/i, 'T-HOA'], [/Ukrain|Odesa|Odessa|Novorossiysk|Crimea|Sevastopol|Kerch/i, 'T-UKR'],
  [/Philippine|Second Thomas|Paracel|China Coast Guard/i, 'T-SCS'], [/Kinmen|Matsu/i, 'T-TWN'], [/Gulf of Finland|Estlink|Balticconnector|shadow fleet|dark fleet/i, 'T-EUH'],
  [/Haifa|Ashdod|Beirut|Gaza/i, 'T-LEV'], [/North Korea|Yellow Sea/i, 'T-KOR'], [/Guyana/i, 'T-VEN']];
const pressPlace = (text) => { for (const [re, t] of PRESS_PLACES) if (re.test(text)) return t; return null; };
// Headlines that use incident words for something else: weapons programmes, market and insurance stories, meetings,
// and cyber attacks, which the cyber side of the collection carries.
export const SEA_PRESS_NOT = /\b(attack craft|attack submarines?|attack boats? (?:order|contract|programme|program)|cyber[- ]?attacks?|ransomware|insurance|premiums?|freight|rates|prices?|webinar|conference|meeting|summit|award\w*|contracts?|unveil\w*|develop\w*|concept|commission\w*|launch(?:es|ed)? (?:of|new)|order(?:s|ed)? for)\b/i;
export function pressIncidents(items = []) {
  const out = [], seen = new Set();
  for (const it of items) {
    const title = String(it.title || '').replace(/\s+/g, ' ').trim(), text = title + ' ' + String(it.summary || '');
    if (!title || !SEA_PRESS_RE.test(text) || SEA_PRESS_NOT.test(title)) continue;
    const theater = seaTheater(text) || pressPlace(text) || (/^T-[A-Z]{3}$/.test(it.region || '') ? it.region : null);
    if (!theater) continue;
    const key = title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 80);
    if (seen.has(key)) continue;
    seen.add(key);
    const d = it.published || it.seen_at;
    out.push({ kind: 'press', title, date: d ? new Date(d).toISOString().slice(0, 10) : null, url: it.link, publisher: it.host || null, theater, lang: it.lang || null });
  }
  return out.sort((x, y) => String(y.date).localeCompare(String(x.date)));
}
export function maritimeDoc({ marad, asam, navwarn, ukmto, press, status, now = Date.now() }) {
  const adv = (marad || []).filter((a) => a.status === 'active');
  const inc = (asam || []).filter((r) => r.date).sort((x, y) => String(y.date).localeCompare(String(x.date)));
  const byTheater = {};
  const d30 = isoDay(now - 30 * IX_DAY);
  const T = (id) => (byTheater[id] = byTheater[id] || { advisories: 0, incidents_90d: 0, incidents_30d: 0, warnings: 0, warn_hostile: 0, warn_mines: 0, warn_gnss: 0, warn_military: 0, press_7d: 0, press_14d: 0 });
  const d7 = isoDay(now - 7 * IX_DAY);
  for (const r of press || []) { const t = T(r.theater); t.press_14d++; if (r.date >= d7) t.press_7d++; }
  for (const a of adv) if (a.in_force && a.theater) T(a.theater).advisories++;
  for (const r of inc) if (r.theater) { const t = T(r.theater); t.incidents_90d++; if (r.date >= d30) t.incidents_30d++; }
  for (const [id, c] of Object.entries((navwarn && navwarn.by_theater) || {})) { const t = T(id); for (const k of ['hostile', 'mines', 'gnss', 'military']) { t['warn_' + k] += c[k] || 0; t.warnings += c[k] || 0; } }
  // Warnings first in priority order, so the row cap drops military notices before hostile acts.
  const rank = { hostile: 0, mines: 1, gnss: 2, military: 3 };
  const warns = ((navwarn && navwarn.rows) || []).slice().sort((x, y) => rank[x.category] - rank[y.category] || (y.lat != null) - (x.lat != null));
  const rows = adv.concat(inc.slice(0, 250), warns.slice(0, 220), (ukmto || []).slice(0, 100), (press || []).slice(0, 150));
  const official = (status || []).filter((x) => x.id !== 'PRESS');
  return { source: 'Maritime security: MARAD MSCI advisories, NGA ASAM reports and NGA broadcast navigational warnings (U.S. government works); UKMTO where reachable; incidents reported in the maritime trade press and UKMTO\'s feed, from the source network',
    degraded: official.length > 0 && !official.some((x) => x.ok), press_14d: (press || []).length,
    terms: 'U.S. government works are not subject to copyright in the United States; UKMTO material is Crown copyright under the Open Government Licence.',
    method: 'Advisories in force are those MARAD lists as active whose expiry date has not passed; an active listing past its expiry is marked lapsed. ASAM reports cover 90 days and are placed in a theater by position. NGA broadcast warnings in force are sorted by their own wording into hostile acts, mines and ordnance, GNSS interference, military activity (firing, exercises, missile and rocket launches) and other navigation notices; each listed warning is placed at the mean of the positions it gives (its first position when they lie more than 5 degrees apart) and in a theater by that point. Warnings are notices of hazards declared by the issuing authority, not reports of incidents. Press-reported incidents are entries of the last 14 days from the maritime trade press and UKMTO\'s feed whose title or summary reports a security incident, placed in a theater by their wording or the feed\'s theater, one per headline; they are reports, counted apart from official advisories and incidents.',
    sources: status, by_theater: byTheater, advisories_in_force: adv.filter((a) => a.in_force).length, asam_90d: inc.length,
    gnss: navwarn ? { total_warnings: navwarn.total, gnss: navwarn.gnss, by_area: navwarn.by_area } : null,
    navwarn: navwarn ? { total: navwarn.total, by_category: navwarn.by_category, listed: warns.length, positioned: warns.filter((w) => w.lat != null).length } : null,
    generated: new Date(now).toISOString(), served_from: 'store', count: rows.length, rows };
}
export async function jobMaritime() {
  const t0 = Date.now(), status = [];
  const note = (id, url, r, n, extra) => status.push({ id, url, ok: !!(r.ok && n), status: r.status, n, error: r.ok ? (n ? null : 'parsed no rows') : (r.error || 'HTTP ' + r.status), ...(extra || {}) });
  const from = isoDay(Date.now() - 90 * IX_DAY);
  const [m, a, w, u] = await Promise.all([get(MARAD_URL, { timeout: 25000, headers: { accept: 'text/html' } }), get(ASAM_URL(from), { as: 'json', timeout: 25000, headers: { accept: 'application/json' } }),
    get(NAVWARN_URL, { as: 'json', timeout: 25000, headers: { accept: 'application/json' } }), get(UKMTO_URL.api, { as: 'json', timeout: 15000, headers: { accept: 'application/json' } })]);
  const marad = m.ok ? parseMarad(m.text) : [];
  note('MARAD', MARAD_URL, m, marad.length, m.status === 403 ? { error: "refused by the site's Akamai edge (HTTP 403)" } : null);
  const asam = a.ok ? parseAsam(a.json) : [];
  // An empty 90-day window could be a quiet sea or a source that stopped publishing; the current and previous year
  // tell the two apart.
  let asamNewest = asam.reduce((x, r) => (r.date > x ? r.date : x), '') || null;
  if (a.ok && !asam.length) {
    const y = new Date().getUTCFullYear();
    for (const yr of [y, y - 1]) {
      const r = await get(`https://msi.nga.mil/api/publications/asam?filter=none&year=${yr}&sort=date&output=json`, { as: 'json', timeout: 25000, headers: { accept: 'application/json' } });
      const rows = r.ok ? parseAsam(r.json) : [];
      asamNewest = rows.reduce((x, q) => (q.date > x ? q.date : x), '') || null;
      if (asamNewest) break;
    }
  }
  const asamStale = !asamNewest || Date.now() - Date.parse(asamNewest) > ASAM_STALE_DAYS * IX_DAY;
  note('ASAM', ASAM_URL(from), a, asam.length, a.ok ? { newest: asamNewest, stale: asamStale || undefined,
    error: asam.length ? null : asamNewest ? `no reports in the 90-day window; newest report ${asamNewest}` + (asamStale ? ' (source not current)' : '') : 'no reports in this or last year' } : null);
  let navAll = w.ok ? parseNavwarn(w.json) : null, navVia = null;
  // The broadcast-warning API down: the same warnings from NGA's daily memoranda, one file per area.
  if (!navAll) {
    const memo = await Promise.all(NGA_MEMO_AREAS.map(async ([code, area]) => {
      for (const url of NGA_MEMO_URLS(code)) {
        const r = await get(url, { timeout: 20000, headers: { accept: 'text/plain' } });
        const rows = r.ok ? parseDailyMem(r.text, area) : null;
        if (rows) return { code, url, rows, modified: r.headers && typeof r.headers.get === 'function' ? r.headers.get('last-modified') : null };
      }
      return { code, rows: null };
    }));
    const read = memo.filter((x) => x.rows);
    if (read.length) {
      navAll = parseNavwarn(read.flatMap((x) => x.rows));
      // A memorandum without date-time groups is dated by the newest file, so a current file is not called stale.
      const mod = read.map((x) => Date.parse(x.modified || '')).filter(isFinite);
      if (!navAll.newest && mod.length) navAll.newest = new Date(Math.max(...mod)).toISOString();
      navVia = { via: 'NGA daily memoranda (' + read.map((x) => x.code).join(', ') + ')', api_status: w.status, memo_missing: memo.filter((x) => !x.rows).map((x) => x.code) };
    }
  }
  const navStale = !!navAll && (!navAll.newest || Date.now() - Date.parse(navAll.newest) > SEA_STALE_DAYS * IX_DAY);
  // NGA's broadcast-warning API answered on 22 October 2026 with warnings issued no later than May 2024; a list frozen
  // like that is reported stale and kept out of the map and the counts, since its "in force" status cannot be trusted.
  const navwarn = navStale ? null : navAll;
  note('NAVWARN', NAVWARN_URL, navVia ? { ok: true, status: 200 } : w, navAll && !navStale ? navAll.total : 0, navAll ? { ...(navVia || {}), newest: navAll.newest, stale: navStale || undefined,
    error: navStale ? `stale: the newest warning listed in force was issued ${String(navAll.newest || 'at an unknown date').slice(0, 10)}; the list is not current` : null } : null);
  const ukmto = u.ok && u.json ? parseUkmto(u.json) : [];
  note('UKMTO', UKMTO_URL.api, u, ukmto.length, u.status === 403 ? { error: "refused by the site's Cloudflare rule (HTTP 403)" } : null);
  let press = [];
  try {
    const items = await sql(`SELECT link, coalesce(title_en, title) AS title, left(summary, 400) AS summary, host, region, lang, published, seen_at FROM ti.item
      WHERE (category = 'maritime' OR host IN ('ukmto.org', 'www.ukmto.org')) AND seen_at > now() - interval '14 days' ORDER BY seen_at DESC LIMIT 3000`);
    press = pressIncidents(items);
    status.push({ id: 'PRESS', url: '/api/search?category=maritime', ok: press.length > 0, status: 200, n: press.length, newest: press.length ? press[0].date : null,
      via: `${new Set(press.map((r) => r.publisher)).size} publishers in the source network, ${items.length} maritime entries read`, error: press.length ? null : 'no incident reported in 14 days of maritime entries' });
  } catch (e) { status.push({ id: 'PRESS', url: '/api/search?category=maritime', ok: false, status: 0, n: 0, error: String(e.message || e).slice(0, 160) }); }
  if (!marad.length && !asam.length && !navAll && !ukmto.length && !press.length) throw new Error('maritime: no source answered: ' + JSON.stringify(status).slice(0, 600));
  const doc = maritimeDoc({ marad, asam: asamStale ? [] : asam, navwarn, ukmto, press, status });
  doc.stale_sources = status.filter((x) => x.stale).map((x) => ({ id: x.id, newest: x.newest || null }));
  await recordVolume([['marad', marad.length], ['asam', asam.length], ['navwarn_security', navwarn ? navwarn.rows.length : 0], ['maritime_press', press.length]]);
  return { sources: status.map((x) => x.id + ':' + (x.ok ? x.n : 'fail ' + x.status)), published: await putDoc('maritime', doc), ms: Date.now() - t0 };
}

