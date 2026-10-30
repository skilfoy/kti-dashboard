// ---------------------------------------------------------------- context feeds: Lanes relationship temperatures, OFAC recent actions
// Shared by the collector's snap job (snap-lanes, snap-ofac) and /api/context, which imports this file on its own, so it
// has no imports. The fetchers take a function url -> Promise<{ok, status, text}>, the collector's get() or the
// service's upstream().
//
// Lanes (lanes.news) publishes daily temperatures for the country pairs it tracks as open data (CC BY 4.0, derived
// from GDELT event files): temperature = 0.6 x share(verbal + material conflict) + 0.4 x min(1, 2 x share(material
// conflict)), article-weighted, 0 cooperative to 1 open conflict. The 7-day means and their change are computed here
// from Lanes' daily rows. Its RSS feed carries one AI-compiled daily page per pair, built from cited reporting and
// labeled by Lanes as not human-reviewed; only the title, link and date are kept.
//
// OFAC retired its RSS feed in January 2025, so the Recent Actions listing (10 entries a page) is read as HTML. The
// entry date comes from the YYYYMMDD in each entry's address; programs, action types and theaters are read from
// OFAC's own title by the rules below, and a title that names no listed program maps to no theater.

export const LANES_URL = { temps: 'https://lanes.news/data/temperatures.csv', rss: 'https://lanes.news/feed.xml', data: 'https://lanes.news/data', bridge: 'https://lanes.news/bridge/' };
export const OFAC_URL = { list: 'https://ofac.treasury.gov/recent-actions', origin: 'https://ofac.treasury.gov' };

// ISO 3166 alpha-3 to alpha-2 for the countries Lanes pairs and the dashboard's theaters; others keep alpha-3 only.
const A3 = { AFG: 'AF', ARE: 'AE', ARG: 'AR', ARM: 'AM', AUS: 'AU', AUT: 'AT', AZE: 'AZ', BHR: 'BH', BFA: 'BF', BIH: 'BA', BLR: 'BY', BRA: 'BR',
  CHN: 'CN', DEU: 'DE', DNK: 'DK', EGY: 'EG', ERI: 'ER', ESP: 'ES', EST: 'EE', ETH: 'ET', FRA: 'FR', GBR: 'GB', GEO: 'GE', IND: 'IN', IRN: 'IR',
  IRQ: 'IQ', ISR: 'IL', JPN: 'JP', KAZ: 'KZ', KGZ: 'KG', KOR: 'KR', KWT: 'KW', LBN: 'LB', LTU: 'LT', LVA: 'LV', MAR: 'MA', MEX: 'MX', MLI: 'ML',
  MYS: 'MY', NER: 'NE', NOR: 'NO', OMN: 'OM', PAK: 'PK', PHL: 'PH', POL: 'PL', PRK: 'KP', PSE: 'PS', QAT: 'QA', RUS: 'RU', SAU: 'SA', SDN: 'SD',
  SOM: 'SO', SRB: 'RS', SYR: 'SY', THA: 'TH', TJK: 'TJ', TUR: 'TR', TWN: 'TW', UKR: 'UA', USA: 'US', UZB: 'UZ', VEN: 'VE', VNM: 'VN', XKX: 'XK', YEM: 'YE' };

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', rsquo: "'", lsquo: "'", ldquo: '"', rdquo: '"', ndash: '-', mdash: '-', hellip: '...' };
export function unent(s) {
  return String(s == null ? '' : s)
    .replace(/&#x([0-9a-f]+);/gi, (m, h) => { const n = parseInt(h, 16); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ''; })
    .replace(/&#(\d+);/g, (m, d) => { const n = +d; return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ''; })
    .replace(/&([a-z]+);/gi, (m, k) => (ENT[k.toLowerCase()] != null ? ENT[k.toLowerCase()] : m));
}
const strip = (s) => unent(String(s || '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();

// RFC 4180 CSV: quoted fields, doubled quotes, CRLF or LF.
export function parseCsv(text) {
  const rows = [];
  let row = [], f = '', q = false;
  const s = String(text || '').split(String.fromCharCode(13)).join('');
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === '"') { if (s[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n') { row.push(f); f = ''; if (row.length > 1 || row[0] !== '') rows.push(row); row = []; }
    else f += c;
  }
  if (f !== '' || row.length) { row.push(f); if (row.length > 1 || row[0] !== '') rows.push(row); }
  if (!rows.length) return [];
  const head = rows[0].map((h) => h.trim());
  return rows.slice(1).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] == null ? '' : r[i]])));
}

const num = (v) => { const n = Number(v); return v === '' || v == null || !isFinite(n) ? null : n; };
const r3 = (x) => (x == null || !isFinite(x) ? null : Math.round(x * 1000) / 1000);
const dayMs = (d) => Date.parse(d + 'T00:00:00Z');

// RSS 2.0 items: title, link, pubDate and the pair slug from /daily/<pair>/<date>.
export function parseLanesRss(xml) {
  const out = [];
  for (const m of String(xml || '').matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)) {
    const it = m[1], low = it.toLowerCase();
    const tag = (name) => {
      const t = name.toLowerCase(), a = low.indexOf('<' + t), gt = a < 0 ? -1 : low.indexOf('>', a), b = gt < 0 ? -1 : low.indexOf('</' + t + '>', gt);
      return b < 0 || /[a-z]/.test(low[a + t.length + 1] || '') ? '' : strip(it.slice(gt + 1, b));
    };
    const link = tag('link') || tag('guid');
    const p = link.match(/\/daily\/([a-z0-9-]+)\/(\d{4}-\d{2}-\d{2})/i);
    const t = Date.parse(tag('pubDate'));
    out.push({ conflict: p ? p[1].toLowerCase() : '', day: p ? p[2] : '', title: tag('title'), url: link, published: isFinite(t) ? new Date(t).toISOString() : '' });
  }
  return out.filter((x) => x.title && /^https:\/\/lanes\.news\//.test(x.url));
}

// One row per pair: the latest day, article-weighted 7-day means (latest 7 days of data and the 7 before), and the
// last 30 days as [date, temperature, articles].
export function lanesDoc(csvText, rssText, generated = new Date().toISOString()) {
  const recs = parseCsv(csvText).filter((r) => r.date && r.conflict && /^\d{4}-\d{2}-\d{2}$/.test(r.date) && num(r.temperature) != null);
  const by = new Map();
  for (const r of recs) { const k = r.conflict.trim().toLowerCase(); if (!by.has(k)) by.set(k, []); by.get(k).push(r); }
  const daily = parseLanesRss(rssText);
  const latestDate = recs.reduce((m, r) => (r.date > m ? r.date : m), '');
  const firstDate = recs.reduce((m, r) => (!m || r.date < m ? r.date : m), '');
  const wmean = (arr) => {
    let w = 0, s = 0;
    for (const r of arr) { const a = num(r.articles) || 0, t = num(r.temperature); if (t == null) continue; const ww = a > 0 ? a : 1; w += ww; s += ww * t; }
    return w ? s / w : null;
  };
  const rows = [];
  for (const [conflict, arr] of by) {
    arr.sort((a, b) => a.date.localeCompare(b.date));
    const last = arr[arr.length - 1];
    const end = dayMs(last.date);
    const inDays = (lo, hi) => arr.filter((r) => { const d = (end - dayMs(r.date)) / 864e5; return d >= lo && d < hi; });
    const w1 = inDays(0, 7), w0 = inDays(7, 14);
    const t7 = wmean(w1), t7p = wmean(w0);
    const a3 = String(last.country_a || '').toUpperCase(), b3 = String(last.country_b || '').toUpperCase();
    const mine = daily.filter((d) => d.conflict === conflict).sort((a, b) => b.published.localeCompare(a.published));
    const latestPub = mine[0] ? Date.parse(mine[0].published) : NaN;
    rows.push({
      conflict, a3, b3, a2: A3[a3] || '', b2: A3[b3] || '', a_name: last.country_a_name || a3, b_name: last.country_b_name || b3,
      date: last.date, temperature: r3(num(last.temperature)), events: num(last.events), articles: num(last.articles),
      goldstein_mean: r3(num(last.goldstein_mean)), tone_mean: r3(num(last.tone_mean)),
      verbal_cooperation_share: r3(num(last.verbal_cooperation_share)), material_cooperation_share: r3(num(last.material_cooperation_share)),
      verbal_conflict_share: r3(num(last.verbal_conflict_share)), material_conflict_share: r3(num(last.material_conflict_share)),
      t7: r3(t7), t7_prev: r3(t7p), delta7: t7 != null && t7p != null ? r3(t7 - t7p) : null, days7: w1.length,
      series: arr.slice(-30).map((r) => [r.date, r3(num(r.temperature)), num(r.articles)]),
      bridge_url: LANES_URL.bridge + conflict,
      daily_title: mine[0] ? mine[0].title : '', daily_url: mine[0] ? mine[0].url : '', daily_published: mine[0] ? mine[0].published : '',
      daily_7d: mine.filter((d) => isFinite(latestPub) && latestPub - Date.parse(d.published) < 7 * 864e5).length,
    });
  }
  rows.sort((a, b) => (b.t7 ?? b.temperature ?? 0) - (a.t7 ?? a.temperature ?? 0));
  const gen = Date.parse(generated);
  return {
    source: 'Lanes News open data (lanes.news/data), derived from the GDELT Project', type: 'lanes', license: 'CC BY 4.0',
    credit: 'Lanes News (2026). Relationship temperatures [data set]. https://lanes.news/data. CC BY 4.0. Derived from the GDELT Project (gdeltproject.org).',
    method: 'temperature = 0.6 x share(verbal + material conflict) + 0.4 x min(1, 2 x share(material conflict)), article-weighted; 0 cooperative, 1 open conflict. t7 and t7_prev are article-weighted means of the latest 7 days of Lanes rows and the 7 before, computed by threat-feeds.',
    daily_note: 'Lanes labels its daily pages AI-compiled from cited reporting and not human-reviewed; only titles and links are kept here.',
    generated, first_date: firstDate, latest_date: latestDate,
    upstream_age_days: latestDate && isFinite(gen) ? Math.floor((gen - dayMs(latestDate)) / 864e5) : null,
    daily_items: daily.length, count: rows.length, rows,
  };
}

export async function fetchLanes(fetchText) {
  const [t, r] = await Promise.all([fetchText(LANES_URL.temps), fetchText(LANES_URL.rss)]);
  if (!t || !t.ok || !t.text) throw new Error('Lanes temperatures HTTP ' + (t ? t.status : 0));
  const doc = lanesDoc(t.text, r && r.ok ? r.text : '');
  if (!doc.count) throw new Error('Lanes temperatures parsed to no rows');
  if (!(r && r.ok)) doc.rss_status = r ? r.status : 0;
  return doc;
}

// ---------------------------------------------------------------- OFAC
// [label, title pattern, theater]. Order matters: South Sudan is tested before Sudan.
export const OFAC_PROGRAMS = [
  ['Iran', /\bIran(?:ian)?\b/i, 'T-HRM'],
  ['Russia', /\bRussia(?:n)?\b/i, 'T-UKR'],
  ['Ukraine', /\bUkraine\b/i, 'T-UKR'],
  ['Belarus', /\bBelarus/i, ''],
  ['Venezuela', /\bVenezuela/i, 'T-VEN'],
  ['North Korea', /\bNorth Korea|\bDPRK\b/i, 'T-KOR'],
  ['Cuba', /\bCuba/i, ''],
  ['Burma', /\bBurma|\bMyanmar/i, ''],
  ['Syria', /\bSyria/i, 'T-LEV'],
  ['Lebanon', /\bLebanon|\bHizballah|\bHezbollah/i, 'T-LEV'],
  ['DR Congo', /\bDemocratic Republic of the Congo|\bDRC\b|\bCongo-related/i, ''],
  ['South Sudan', /\bSouth Sudan/i, ''],
  ['Sudan', /(?<!South )\bSudan/i, 'T-SDN'],
  ['Yemen', /\bYemen|\bHouthi|\bAnsarallah/i, 'T-RSY'],
  ['Iraq', /\bIraq/i, ''],
  ['Afghanistan', /\bAfghanistan|\bTaliban/i, 'T-AFP'],
  ['Western Balkans', /\bBalkans/i, 'T-BAL'],
  ['Somalia', /\bSomalia/i, 'T-HOA'],
  ['Ethiopia', /\bEthiopia/i, 'T-HOA'],
  ['Mali', /\bMali\b/i, 'T-SAH'],
  ['Libya', /\bLibya/i, ''],
  ['Nicaragua', /\bNicaragua/i, ''],
  ['China', /\bChina\b|\bChinese\b|\bHong Kong/i, ''],
  ['Mexico cartels', /\bCartels?\b|\bCJNG\b|\bSinaloa|\bMexic/i, 'T-MEX'],
  ['Counter Terrorism', /\bCounter[- ]?Terrorism|\bTerrorism\b|\bTerrorist/i, ''],
  ['Counter Narcotics', /\bCounter[- ]?Narcotics|\bNarcotics?\b|\bFentanyl|\bIllicit Drug/i, ''],
  ['Cyber', /\bCyber/i, ''],
  ['Global Magnitsky', /\bMagnitsky/i, ''],
  ['Transnational Criminal Organizations', /\bTransnational Criminal/i, ''],
  ['International Criminal Court', /\bInternational Criminal Court\b/i, ''],
  ['PAIPA', /\bPAIPA\b|Protecting American Intellectual Property/i, ''],
  ['Non-proliferation', /\bNon-?proliferation|\bWeapons of Mass Destruction/i, ''],
  ['Hostage-taking', /\bHostage|\bWrongful(?:ly)? Detain/i, ''],
];
export const OFAC_ACTIONS = [
  ['Designation removal', /\bRemovals?\b|\bDelist/i],
  ['Designation', /\bDesignations?\b(?!\s+(?:Removals?|Updates?)\b)/i],
  ['Designation update', /\bDesignations?\s+Updates?\b|\bIdentification Updates?\b/i],
  ['General license', /\bGeneral Licen[cs]es?\b/i],
  ['FAQ', /\bFrequently Asked Questions?\b|\bFAQs?\b/i],
  ['Enforcement', /\bSettlement\b|\bCivil Penalt|\bFinding of Violation|\bEnforcement\b|\bPenalty\b/i],
  ['Advisory or guidance', /\bAdvisory\b|\bAlert\b|\bGuidance\b/i],
  ['Regulation', /\bRegulations?\b|\bFederal Register\b|\bFinal Rule\b|\bInterim Final\b/i],
];
export function ofacTags(title) {
  const t = String(title || '');
  const programs = [], theaters = [], actions = [];
  for (const [label, re, th] of OFAC_PROGRAMS) if (re.test(t)) { programs.push(label); if (th && !theaters.includes(th)) theaters.push(th); }
  for (const [label, re] of OFAC_ACTIONS) if (re.test(t)) actions.push(label);
  return { programs, theaters, actions, cyber: programs.includes('Cyber') };
}

// Entries are links to /recent-actions/YYYYMMDD[_NN]; each one's category is the next /recent-actions/<slug> link
// within 1,500 characters of it.
export function parseOfacList(html) {
  const s = String(html || '');
  const out = [], seen = new Set();
  let open = null;
  for (const m of s.matchAll(/<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    let href = unent(m[1]).trim();
    if (href.startsWith(OFAC_URL.origin)) href = href.slice(OFAC_URL.origin.length);
    href = href.split('#')[0];
    const e = href.match(/^\/recent-actions\/(\d{8})(?:_(\d+))?\/?$/);
    if (e) {
      const id = e[1] + (e[2] ? '_' + e[2] : '');
      const title = strip(m[2]);
      if (!title || seen.has(id)) { open = null; continue; }
      seen.add(id);
      const day = e[1].slice(0, 4) + '-' + e[1].slice(4, 6) + '-' + e[1].slice(6, 8);
      open = { id, date: day, title, url: OFAC_URL.origin + '/recent-actions/' + id, category: '', category_slug: '', at: m.index };
      out.push(open);
      continue;
    }
    const c = href.match(/^\/recent-actions\/([a-z][a-z0-9-]*)\/?$/);
    if (c && open && !open.category && m.index - open.at < 1500) { open.category = strip(m[2]); open.category_slug = c[1]; open = null; }
  }
  return out.map(({ at, ...r }) => r);
}

export function ofacDoc(pages, generated = new Date().toISOString()) {
  const all = new Map();
  let total = null;
  for (const html of pages || []) {
    const tm = String(html || '').match(/Displaying\s+\d+\s*-\s*\d+\s+of\s+([\d,]+)\s+results/i);
    if (tm && total == null) total = +tm[1].replace(/,/g, '');
    for (const r of parseOfacList(html)) if (!all.has(r.id)) all.set(r.id, r);
  }
  const rows = [...all.values()].map((r) => {
    const t = ofacTags(r.title);
    return { ...r, programs: t.programs.join('; '), actions: t.actions.join('; '), theaters: t.theaters.join(','), cyber: t.cyber ? 'Yes' : 'No' };
  }).sort((a, b) => b.date.localeCompare(a.date) || b.id.localeCompare(a.id));
  return {
    source: 'U.S. Treasury OFAC Recent Actions (ofac.treasury.gov/recent-actions)', type: 'ofac', generated,
    method: 'Entries read from the Recent Actions listing; the date is the one in the entry address. Programs, action types and theaters are matched in OFAC titles by named rules; a title naming no listed program maps to no theater.',
    total_listed: total, newest: rows.length ? rows[0].date : '', count: rows.length, rows,
  };
}

export async function fetchOfac(fetchText, pages = 2) {
  const urls = Array.from({ length: pages }, (_, i) => OFAC_URL.list + (i ? '?page=' + i : ''));
  const res = [];
  for (const u of urls) res.push(await fetchText(u));
  if (!res[0] || !res[0].ok || !res[0].text) throw new Error('OFAC Recent Actions HTTP ' + (res[0] ? res[0].status : 0));
  const doc = ofacDoc(res.filter((r) => r && r.ok).map((r) => r.text));
  if (!doc.count) throw new Error('OFAC Recent Actions parsed to no entries');
  doc.pages_read = res.filter((r) => r && r.ok).length;
  return doc;
}

