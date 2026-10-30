// ---------------------------------------------------------------- SEC Form 8-K cybersecurity disclosures (G54)
// Since 18 December 2023 U.S.-listed companies report material cybersecurity incidents under Form 8-K Item 1.05; some
// disclose under Item 8.01 (other events) instead. The job reads EDGAR full-text search (efts.sec.gov) twice a day over
// 90 days of filings. SEC's fair-access policy asks for a declared User-Agent naming the requester and a contact
// address, and at most ten requests a second; SEC_USER_AGENT in the function environment holds the contact Sean chose
// (22 October 2026), and the job makes at most twelve requests a run, one at a time. Scoring follows Yet Another
// Ransomware Tracker's weights and is listed with each row: Item 1.05 5, "ransomware" 2, "cyber attack" or
// "cybersecurity incident" 1. Rows are Item 1.05 filings, their amendments, and Item 8.01 filings that match an
// incident term. Company names are the filers' own public disclosures.
export const SEC_FTS = 'https://efts.sec.gov/LATEST/search-index';
const SEC_QUERIES = [
  { id: 'item105', q: '"Item 1.05"', forms: '8-K' },
  { id: 'ransomware', q: '"ransomware"', forms: '8-K' },
  { id: 'cyberattack', q: '"cyber attack" OR "cyberattack"', forms: '8-K' },
  { id: 'incident', q: '"cybersecurity incident"', forms: '8-K' },
];
// SIC code to the dashboard's verticals (8 critical-infrastructure lenses), then to SIC divisions for the rest.
export function secVertical(sic) {
  const n = Number(sic);
  if (!isFinite(n) || n <= 0) return { vertical: null, sector: 'Unclassified' };
  if (n === 4941 || n === 4952) return { vertical: 'water', sector: 'Water and wastewater' };
  if ((n >= 4900 && n <= 4999) || (n >= 1300 && n <= 1399) || (n >= 2900 && n <= 2999) || (n >= 4610 && n <= 4619)) return { vertical: 'energy', sector: 'Energy and utilities' };
  if (n >= 6000 && n <= 6799) return { vertical: 'financial', sector: 'Financial services' };
  if ((n >= 8000 && n <= 8099) || (n >= 2830 && n <= 2836) || (n >= 3841 && n <= 3851)) return { vertical: 'healthcare', sector: 'Healthcare' };
  if (n >= 4800 && n <= 4899) return { vertical: 'telecom', sector: 'Telecommunications' };
  if (n >= 9100 || (n >= 3760 && n <= 3769) || n === 3812 || (n >= 3480 && n <= 3489)) return { vertical: 'government', sector: 'Government and defense' };
  if (n >= 4000 && n <= 4799) return { vertical: 'transportation', sector: 'Transportation and logistics' };
  if (n >= 2000 && n <= 3999) return { vertical: 'manufacturing', sector: 'Manufacturing' };
  if (n >= 7370 && n <= 7379) return { vertical: null, sector: 'Software and IT services' };
  if (n >= 5000 && n <= 5199) return { vertical: null, sector: 'Wholesale trade' };
  if (n >= 5200 && n <= 5999) return { vertical: null, sector: 'Retail trade' };
  if (n >= 7000 && n <= 8999) return { vertical: null, sector: 'Services' };
  if (n >= 1500 && n <= 1799) return { vertical: null, sector: 'Construction' };
  if (n >= 1000 && n <= 1499) return { vertical: null, sector: 'Mining' };
  return { vertical: null, sector: 'Agriculture, forestry and fishing' };
}
const SCORE = { item105: 5, ransomware: 2, cyberattack: 1, incident: 1 };
// Hits from the four queries to one row per filing (adsh), with the queries that matched it. Each hit is one document
// of the filing; file_type tells the 8-K's own text (8-K, 8-K/A) from its exhibits (EX-99.1, EX-10.1 and so on).
const mainDoc = (s) => /^8-K/i.test(String((s && s.file_type) || ''));
export function secRows(byQuery, now = Date.now()) {
  const by = new Map();
  for (const [qid, hits] of Object.entries(byQuery)) {
    for (const h of hits || []) {
      const s = h && h._source;
      if (!s || !s.adsh) continue;
      const file = String(h._id || '').split(':')[1] || '';
      const r = by.get(s.adsh) || { s, file, matched: new Set(), main: new Set() };
      r.matched.add(qid);
      if (mainDoc(s)) { r.main.add(qid); if (!mainDoc(r.s)) { r.s = s; r.file = file; } }
      by.set(s.adsh, r);
    }
  }
  const rows = [];
  for (const [adsh, { s, file, matched, main }] of by) {
    const items = (s.items || []).map(String);
    const is105 = items.includes('1.05');
    const is801 = items.includes('8.01');
    const terms = [...matched].filter((q) => q !== 'item105');
    const mainTerms = [...main].filter((q) => q !== 'item105');
    // Item 1.05 by the filing's own item list. Item 8.01 only when an incident term appears in the 8-K's own text:
    // a match only in an exhibit is almost always boilerplate (a credit agreement's covenants, an earnings release's
    // forward-looking statements), as a check of the 22 October 2026 results showed. Other items are left out.
    if (!is105 && !(is801 && mainTerms.length)) continue;
    const name = String((s.display_names || [])[0] || '');
    const m = name.match(/^(.*?)\s+(?:\(([A-Z0-9.,\- ]{1,30})\)\s+)?\(CIK\s+(\d+)\)\s*$/);
    const cik = String((s.ciks || [])[0] || (m && m[3]) || '').replace(/^0+/, '');
    const sic = String((s.sics || [])[0] || '');
    const v = secVertical(sic);
    const score = (is105 ? SCORE.item105 : 0) + terms.reduce((t, q) => t + (SCORE[q] || 0), 0);
    rows.push({ kind: 'filing', company: (m ? m[1] : name).trim(), ticker: m && m[2] ? m[2].split(',')[0].trim() : null, cik, sic: sic || null, sector: v.sector, vertical: v.vertical,
      financial: v.vertical === 'financial', form: s.form || s.file_type || '8-K', amendment: /\/A$/.test(String(s.form || s.file_type || '')), items, item_105: is105,
      item_801: is801 && !is105, terms, in_8k_text: mainTerms, score, filed: s.file_date || null, period: s.period_ending || null, state: (s.biz_states || [])[0] || null, adsh,
      url: cik ? `https://www.sec.gov/Archives/edgar/data/${cik}/${adsh.replace(/-/g, '')}/${adsh}-index.htm` : null,
      doc_url: cik && file ? `https://www.sec.gov/Archives/edgar/data/${cik}/${adsh.replace(/-/g, '')}/${file}` : null });
  }
  // An amendment links to the company's latest earlier original that the rows hold.
  rows.sort((a, b) => String(b.filed).localeCompare(String(a.filed)) || b.score - a.score);
  for (const r of rows) {
    if (!r.amendment) continue;
    const orig = rows.find((o) => !o.amendment && o.cik === r.cik && String(o.filed) <= String(r.filed));
    if (orig) r.amends = orig.adsh;
  }
  return rows;
}
// EDGAR full-text search filters on the root form, so forms=8-K returns 8-K and 8-K/A filings alike; a list of
// "8-K,8-K/A" returned amendments only (22 October 2026). Form names are fixed in SEC_QUERIES and need no escaping.
export const secUrl = (q, forms, from, to, page = 0) => `${SEC_FTS}?q=${encodeURIComponent(q)}&forms=${String(forms).replace(/[^A-Z0-9,/-]/g, '')}&dateRange=custom&startdt=${from}&enddt=${to}${page ? '&from=' + page * 100 : ''}`;
async function secSearch(q, forms, from, to, ua, page = 0) {
  const u = secUrl(q, forms, from, to, page);
  return get(u, { as: 'json', timeout: 20000, headers: { 'user-agent': ua, accept: 'application/json' } });
}
export async function jobSec8k() {
  const t0 = Date.now(), ua = ENV().SEC_USER_AGENT || '';
  if (!ua) throw new Error('SEC_USER_AGENT is not set: SEC fair access needs a declared contact');
  const to = isoDay(Date.now()), from = isoDay(Date.now() - 90 * IX_DAY);
  const byQuery = {}, status = [];
  let requests = 0;
  for (const Q of SEC_QUERIES) {
    byQuery[Q.id] = [];
    // Each hit is one document, so a filing can take several; three pages of 100 cover a quarter's 8-Ks per term.
    for (let page = 0; page < 3; page++) {
      if (requests) await new Promise((r) => setTimeout(r, 250));
      requests++;
      const r = await secSearch(Q.q, Q.forms, from, to, ua, page);
      const hits = r.ok && r.json && r.json.hits ? r.json.hits.hits || [] : [];
      const total = r.ok && r.json && r.json.hits && r.json.hits.total ? r.json.hits.total.value : null;
      status.push({ query: Q.id, page, ok: r.ok, status: r.status, hits: hits.length, total, error: r.ok ? null : r.error || 'HTTP ' + r.status });
      byQuery[Q.id].push(...hits);
      if (!r.ok || hits.length < 100) break;
    }
  }
  if (!status.some((x) => x.ok)) throw new Error('EDGAR full-text search: no query answered: ' + JSON.stringify(status).slice(0, 400));
  const rows = secRows(byQuery);
  const f105 = rows.filter((r) => r.item_105 && !r.amendment);
  const doc = { source: 'SEC EDGAR full-text search: Form 8-K and 8-K/A filings citing Item 1.05 (material cybersecurity incidents), and Item 8.01 filings matching incident terms',
    terms: 'EDGAR filings are public records of the U.S. Securities and Exchange Commission; access follows SEC fair-access rules (declared User-Agent, at most 10 requests a second).',
    method: 'Four full-text queries over 90 days ("Item 1.05", "ransomware", "cyber attack" or "cyberattack", "cybersecurity incident"), root form 8-K (originals and amendments). A filing is kept when its own item list includes 1.05 (a disclosed material cybersecurity incident), or 8.01 with an incident term in the 8-K\'s own text (a candidate, to be read before it is treated as a disclosure; matches only in exhibits are boilerplate and left out). Score: Item 1.05 5, ransomware 2, cyber attack or cybersecurity incident 1 (Yet Another Ransomware Tracker weights). Sector from the filer\'s SIC code; amendments link to the latest earlier original held.',
    window: { from, to }, queries: status, item_105_90d: f105.length, item_105_30d: f105.filter((r) => String(r.filed) >= isoDay(Date.now() - 30 * IX_DAY)).length,
    financial_90d: rows.filter((r) => r.financial).length, item_801_90d: rows.filter((r) => r.item_801).length, generated: new Date().toISOString(), served_from: 'store', count: rows.length, rows };
  await recordVolume([['sec_8k_105', f105.length]]);
  return { requests, filings: rows.length, item_105: f105.length, published: await putDoc('sec-8k', doc), ms: Date.now() - t0 };
}

