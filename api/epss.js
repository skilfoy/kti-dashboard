const { handle, sendJson, upstream, q } = require('./_lib');
const store = require('../lib/store');
// FIRST EPSS. ?cve=CVE-1,CVE-2 for named CVEs, otherwise the day's highest scores (?limit=N).
module.exports = handle(async (req, res) => {
  const cve = q(req, 'cve', '');
  const limit = Math.min(parseInt(q(req, 'limit', '100'), 10) || 100, 2000);
  let url = `https://api.first.org/data/v1/epss?envelope=false&limit=${limit}`;
  url += cve ? `&cve=${encodeURIComponent(cve)}` : '&order=!epss';
  const r = await upstream(url, { timeout: 20000 }).catch((e) => ({ ok: false, status: 0, error: String(e.message || e) }));
  if (!r.ok || !r.json) {
    // Last-good copy of the day's 200 highest scores, kept by the collector.
    const s = !cve && limit === 200 ? await store.getDoc(req, 'snap-epss') : { ok: false };
    if (s.ok) return sendJson(res, 200, { ...s.doc, served_from: 'store-stale', stale: true, age_min: Math.round(store.ageMin(s.doc.generated)), upstream_status: r.status }, 300, 1800);
    return sendJson(res, 502, { error: 'upstream', status: r.status }, 0);
  }
  const data = Array.isArray(r.json) ? r.json : (r.json.data || []);
  const rows = data.map((d) => ({ cve: d.cve, epss: Number(d.epss), percentile: Number(d.percentile), date: d.date }));
  sendJson(res, 200, { source: 'FIRST EPSS', generated: new Date().toISOString(), count: rows.length, rows }, 3600, 21600);
});
