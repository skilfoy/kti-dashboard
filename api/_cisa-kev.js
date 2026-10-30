const { handle, sendJson, upstream } = require('./_lib');
// CISA KEV from the official feed: catalog version and the newest additions, a cross-check on the GitHub mirror.
module.exports = handle(async (req, res) => {
  const r = await upstream('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 25000 });
  if (!r.ok || !r.json) return sendJson(res, 502, { error: 'upstream', status: r.status }, 0);
  const v = (r.json.vulnerabilities || []).slice().sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)));
  const rows = v.slice(0, 60).map((x) => ({ cve: x.cveID, vendor: x.vendorProject, product: x.product, date_added: x.dateAdded, due_date: x.dueDate, ransomware: x.knownRansomwareCampaignUse }));
  sendJson(res, 200, { source: 'CISA KEV (official)', catalogVersion: r.json.catalogVersion, dateReleased: r.json.dateReleased, total: r.json.count, generated: new Date().toISOString(), count: rows.length, rows }, 3600, 21600);
});
