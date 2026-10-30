const { handle, sendJson, q } = require('./_lib');
const store = require('../lib/store');

// History the collector keeps in Postgres, published as documents:
//   ?kind=conflict  daily armed-conflict events by country for 30 days (GDELT), with per-day export coverage
//   ?kind=infra     daily counts of reported malicious infrastructure by layer for 30 days
//   ?kind=uptime    upstream uptime over 24 hours and 7 days, failing streaks, and the collector's own runs
//   ?kind=outages   IODA internet-outage events by country over 7 days
const DOCS = { conflict: 'gdelt-series30', infra: 'threatmap', uptime: 'health', outages: 'ioda' };

module.exports = handle(async (req, res) => {
  const kind = q(req, 'kind', 'conflict');
  const name = DOCS[kind];
  if (!name) return sendJson(res, 400, { error: 'kind must be one of ' + Object.keys(DOCS).join(', ') }, 0);
  const s = await store.getDoc(req, name);
  if (!s.ok) return sendJson(res, 502, { error: 'collector store unavailable', reason: s.reason, kind }, 0);
  let doc = s.doc;
  if (kind === 'infra') {
    const rows = (doc.rows || []).filter((r) => r.kind === 'trend');
    doc = { source: doc.source, generated: doc.generated, served_from: 'store', count: rows.length, rows };
  }
  return sendJson(res, 200, { ...doc, kind, age_min: Math.round(store.ageMin(doc.generated)) }, kind === 'uptime' ? 120 : 600, 3600);
});
