const { handle, sendJson, q } = require('./_lib');
const store = require('../lib/store');

// On-demand enrichment of one public indicator, answered by the collector (GET /enrich), which holds the cl0q key and a
// day's cache: ?type=asn|ip|domain|hash|actor&q=<value>. Each result names its analyzer, its public page and when it was
// read. Inputs are checked here by type and length and again by the collector, which refuses private addresses.
const TYPES = new Set(['asn', 'ip', 'domain', 'hash', 'actor']);
module.exports = handle(async (req, res) => {
  const type = q(req, 'type', ''), value = q(req, 'q', '').trim();
  if (!TYPES.has(type) || !value || value.length > 253) return sendJson(res, 400, { error: 'type must be one of ' + [...TYPES].join(', ') + ' and q a value' }, 0);
  const r = await store.call(req, '/enrich?type=' + encodeURIComponent(type) + '&q=' + encodeURIComponent(value), { timeout: 40000 });
  let body;
  try { body = JSON.parse(r.buf.toString('utf8')); } catch { body = { error: 'collector', reason: r.reason || 'unreadable answer' }; }
  return sendJson(res, r.ok ? 200 : r.status || 502, body, r.ok ? 300 : 0, r.ok ? 3600 : 0);
});
