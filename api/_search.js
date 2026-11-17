const { handle, sendJson, q } = require('./_lib');
const store = require('../lib/store');

// Platform search (3.0): /api/search?q=&days=1..45&category=&region=&limit=&offset=
// Full-text over every entry the source network collected in the last 45 days (title and publisher summary) and the
// advisory feeds, each hit with its machine-triage label. The collector answers from Postgres (neon/parts/37h-sources.mjs).
module.exports = handle(async (req, res) => {
  const query = String(q(req, 'q', '')).slice(0, 200);
  if (query.trim().length < 2) return sendJson(res, 400, { error: 'q must be two characters or more' }, 0);
  const body = JSON.stringify({ q: query, days: +q(req, 'days', 30), category: q(req, 'category', ''), region: q(req, 'region', ''), limit: +q(req, 'limit', 50), offset: +q(req, 'offset', 0) });
  const r = await store.call(req, '/search', { method: 'POST', body, timeout: 25000 });
  if (!r.ok) return sendJson(res, 502, { error: 'search unavailable', reason: r.reason || 'HTTP ' + r.status }, 0);
  sendJson(res, 200, { source: 'KTI source network and advisory feeds', generated: new Date().toISOString(), ...JSON.parse(r.buf.toString('utf8')) }, 60, 300);
});
