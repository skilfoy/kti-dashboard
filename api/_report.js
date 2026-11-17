const crypto = require('crypto');
const { cors, sendJson, q } = require('./_lib');
const store = require('../lib/store');

// Agentic reports (3.0).
//   POST /api/report {q, type: brief|exec|technical|summary|practitioner, prompt}   queue a report, answers {id}
//   GET  /api/report?id=R-...                                                      the report, its progress and sources
//   GET  /api/report?list=1                                                        recent finished reports
// The collector writes the report with a free reasoning model and free client-side web search (neon/parts/37i-report.mjs).
// Requests are limited per address (hashed, never stored raw) and per day.
const parseBody = async (req) => {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { return {}; } }
  const chunks = []; for await (const c of req) chunks.push(c);
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { return {}; }
};
module.exports = async (req, res) => {
  res.__req = req;
  cors(res);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  try {
    if (req.method === 'POST') {
      const b = await parseBody(req);
      const ip = String(req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || '').split(',')[0].trim();
      const r = await store.call(req, '/report', { method: 'POST', timeout: 20000, body: JSON.stringify({ q: b.q, type: b.type, prompt: b.prompt,
        ip: crypto.createHash('sha256').update('kti|' + ip).digest('hex') }) });
      const out = r.buf ? JSON.parse(r.buf.toString('utf8') || '{}') : { error: r.reason };
      return sendJson(res, r.ok ? 200 : r.status || 502, out, 0);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'method_not_allowed' }, 0);
    if (q(req, 'list', '')) {
      const r = await store.call(req, '/reports?limit=' + encodeURIComponent(q(req, 'limit', '30')), { timeout: 15000 });
      return sendJson(res, r.ok ? 200 : 502, r.ok ? JSON.parse(r.buf.toString('utf8')) : { error: r.reason || 'HTTP ' + r.status }, 30, 120);
    }
    const id = String(q(req, 'id', ''));
    if (!/^R-\d{8}-[0-9a-f]{8}$/.test(id)) return sendJson(res, 400, { error: 'id required' }, 0);
    const r = await store.call(req, '/report/' + id, { timeout: 15000 });
    if (!r.ok) return sendJson(res, r.status === 404 ? 404 : 502, { error: r.status === 404 ? 'not found' : r.reason || 'HTTP ' + r.status }, 0);
    const rep = JSON.parse(r.buf.toString('utf8'));
    sendJson(res, 200, rep, rep.status === 'done' ? 3600 : 0, 86400);
  } catch (e) { sendJson(res, 502, { error: 'proxy_error', message: String((e && e.message) || e) }, 0); }
};
