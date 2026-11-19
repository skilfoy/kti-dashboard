const { handle, sendJson, q } = require('./_lib');
const store = require('../lib/store');

// Entity graph (3.4.0), answered by the collector from Postgres (neon/parts/37k-entities.mjs):
//   /api/graph                      the summary: rising and new entities, the most named per type, the strongest co-mentions
//   /api/graph?id=actor:G0007       one entity: names, mentions per day, co-mentioned entities with counts, publishers and
//                                   normalized PMI, curated relationships (ATT&CK, MISP, KEV) and the latest entries
//   /api/graph?a=<id>&b=<id>        the entries that name both, and any curated relationship between them
//   /api/graph?q=fancy&t=actor      entities by name or alias
// days=7..400 sets the window of the entity and pair views (default 90).
const ID = /^(actor|extortion|malware|tool|campaign|vendor|product|cve|country):[A-Za-z0-9:._\-]{1,120}$/;
module.exports = handle(async (req, res) => {
  const id = String(q(req, 'id', '')), a = String(q(req, 'a', '')), b = String(q(req, 'b', '')), term = String(q(req, 'q', '')).slice(0, 80);
  const days = Math.max(7, Math.min(400, +q(req, 'days', 90) || 90));
  if (!id && !a && !term) {
    const s = await store.getDoc(req, 'entities');
    if (!s.ok) return sendJson(res, 502, { error: 'not collected yet', store: s.reason || 'missing' }, 0);
    return sendJson(res, 200, { ...s.doc, age_min: Math.round(store.ageMin(s.doc.generated)) }, 300, 1800);
  }
  let path;
  if (id) { if (!ID.test(id)) return sendJson(res, 400, { error: 'bad id' }, 0); path = `/graph?id=${encodeURIComponent(id)}&days=${days}`; }
  else if (a) { if (!ID.test(a) || !ID.test(b)) return sendJson(res, 400, { error: 'a and b must be entity ids' }, 0); path = `/graph?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}&days=${days}`; }
  else { if (term.trim().length < 2) return sendJson(res, 400, { error: 'q must be two characters or more' }, 0); path = `/graph?q=${encodeURIComponent(term)}&t=${encodeURIComponent(String(q(req, 't', '')).slice(0, 12))}`; }
  const r = await store.call(req, path, { timeout: 20000 });
  if (!r.ok && r.status !== 404 && r.status !== 400) return sendJson(res, 502, { error: 'graph unavailable', reason: r.reason || 'HTTP ' + r.status }, 0);
  const body = JSON.parse(r.buf.toString('utf8') || '{}');
  sendJson(res, r.ok ? 200 : r.status, { source: 'KTI entity graph', generated: new Date().toISOString(), ...body }, r.ok ? 300 : 60, r.ok ? 1800 : 300);
});
