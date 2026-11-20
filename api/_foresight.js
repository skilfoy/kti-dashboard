const { handle, sendJson, q } = require('./_lib');
const store = require('../lib/store');

// Threatcasting futures (3.9.0), from the collector's foresight document (neon/parts/37p-foresight.mjs).
//   /api/foresight                 every theater's futures, readings and the drafting attempts of the last 60 days
//   /api/foresight?theater=T-HRM   one theater
// Futures are drafted by a free hosted model and accepted by deterministic checks; the reading counts signposts met
// against the analyst's indicator states and is never a forecast.
const THEATER = /^T-[A-Z]{2,4}$/;

module.exports = handle(async (req, res) => {
  const s = await store.getDoc(req, 'foresight');
  if (!s.ok) return sendJson(res, 502, { error: 'not collected yet', store: s.reason || 'missing' }, 0);
  const theater = String(q(req, 'theater', '')).toUpperCase();
  if (theater && !THEATER.test(theater)) return sendJson(res, 400, { error: 'theater must be a theater id such as T-HRM' }, 0);
  const rows = theater ? (s.doc.rows || []).filter((r) => r.theater_id === theater) : s.doc.rows || [];
  const { signposts, ...doc } = s.doc;
  sendJson(res, 200, { ...doc, rows, count: rows.length, age_min: Math.round(store.ageMin(s.doc.generated)) }, 300, 1200);
});
