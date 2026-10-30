const { handle, sendJson, upstream, q } = require('./_lib');
// GDELT DOC 2.0. ?query=...&timespan=7d&mode=timelinevol|artlist
module.exports = handle(async (req, res) => {
  const query = q(req, 'query', '');
  if (!query) return sendJson(res, 400, { error: 'missing_query' }, 0);
  const tsMap = { '1h': '1h', '6h': '6h', '24h': '24h', '48h': '2d', '72h': '3d', '7d': '7d', '14d': '14d', '30d': '30d' };
  const ts = tsMap[q(req, 'timespan', '7d')] || '7d';
  const mode = q(req, 'mode', 'timelinevol') === 'artlist' ? 'artlist' : 'timelinevol';
  const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(query)}&mode=${mode}&format=json&timespan=${ts}` + (mode === 'artlist' ? '&maxrecords=50&sort=datedesc' : '');
  const r = await upstream(url, { timeout: 25000 });
  if (!r.ok || !r.json) return sendJson(res, 502, { error: 'upstream', status: r.status, body: (r.text || '').slice(0, 200) }, 0);
  let rows;
  if (mode === 'timelinevol') {
    const series = (r.json.timeline && r.json.timeline[0] && r.json.timeline[0].data) || [];
    rows = series.map((p) => ({ date: p.date, volume: Number(p.value) }));
  } else {
    rows = (r.json.articles || []).map((a) => ({ title: a.title, url: a.url, domain: a.domain, seendate: a.seendate, sourcecountry: a.sourcecountry, language: a.language }));
  }
  sendJson(res, 200, { source: 'GDELT DOC 2.0', query, timespan: ts, mode, generated: new Date().toISOString(), count: rows.length, rows }, 900, 3600);
});
