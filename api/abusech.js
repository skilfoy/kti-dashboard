const { handle, sendJson, upstream, q } = require('./_lib');
const store = require('../lib/store');
// abuse.ch. ?feed=threatfox (recent IOCs) | feodo (botnet C2 blocklist).
module.exports = handle(async (req, res) => {
  if (q(req, 'feed', 'threatfox') === 'feodo') {
    const r = await upstream('https://feodotracker.abuse.ch/downloads/ipblocklist.json', { timeout: 20000 });
    if (!r.ok || !r.json) return sendJson(res, 502, { error: 'upstream', status: r.status }, 0);
    const rows = r.json.map((d) => ({ ip: d.ip_address, port: d.port, malware: d.malware, status: d.status, first_seen: d.first_seen, last_online: d.last_online, country: d.country, as_name: d.as_name }));
    return sendJson(res, 200, { source: 'abuse.ch Feodo Tracker', generated: new Date().toISOString(), count: rows.length, rows }, 300, 1800);
  }
  // abuse.ch closed the keyless ThreatFox export on 21 October 2026 (HTTP 410) and now issues Auth-Keys, which stay off
  // Vercel. ThreatFox comes from the collector's copy (snap-threatfox, refreshed every 30 minutes when the collector holds
  // a key); a copy older than a day is not served as current.
  const s = await store.getDoc(req, 'snap-threatfox');
  const age = s.ok ? store.ageMin(s.doc.generated) : null;
  if (!s.ok || age > 1440) {
    return sendJson(res, 503, { error: 'ThreatFox needs an abuse.ch Auth-Key since 21 October 2026; no current collector copy', gated: true,
      last_copy: s.ok ? s.doc.generated : null, terms: 'https://abuse.ch/terms-of-use/' }, 60);
  }
  const lim = Math.min(parseInt(q(req, 'limit', '1000'), 10) || 1000, 1000);
  const rows = (s.doc.rows || []).slice(0, lim);
  sendJson(res, 200, { ...s.doc, rows, count: rows.length, served_from: age <= 90 ? 'store' : 'store-stale', stale: age > 90, age_min: Math.round(age) }, 60, 300);
});
