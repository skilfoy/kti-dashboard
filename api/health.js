const { handle, sendJson, upstream } = require('./_lib');
const store = require('../lib/store');

// Whether the upstreams behind the proxied routes answer right now, with latency (short timeouts), plus what the collector
// has recorded: uptime over 24 hours and 7 days for every feed it checks every 30 minutes (the GDELT DOC API among them, which
// rate-limits cloud egress and feeds no layer, so it is not probed live), failing streaks, its own job runs and Infocon,
// and each feed's latest snapshot size against its 30-day median (spike and silence flags).
module.exports = handle(async (req, res) => {
  const checks = {
    epss: 'https://api.first.org/data/v1/epss?envelope=false&limit=1',
    ransomware_live: 'https://api.ransomware.live/v2/recentvictims',
    feodo: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
    cisa_kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  };
  // Edge cache window (seconds) each data endpoint uses, so the page can say how fresh a refresh can be.
  const ttl = { epss: 3600, ransomware_live: 60, feodo: 300, cisa_kev: 3600 };
  // abuse.ch closed the keyless ThreatFox export on 21 October 2026; /api/abusech?feed=threatfox serves the collector's copy.
  const out = { threatfox: { ok: false, status: 410, error: 'keyless export closed by abuse.ch on 21 Oct 2026; served from the collector when it holds an Auth-Key', ttl: 300 } };
  const [s] = await Promise.all([
    store.getDoc(req, 'health', { timeout: 6000 }),
    ...Object.entries(checks).map(async ([k, u]) => {
      try { const r = await upstream(u, { timeout: 10000 }); out[k] = { ok: r.ok, status: r.status, ms: r.ms, ttl: ttl[k] }; }
      catch (e) { out[k] = { ok: false, error: String((e && e.message) || e), ttl: ttl[k] }; }
    }),
  ]);
  const collector = s.ok
    ? { ok: true, generated: s.doc.generated, checked_at: s.doc.checked_at, infocon: s.doc.infocon,
        feeds: (s.doc.rows || []).filter((r) => r.kind === 'feed'), jobs: (s.doc.rows || []).filter((r) => r.kind === 'job'),
        volume: (s.doc.rows || []).filter((r) => r.kind === 'volume') }
    : { ok: false, reason: s.reason };
  sendJson(res, 200, { service: 'threat-feeds', at: new Date().toISOString(), upstreams: out, collector, oidc: store.hasToken(req) }, 30, 120);
});
