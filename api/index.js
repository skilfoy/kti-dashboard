const { handle, sendJson, q, isOperator } = require('./_lib');

// One function serves the service index and the low-traffic reference routes, which keeps the deployment inside the
// Hobby plan's limit of twelve functions. vercel.json rewrites /api/actors, /api/gdelt, /api/cisa-kev and /api/context
// here with ?route=, so their public paths are unchanged; the handlers live in underscore files, which Vercel does not
// deploy as functions of their own.
const ROUTES = { actors: () => require('./_actors'), gdelt: () => require('./_gdelt'), 'cisa-kev': () => require('./_cisa-kev'), context: () => require('./_context'), enrich: () => require('./_enrich') };

const index = handle(async (req, res) => {
  sendJson(res, 200, {
    service: 'threat-feeds', purpose: 'Server-side OSINT proxy for the Global threat intelligence site',
    endpoints: ['/api/health', '/api/epss?cve=|limit=', '/api/ransomware?type=recentvictims|groups|recentcyberattacks', '/api/gdelt?query=&timespan=&mode=', '/api/abusech?feed=threatfox|feodo&limit=&summary=1', '/api/cisa-kev', '/api/gdelt-events?hours=1..24&quad=4|3,4&top=&flows=&live=1', '/api/exposure?domains=&vendors=&terms=&ips=',
      '/api/threatmap?live=1&format=compact', '/api/history?kind=conflict|infra|uptime|outages', '/api/actors', '/api/context?type=lanes|ofac|fires|maritime|leaksites|lists|blogs|links|unit42|genioc|lanesreg|ransompay|sec8k|cables[&format=geojson]', '/open-data/cables.geojson', '/api/enrich?type=asn|ip|domain|hash|actor&q=', ...(isOperator(req) ? ['/api/admin?op=whoami|sha|status|doc|probe|run|push'] : [])],
    store: 'Neon project threat-intel: collector function ti (schedule every 15 minutes), Postgres schema ti, private bucket ti-docs',
  }, 3600, 86400);
});

module.exports = (req, res) => {
  const route = ROUTES[q(req, 'route', '')];
  return route ? route()(req, res) : index(req, res);
};
