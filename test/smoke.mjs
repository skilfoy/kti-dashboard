// Check a deployed public site from outside: the page and its data load, the service answers and is readable from any
// origin, the map and enrichment answer in full, the security headers are present, and the collector's control plane is
// not reachable there. With EXPECT_COMMIT set, the site must serve that commit.
//   [EXPECT_COMMIT=<sha>] node test/smoke.mjs https://<public domain>
const BASE = (process.argv[2] || '').replace(/\/+$/, '');
if (!/^https:\/\//.test(BASE)) { console.error('usage: node test/smoke.mjs https://<public domain>'); process.exit(2); }
const problems = [];
const check = (c, m) => { if (!c) problems.push(m); };
const get = async (p) => { const r = await fetch(BASE + p, { redirect: 'manual' }); return { r, text: await r.text() }; };

const home = await get('/');
check(home.r.status === 200 && /<title>Global Threat Intelligence<\/title>/.test(home.text), 'home page answers 200 with the site title');
const site = await get('/site.json');
let catalog = null;
try { catalog = JSON.parse(site.text); } catch { /* reported below */ }
check(catalog && catalog.datasets && Object.keys(catalog.datasets).length > 40, 'site.json lists the datasets');
if (catalog) {
  const kev = catalog.datasets.kev;
  const d = kev && (await get(kev.url));
  check(d && d.r.status === 200 && JSON.parse(d.text).length > 1000, 'a built dataset (kev) downloads');
  check(d && /immutable/.test(d.r.headers.get('cache-control') || ''), 'built datasets are served immutable');
  const age = (Date.now() - Date.parse(catalog.built)) / 3600000;
  check(age < 30, `site was built within 30 hours (${age.toFixed(1)} h ago)`);
  // EXPECT_COMMIT (the deploy workflow sets it): the domain serves the deployment just made, not an earlier one.
  const want = (process.env.EXPECT_COMMIT || '').slice(0, 12);
  if (want) check(catalog.commit === want, `the site serves commit ${want} (it serves ${catalog.commit})`);
  check(catalog.datasets.history && catalog.datasets.outcomes, 'site.json lists the change log and the forecast record');
}
const feed = await get('/feed.json');
let feedDoc = null;
try { feedDoc = JSON.parse(feed.text); } catch { /* reported below */ }
check(feed.r.status === 200 && feedDoc && /jsonfeed/.test(feedDoc.version || '') && feedDoc.items.length > 0 && catalog
  && feedDoc.items[0]._kti.run_id, 'the change feed lists the runs, newest first');
// Security headers (vercel.json): a policy that keeps scripts, styles and connections to this origin, and no framing.
const csp = home.r.headers.get('content-security-policy') || '';
check(/default-src 'none'/.test(csp) && /script-src 'self'(;|$)/.test(csp) && /frame-ancestors 'none'/.test(csp), 'the page carries its content security policy');
check((home.r.headers.get('x-content-type-options') || '').toLowerCase() === 'nosniff', 'responses carry X-Content-Type-Options: nosniff');
check(!!home.r.headers.get('referrer-policy'), 'the page carries a referrer policy');
const health = await get('/api/health');
check(health.r.status === 200 && JSON.parse(health.text).service === 'threat-feeds', 'the service answers /api/health');
check(health.r.headers.get('access-control-allow-origin') === '*', 'the service is readable from any origin');
const admin = await get('/api/admin?op=whoami');
check(admin.r.status === 404, `the operator route does not exist on the public host (got ${admin.r.status})`);
const tm = await get('/api/threatmap?format=compact');
if (tm.r.status === 200) {
  const b = JSON.parse(tm.text);
  const ipCol = b.cols.indexOf('ip');
  const shown = b.nodes.filter((n) => n[ipCol] != null).length;
  check(b.nodes.length > 0 && shown === b.nodes.length, `the map carries every host address (${shown} of ${b.nodes.length})`);
} else problems.push(`threatmap answered ${tm.r.status}`);
const en = await get('/api/enrich?type=hash&q=' + 'e'.repeat(64));
if (en.r.status === 200) {
  const b = JSON.parse(en.text);
  check((b.results || []).some((x) => x.analyzer === 'mbazaar') && (b.results || []).some((x) => x.analyzer === 'hashlookup'), 'enrichment reads every analyzer for a hash');
}
if (problems.length) { console.error('SMOKE FAILED for ' + BASE + '\n - ' + problems.join('\n - ')); process.exit(1); }
console.log('PASS smoke: ' + BASE);
