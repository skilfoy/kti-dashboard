const { handle, sendJson, upstream, q } = require('./_lib');
const store = require('../lib/store');

// Live exposure monitoring for the operator's own estate and named suppliers, built on free public sources the
// darknet-mcp-server tools also use (breachList, ransomwareSearch, tor_exit_check, greynoise_ip, threatfox):
//   ?domains=  up to 3 of the organization's own domains: HIBP breaches of those sites
//   ?vendors=  up to 15 supplier domains: HIBP breaches of those sites and leak-site listings that name them
//   ?terms=    up to 5 brand terms to search on leak sites (defaults to the domains' first labels)
//   ?ips=      up to 10 of the organization's public egress IPs: Tor exit list, Feodo C2 blocklist, ThreatFox (from the
//              collector's map when it holds that layer; null otherwise), GreyNoise
// Rows carry a `kind`: breach, leak, ip, plus one `summary` row. With no parameters it returns only the summary
// row with configured=false, so a page can run it at its defaults.
const HOST = /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const split = (d) => {
  const h = String(d).toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  const p = h.split('.');
  if (p.length < 2) return null;
  const two = /^(co|com|net|org|gov|ac|edu)\.[a-z]{2}$/.test(p.slice(-2).join('.')) && p.length >= 3;
  const tld = two ? p.slice(-2).join('.') : p[p.length - 1];
  const label = p[p.length - (two ? 3 : 2)];
  return { domain: label + '.' + tld, label, tld };
};
const list = (s, n) => [...new Set(String(s || '').toLowerCase().split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean))].slice(0, n);
const isPublicV4 = (ip) => {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [+m[1], +m[2]];
  if (m.slice(1).some((x) => +x > 255)) return false;
  return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127));
};


async function pool(items, n, fn) {
  const out = []; const queue = items.slice();
  await Promise.all(Array.from({ length: n }, async () => { while (queue.length) { const it = queue.shift(); out.push(await fn(it)); } }));
  return out;
}

async function breaches(domain, role) {
  const r = await upstream(`https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`, { timeout: 10000 });
  if (!r.ok || !Array.isArray(r.json)) return [];
  return r.json.map((b) => ({
    kind: 'breach', role, of: domain, name: b.Name, title: b.Title, breach_date: b.BreachDate, added: String(b.AddedDate || '').slice(0, 10),
    pwn_count: b.PwnCount, passwords: (b.DataClasses || []).includes('Passwords') ? 'Yes' : 'No', data_classes: (b.DataClasses || []).join(', '), verified: b.IsVerified ? 'Yes' : 'No',
  }));
}

async function leaks(term, role, domainHint) {
  const r = await upstream(`https://api.ransomware.live/v2/searchvictims/${encodeURIComponent(term)}`, { timeout: 12000 });
  const arr = Array.isArray(r.json) ? r.json : (r.json && (r.json.victims || r.json.data || r.json.results)) || [];
  if (!r.ok || !arr.length) return [];
  const word = new RegExp('(^|[^a-z0-9])' + term.replace(/[.&-]/g, (c) => '[' + c + ']') + '([^a-z0-9]|$)', 'i');
  return arr
    .map((v) => {
      const site = String(v.website || v.domain || '').toLowerCase();
      const name = String(v.victim || v.post_title || v.name || '');
      const match = domainHint && site.includes(domainHint) ? 'domain' : word.test(name) || word.test(site) ? 'name' : '';
      return match ? { kind: 'leak', role, term, match, victim: name, group: String(v.group_name || v.group || '').toLowerCase(), country: v.country || '',
        sector: v.activity || v.sector || '', discovered: String(v.discovered || v.attackdate || '').slice(0, 10), published: String(v.published || '').slice(0, 10) } : null;
    })
    .filter(Boolean);
}

async function ipRep(ips) {
  if (!ips.length) return [];
  // ThreatFox's keyless export closed on 21 October 2026 (abuse.ch now issues Auth-Keys, kept off Vercel), so ThreatFox
  // membership is read from the collector's stored map when it holds the ThreatFox layer, and reported unknown otherwise.
  const [tor, feodo, tm] = await Promise.all([
    upstream('https://check.torproject.org/torbulkexitlist', { timeout: 10000, accept: 'text/plain' }),
    upstream('https://feodotracker.abuse.ch/downloads/ipblocklist.json', { timeout: 10000 }),
    store.getDoc(req, 'threatmap', { timeout: 6000 }),
  ]);
  const torSet = new Set(String(tor.text || '').split('\n').map((s) => s.trim()));
  const feodoSet = new Set((Array.isArray(feodo.json) ? feodo.json : []).map((d) => d.ip_address));
  const tfKnown = !!(tm.ok && tm.doc.layers && tm.doc.layers.ioc && tm.doc.layers.ioc.ok);
  const tfCount = {};
  if (tfKnown) for (const n of tm.doc.rows || []) if (n.kind === 'node' && n.layer === 'ioc') tfCount[n.ip] = (tfCount[n.ip] || 0) + 1;
  return pool(ips, 5, async (ip) => {
    const g = await upstream(`https://api.greynoise.io/v3/community/${ip}`, { timeout: 6000 });
    const gj = g.json || {};
    const row = { kind: 'ip', ip, tor_exit: torSet.has(ip) ? 'Yes' : 'No', feodo_c2: feodoSet.has(ip) ? 'Yes' : 'No', threatfox_iocs: tfKnown ? tfCount[ip] || 0 : null,
      greynoise: gj.classification || (g.status === 404 ? 'not seen' : g.status === 429 ? 'rate-limited' : 'unknown'), greynoise_name: gj.name || '', last_seen: gj.last_seen || '' };
    row.flagged = row.feodo_c2 === 'Yes' || (row.threatfox_iocs || 0) > 0 || row.greynoise === 'malicious' ? 'Yes' : 'No';
    return row;
  });
}

module.exports = handle(async (req, res) => {
  const started = Date.now();
  const domains = list(q(req, 'domains', ''), 3).map((d) => (split(d) || {}).domain).filter((d) => d && HOST.test(d));
  const vendors = list(q(req, 'vendors', ''), 15).map((d) => (split(d) || {}).domain).filter((d) => d && HOST.test(d));
  const terms = list(q(req, 'terms', ''), 5).filter((t) => /^[a-z0-9][a-z0-9 .&-]{2,40}$/.test(t));
  const ips = list(q(req, 'ips', ''), 10).filter(isPublicV4);
  const configured = domains.length + vendors.length + terms.length + ips.length > 0;

  const rows = [];
  if (configured) {
    const orgTerms = [...new Set(terms.concat(domains.map((d) => split(d).label)))];
    const tasks = [
      ...domains.map(async (d) => rows.push(...(await breaches(d, 'organization')))),
      ...vendors.map(async (v) => rows.push(...(await breaches(v, 'supplier')))),
      ...orgTerms.map(async (t) => rows.push(...(await leaks(t, 'organization', domains.find((d) => d.startsWith(t + '.')))))),
      ...vendors.map(async (v) => rows.push(...(await leaks(split(v).label, 'supplier', v)))),
      (async () => rows.push(...(await ipRep(ips))))(),
    ];
    await Promise.all(tasks.map((p) => p.catch(() => null)));
  }
  const n = (k, f = () => true) => rows.filter((r) => r.kind === k && f(r)).length;
  const yearAgo = new Date(Date.now() - 365 * 864e5).toISOString().slice(0, 10);
  const summary = {
    kind: 'summary', configured, domains: domains.join(', '), vendors: vendors.length, ips: ips.length,
    breaches: n('breach', (r) => r.role === 'organization'), breaches_pw: n('breach', (r) => r.role === 'organization' && r.passwords === 'Yes'),
    supplier_breaches: n('breach', (r) => r.role === 'supplier'),
    org_leaks: n('leak', (r) => r.role === 'organization'), org_leaks_year: n('leak', (r) => r.role === 'organization' && r.discovered >= yearAgo),
    supplier_leaks: n('leak', (r) => r.role === 'supplier'), supplier_leaks_year: n('leak', (r) => r.role === 'supplier' && r.discovered >= yearAgo),
    suppliers_hit: new Set(rows.filter((r) => r.kind === 'leak' && r.role === 'supplier').map((r) => r.term)).size,
    ips_flagged: n('ip', (r) => r.flagged === 'Yes'), ips_tor: n('ip', (r) => r.tor_exit === 'Yes'), ms: Date.now() - started,
  };
  sendJson(res, 200, { source: 'threat-feeds exposure monitor (HIBP, ransomware.live, Tor Project, abuse.ch, GreyNoise community)',
    generated: new Date().toISOString(), count: rows.length + 1, rows: [summary, ...rows] }, configured ? 3600 : 300, 21600);
});
