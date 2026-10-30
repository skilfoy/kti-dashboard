// ---------------------------------------------------------------- on-demand enrichment of one public indicator (G59, G65 re-scoped)
// The dashboard asks; the collector reads free public analyzers and answers with each one's source and retrieval time.
// Nothing here is written into the map or the items. Keys (cl0q, abuse.ch) stay in this function's environment. Inputs are
// validated by type before any request, private addresses are refused, and answers are cached for a day.
//   asn     CIRCL BGP Ranking (rank and 30-day history), cl0q cross-section of the network's hosted sites
//   ip      the collector's own holdings (layers, geolocation, list memberships), CIRCL IP-to-ASN history, cl0q sites on the address
//   domain  Tranco research ranking, cl0q domain profile and indexed subdomains
//   hash    CIRCL hashlookup (known-software hash database), abuse.ch MalwareBazaar (sample record) and YARAify (public YARA
//           matches), both read with the abuse.ch community Auth-Key sent as a header, never in a URL
//   actor   ORKL threat report library
const ENRICH_RX = { asn: /^(?:AS)?(\d{1,10})$/i, ip: /^(\d{1,3}\.){3}\d{1,3}$/, domain: /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i,
  hash: /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i, actor: /^[A-Za-z0-9][\w .'&()-]{1,59}$/ };
export function enrichInput(type, q) {
  const re = ENRICH_RX[type], v = String(q || '').trim().replace(type === 'domain' ? /\.$/ : /$^/, '');
  if (!re || !re.test(v)) return null;
  if (type === 'asn') return v.replace(/^AS/i, '');
  if (type === 'ip') return publicV4(v) ? v : null;
  return type === 'domain' || type === 'hash' ? v.toLowerCase() : v;
}
const CL0Q = 'https://cl0q.com';
const RATE = { cl0q: { per: 60000, max: 25 }, tranco: { per: 60000, max: 50 }, circl: { per: 60000, max: 60 }, orkl: { per: 60000, max: 30 }, abusech: { per: 60000, max: 20 } };
const BUCKET_STATE = new Map();
function take(name) {
  const r = RATE[name]; if (!r) return true;
  const now = Date.now(), b = BUCKET_STATE.get(name) || { at: now, n: 0 };
  if (now - b.at > r.per) { b.at = now; b.n = 0; }
  if (b.n >= r.max) { BUCKET_STATE.set(name, b); return false; }
  b.n++; BUCKET_STATE.set(name, b); return true;
}
const redactKey = (s) => [ENV().CLOQ_API_KEY, ENV().ABUSECH_AUTH_KEY].filter(Boolean).reduce((t, k) => t.split(k).join('***'), String(s || ''));
const cl0qHeaders = () => (ENV().CLOQ_API_KEY ? { 'x-api-key': ENV().CLOQ_API_KEY, accept: 'application/json' } : { accept: 'application/json' });
const trim = (o, n = 40) => (Array.isArray(o) ? o.slice(0, n) : o);
// abuse.ch community APIs (checked 24 October 2026): MalwareBazaar takes a form-encoded POST (query=get_info&hash=) and
// YARAify a JSON POST ({ query: 'lookup_hash', search_term }); both want the Auth-Key header and answer with a query_status.
const abuseHeaders = (ct) => { const k = ENV().ABUSECH_AUTH_KEY; if (!k) throw new Error('no abuse.ch Auth-Key in the collector environment'); return { 'Auth-Key': k, 'content-type': ct, accept: 'application/json' }; };
const NOT_FOUND = /not_found|no_results/;
export function parseBazaar(j) {
  const st = j && j.query_status;
  if (NOT_FOUND.test(st || '')) return { found: false, query_status: st };
  if (st !== 'ok') throw new Error('MalwareBazaar answered ' + (st || 'no status'));
  const d = (Array.isArray(j.data) ? j.data[0] : null) || {};
  const intel = d.intelligence || {};
  return { found: true, sha256: d.sha256_hash || null, file_type: d.file_type || null, file_name: d.file_name || null, signature: d.signature || null,
    tags: Array.isArray(d.tags) ? d.tags.slice(0, 15) : [], first_seen: d.first_seen || null, last_seen: d.last_seen || null, delivery_method: d.delivery_method || null,
    downloads: intel.downloads != null ? Number(intel.downloads) : null, yara_rules: (Array.isArray(d.yara_rules) ? d.yara_rules : []).slice(0, 20).map((y) => ({ rule: y.rule_name || null, author: y.author || null })),
    vendors: d.vendor_intel && typeof d.vendor_intel === 'object' ? Object.keys(d.vendor_intel).slice(0, 20) : [] };
}
export function parseYaraify(j) {
  const st = j && j.query_status;
  if (NOT_FOUND.test(st || '')) return { found: false, query_status: st };
  if (st !== 'ok') throw new Error('YARAify answered ' + (st || 'no status'));
  const d = j.data || {}, m = d.metadata || {}, tasks = Array.isArray(d.tasks) ? d.tasks : [];
  const rules = new Map(), clam = new Set();
  for (const t of tasks) {
    for (const r of Array.isArray(t.static_results) ? t.static_results : []) if (r && r.rule_name && r.rule_name !== 'xxx' && !rules.has(r.rule_name)) rules.set(r.rule_name, { rule: r.rule_name, author: r.author || null });
    for (const c of Array.isArray(t.clamav_results) ? t.clamav_results : []) if (c) clam.add(String(c));
  }
  return { found: true, sha256: m.sha256_hash || null, file_type: m.file_type_mime || null, first_seen: m.first_seen || null, last_seen: m.last_seen || null,
    sightings: m.sightings != null ? Number(m.sightings) : null, tasks: tasks.length, yara_rules: [...rules.values()].slice(0, 25), clamav: [...clam].slice(0, 10) };
}
export const ANALYZERS = {
  bgpranking: { types: ['asn'], label: 'CIRCL BGP Ranking', bucket: 'circl', page: (q) => 'https://bgpranking.circl.lu/asn?asn=' + q,
    run: async (q) => {
      const [a, h] = await Promise.all([get('https://bgpranking-ng.circl.lu/json/asn', { method: 'POST', as: 'json', timeout: 15000, body: JSON.stringify({ asn: q }), headers: { 'content-type': 'application/json' } }),
        get('https://bgpranking-ng.circl.lu/json/asn_history', { method: 'POST', as: 'json', timeout: 15000, body: JSON.stringify({ asn: q, period: 30 }), headers: { 'content-type': 'application/json' } })]);
      if (!a.ok || !a.json) throw new Error('HTTP ' + a.status + (a.error ? ' ' + a.error : ''));
      const r = a.json.response || {};
      return { description: r.asn_description || null, rank: r.ranking ? r.ranking.rank : null, position: r.ranking ? r.ranking.position : null, of: r.ranking ? r.ranking.total_known_asns : null,
        history: h.ok && h.json && h.json.response ? trim(h.json.response.asn_history, 31) : null };
    } },
  cl0q_asn: { types: ['asn'], label: 'cl0q network cross-section', bucket: 'cl0q', page: (q) => CL0Q + '/network/' + q,
    run: async (q) => { const r = await get(CL0Q + '/api/cross/asn/' + encodeURIComponent(q), { as: 'json', timeout: 15000, headers: cl0qHeaders() }); if (!r.ok || !r.json) throw new Error('HTTP ' + r.status); return trimDeep(r.json); } },
  map: { types: ['ip'], label: 'threat-feeds holdings', bucket: null, page: () => null,
    run: async (q) => {
      const [inf, g, l] = await sqlTx([
        [`SELECT layer, port, family, threat, status, first_seen, last_seen, first_obs, last_obs FROM ti.infra WHERE ip = $1::inet ORDER BY last_obs DESC LIMIT 20`, [q]],
        [`SELECT cc, country, city, asn, as_name, provider, fetched_at FROM ti.ip_geo WHERE ip = $1::inet AND ok`, [q]],
        [`SELECT lists, ipsum, tor, checked_at FROM ti.ip_list WHERE ip = $1::inet`, [q]],
      ]);
      const layers = [...new Set(inf.map((x) => x.layer))];
      const lists = l[0] ? l[0].lists : [];
      return { listed_by_map_sources: inf, geolocation: g[0] || null, lists, ipsum: l[0] ? l[0].ipsum : null, tor: l[0] ? l[0].tor : false, lists_checked: l[0] ? l[0].checked_at : null,
        credibility: layers.length ? credibility({ layers, lists }) : null };
    } },
  ipasn: { types: ['ip'], label: 'CIRCL IP-to-ASN history', bucket: 'circl', page: () => null,
    run: async (q) => { const r = await get('https://bgpranking-ng.circl.lu/ipasn_history/?ip=' + encodeURIComponent(q), { as: 'json', timeout: 15000 }); if (!r.ok || !r.json) throw new Error('HTTP ' + r.status);
      const resp = r.json.response || {}; const keys = Object.keys(resp).sort(); const last = keys.length ? resp[keys[keys.length - 1]] : null;
      return { asn: last ? last.asn : null, prefix: last ? last.prefix : null, as_of: keys.length ? keys[keys.length - 1] : null, source: last ? last.source || null : null }; } },
  cl0q_ip: { types: ['ip'], label: 'cl0q sites on this address', bucket: 'cl0q', page: (q) => CL0Q + '/search?q=' + encodeURIComponent('ip:' + q),
    run: async (q) => { const r = await get(CL0Q + '/search?q=' + encodeURIComponent('ip:' + q) + '&limit=25', { as: 'json', timeout: 15000, headers: cl0qHeaders() }); if (!r.ok || !r.json) throw new Error('HTTP ' + r.status);
      // {total, results: [{domain, status_code, title, ip, cname, mx_records, rank, ...}]} (checked 22 October 2026): sites cl0q indexed on the address.
      const res = Array.isArray(r.json.results) ? r.json.results : [];
      return { total: r.json.total ?? res.length, sites: res.slice(0, 25).map((x) => ({ domain: x.domain || null, title: x.title ? String(x.title).slice(0, 120) : null, status: x.status_code ?? null, cname: x.cname || null, rank: x.rank || null })) }; } },
  tranco: { types: ['domain'], label: 'Tranco research ranking', bucket: 'tranco', page: () => 'https://tranco-list.eu/',
    run: async (q) => { const r = await get('https://tranco-list.eu/api/ranks/domain/' + encodeURIComponent(q), { as: 'json', timeout: 15000 }); if (!r.ok || !r.json) throw new Error('HTTP ' + r.status);
      const ranks = Array.isArray(r.json.ranks) ? r.json.ranks : []; const best = ranks.reduce((b, x) => (b == null || x.rank < b ? x.rank : b), null);
      return { domain: r.json.domain || q, latest: ranks.length ? ranks[ranks.length - 1] : null, best_rank_30d: best, days_ranked: ranks.length, note: ranks.length ? 'A high rank marks a popular domain; listing one as malicious needs care.' : 'Not in the Tranco top million.' }; } },
  cl0q_domain: { types: ['domain'], label: 'cl0q domain profile', bucket: 'cl0q', page: (q) => CL0Q + '/site/' + q,
    run: async (q) => { if (!ENV().CLOQ_API_KEY) throw new Error('CLOQ_API_KEY is not set'); const r = await get(CL0Q + '/api/domain/' + encodeURIComponent(q), { as: 'json', timeout: 15000, headers: cl0qHeaders() });
      if (r.status === 404) return { indexed: false }; if (!r.ok || !r.json) throw new Error('HTTP ' + r.status); return { indexed: true, ...trimDeep(r.json) }; } },
  cl0q_subdomains: { types: ['domain'], label: 'cl0q indexed subdomains', bucket: 'cl0q', page: (q) => CL0Q + '/site/' + q,
    run: async (q) => { if (!ENV().CLOQ_API_KEY) throw new Error('CLOQ_API_KEY is not set'); const r = await get(CL0Q + '/api/subdomains?domain=' + encodeURIComponent(q) + '&limit=100', { as: 'json', timeout: 15000, headers: cl0qHeaders() });
      if (!r.ok || !r.json) throw new Error('HTTP ' + r.status); return trimDeep(r.json, 100); } },
  hashlookup: { types: ['hash'], label: 'CIRCL hashlookup', bucket: 'circl', page: (q) => 'https://hashlookup.circl.lu/lookup/' + (q.length === 64 ? 'sha256' : q.length === 40 ? 'sha1' : 'md5') + '/' + q,
    run: async (q) => { const kind = q.length === 64 ? 'sha256' : q.length === 40 ? 'sha1' : 'md5'; const r = await get('https://hashlookup.circl.lu/lookup/' + kind + '/' + q, { as: 'json', timeout: 15000, headers: { accept: 'application/json' } });
      if (r.status === 404) return { known: false, note: 'Not in the known-software database; unknown, not malicious.' }; if (!r.ok || !r.json) throw new Error('HTTP ' + r.status);
      const j = r.json; return { known: true, file_name: j.FileName || null, product: j.ProductCode ? (j.ProductCode.ProductName || null) : null, source: j.source || null, size: j.FileSize || null, trust: j['hashlookup:trust'] || null }; } },
  // abuse.ch's sample pages sit behind a browser check, so the link opens each platform's front page.
  mbazaar: { types: ['hash'], label: 'abuse.ch MalwareBazaar', bucket: 'abusech', page: () => 'https://bazaar.abuse.ch/',
    run: async (q) => { const r = await get('https://mb-api.abuse.ch/api/v1/', { method: 'POST', as: 'json', timeout: 15000, body: 'query=get_info&hash=' + encodeURIComponent(q), headers: abuseHeaders('application/x-www-form-urlencoded') });
      if (!r.ok || !r.json) throw new Error('HTTP ' + r.status); return parseBazaar(r.json); } },
  yaraify: { types: ['hash'], label: 'abuse.ch YARAify', bucket: 'abusech', page: () => 'https://yaraify.abuse.ch/',
    run: async (q) => { const r = await get('https://yaraify-api.abuse.ch/api/v1/', { method: 'POST', as: 'json', timeout: 15000, body: JSON.stringify({ query: 'lookup_hash', search_term: q }), headers: abuseHeaders('application/json') });
      if (!r.ok || !r.json) throw new Error('HTTP ' + r.status); return parseYaraify(r.json); } },
  orkl: { types: ['actor'], label: 'ORKL threat report library', bucket: 'orkl', page: () => 'https://orkl.eu/',
    run: async (q) => { const r = await get('https://orkl.eu/api/v1/library/search?query=' + encodeURIComponent(q) + '&full=false&limit=10', { as: 'json', timeout: 20000, headers: { accept: 'application/json' } });
      if (!r.ok || !r.json) throw new Error('HTTP ' + r.status); const data = Array.isArray(r.json.data) ? r.json.data : Array.isArray(r.json) ? r.json : [];
      // Entries carry the original report's URLs in references and the collections ORKL took them from in sources (checked 22 October 2026).
      return { reports: data.length, items: data.slice(0, 10).map((d) => ({ title: String(d.llm_title || d.title || d.name || '').replace(/\s+/g, ' ').trim() || null,
        published: String(d.file_creation_date || d.created_at || '').slice(0, 10) || null, authors: d.authors || null, collections: Array.isArray(d.sources) ? d.sources.map((x) => (typeof x === 'string' ? x : x && x.name)).filter(Boolean).slice(0, 4) : [],
        url: Array.isArray(d.references) && d.references[0] ? d.references[0] : null, orkl: d.id ? 'https://orkl.eu/api/v1/library/entry/' + d.id : null })) }; } },
};
function trimDeep(o, n = 25, depth = 0) {
  if (Array.isArray(o)) return o.slice(0, n).map((x) => trimDeep(x, n, depth + 1));
  if (o && typeof o === 'object' && depth < 4) return Object.fromEntries(Object.entries(o).slice(0, 40).map(([k, v]) => [k, trimDeep(v, n, depth + 1)]));
  return typeof o === 'string' ? o.slice(0, 400) : o;
}
export async function enrich(type, rawQ) {
  const q = enrichInput(type, rawQ);
  if (!q) return { ok: false, error: 'invalid ' + type + ' value', types: Object.keys(ENRICH_RX) };
  const names = Object.keys(ANALYZERS).filter((n) => ANALYZERS[n].types.includes(type));
  const cached = new Map((await sql(`SELECT analyzer, ok, result, error, at FROM ti.enrich WHERE type = $1 AND q = $2 AND at > now() - interval '1 day'`, [type, q])).map((r) => [r.analyzer, r]));
  const out = await Promise.all(names.map(async (n) => {
    const A = ANALYZERS[n];
    const base = { analyzer: n, label: A.label, page: A.page(q) };
    if (cached.has(n) && n !== 'map') { const c = cached.get(n); return { ...base, ok: c.ok, cached: true, at: c.at, data: c.result, error: c.error }; }
    if (A.bucket && !take(A.bucket)) return { ...base, ok: false, error: 'rate limit for ' + A.bucket + ' reached; try again in a minute' };
    try { return { ...base, ok: true, cached: false, at: new Date().toISOString(), data: await A.run(q) }; }
    catch (e) { return { ...base, ok: false, cached: false, at: new Date().toISOString(), error: redactKey(String(e.message || e)).slice(0, 300) }; }
  }));
  const fresh = out.filter((r) => !r.cached && r.analyzer !== 'map' && r.at && !/rate limit/.test(r.error || ''));
  if (fresh.length) await sql(`INSERT INTO ti.enrich (type, q, analyzer, ok, result, error, at) SELECT $1, $2, analyzer, ok, result, error, now()
    FROM jsonb_to_recordset($3::jsonb) AS x(analyzer text, ok boolean, result jsonb, error text)
    ON CONFLICT (type, q, analyzer) DO UPDATE SET ok = EXCLUDED.ok, result = EXCLUDED.result, error = EXCLUDED.error, at = now()`, [type, q, fresh.map((r) => ({ analyzer: r.analyzer, ok: r.ok, result: r.data || null, error: r.error || null }))]);
  return { ok: true, type, q, at: new Date().toISOString(), results: out };
}
