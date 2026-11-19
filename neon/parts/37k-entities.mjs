// ---------------------------------------------------------------- entity graph (3.4.0)
// Every entry the source network and the advisory feeds collect is read once against the entity gazetteer the site
// build publishes (pipeline/build_gazetteer.py: ATT&CK groups, software and campaigns, MISP threat actors, Malpedia
// families, leak-site extortion groups, KEV vendors, products and CVEs), plus country names. Each entity an entry names
// becomes a mention row; two entities named by the same entry are co-mentioned. The graph keeps the two kinds of link
// apart: curated relationships come with the sources (ATT&CK "uses", KEV "affects"), co-mentions are what the
// collection observed, with a count, the number of publishers and a normalized PMI. No model is involved, so the job
// spends nothing and the same entry always gives the same entities.
//
// Matching rules (the gazetteer's modes): names of two or more words, or with a digit, match in any case; a single plain
// word matches only when capitalized, and also needs a cue word within three words ("ransomware", "hackers", "flaw",
// ...) when it is common in general news (counted daily over the collection) or common English; a product name of
// one or two plain words needs its vendor in the same entry; countries are kept only beside another entity, so the
// geopolitical stream adds country context to the cyber entities without becoming a country index of its own.
export const ENTITY = { BATCH: 3000, BUDGET_MS: 100000, KEEP_DAYS: 400, MAX_N: 7, CUE_SPAN: 3, DOC_EVERY_MS: 3600e3, AMB_EVERY_MS: 86400e3,
  AMB_MIN: 4, AMB_RATIO: 2, AMB_HARD: 40, GAZ_URL: 'https://intel.kilfoycyber.com/data/entity_gazetteer.json' };
export const CYBER_CATS = new Set(['research', 'topic-cyber', 'cyber-news', 'vulnerability']);
const CUE_PREFIX = ['ransomwar', 'malwar', 'gang', 'hacker', 'hacking', 'hacked', 'actor', 'threat', 'campaign', 'operator', 'affiliate', 'extortion', 'extort',
  'backdoor', 'botnet', 'loader', 'stealer', 'infostealer', 'trojan', 'spyware', 'wiper', 'implant', 'phish', 'cyber', 'breach', 'exploit', 'vulnerab',
  'zero-day', 'zeroday', 'flaw', 'patch', 'attack', 'intrusion', 'espionage', 'ddos', 'variant', 'payload', 'dropper', 'strain', 'cybercrim', 'leak',
  'apt', 'advisory', 'security', 'compromis', 'malicious', 'spy', 'hijack', 'worm', 'rootkit', 'ransom'];
const CUE_EXACT = new Set(['rat', 'c2', 'cve', 'bug', 'bugs', '0-day', 'group', 'groups', 'crew', 'family', 'sample', 'samples', 'kit']);
const DEMONYM = 'RU:Russian|CN:Chinese|IR:Iranian|KP:North Korean|KR:South Korean|IL:Israeli|UA:Ukrainian|US:American|GB:British|BY:Belarusian|PK:Pakistani|IN:Indian|'
  + 'VN:Vietnamese|TR:Turkish|TW:Taiwanese|JP:Japanese|DE:German|FR:French|SA:Saudi|AE:Emirati|SY:Syrian|LB:Lebanese|VE:Venezuelan|CU:Cuban|KZ:Kazakh|'
  + 'PL:Polish|NL:Dutch|AU:Australian|CA:Canadian|IT:Italian|ES:Spanish|BR:Brazilian|MX:Mexican|NG:Nigerian|IQ:Iraqi|QA:Qatari|EG:Egyptian|PS:Palestinian|'
  + 'YE:Yemeni|SG:Singaporean|MY:Malaysian|PH:Filipino|ID:Indonesian|TH:Thai|RO:Romanian|SE:Swedish|NO:Norwegian|FI:Finnish|DK:Danish|EE:Estonian|LT:Lithuanian|LV:Latvian|'
  + 'CZ:Czech|HU:Hungarian|GR:Greek|IE:Irish|CH:Swiss|AT:Austrian|BE:Belgian|PT:Portuguese|NZ:New Zealand|ZA:South African|AF:Afghan|AZ:Azerbaijani|AM:Armenian|'
  + 'GE:Georgian|MD:Moldovan|RS:Serbian|LY:Libyan|SD:Sudanese|JO:Jordanian|KW:Kuwaiti|BH:Bahraini|OM:Omani|CL:Chilean|CO:Colombian|AR:Argentine|PE:Peruvian';
// Exact-case country forms: "US" and "UK" are words in lower case.
const COUNTRY_EXACT = 'US:US|US:U.S|US:USA|GB:UK|AE:UAE|KP:DPRK|CN:PRC|US:America|SA:KSA';

export function squashName(s) { return String(s || '').toLowerCase().normalize('NFKD').replace(/[^0-9a-z]+/g, ''); }
const TOKEN = /[\p{L}\p{N}]+(?:[.'’\-][\p{L}\p{N}]+)*\$?/gu;
export function tokenize(text) {
  const out = [];
  for (const m of String(text || '').matchAll(TOKEN)) out.push({ raw: m[0], k: squashName(m[0]), cap: /^\p{Lu}/u.test(m[0]), low: m[0].toLowerCase() });
  return out;
}
const isCue = (low) => CUE_EXACT.has(low) || CUE_PREFIX.some((p) => low.startsWith(p));

// The compiled matcher: squashed name -> one candidate {id, mode, exact?}. A gazetteer name owns its key; a country name
// takes a key only when no entity holds it.
export function compileGazetteer(doc, { ambiguous = [] } = {}) {
  const byKey = new Map(), ents = new Map(), vendorOf = new Map();
  let maxN = 1;
  for (const e of (doc && doc.entities) || []) {
    ents.set(e.id, { t: e.t, n: e.n, m: e.m || {} });
    if (e.t === 'product' && e.m && e.m.vendor) vendorOf.set(e.id, e.m.vendor);
    for (const [name, mode] of e.a || []) {
      const k = squashName(name);
      if (k.length < 3 || byKey.has(k)) continue;
      byKey.set(k, { id: e.id, mode });
      maxN = Math.max(maxN, tokenize(name).length);
    }
  }
  const cn = new Map();
  for (const [cc, names] of CA_NAMES) cn.set(cc, names[0]);
  const addCountry = (cc, name, mode) => {
    const k = squashName(name), id = 'country:' + cc;
    if (!ents.has(id)) ents.set(id, { t: 'country', n: cn.get(cc) || cc, m: { cc } });
    if (mode === 'x') {
      const c = byKey.get(k);
      if (c && c.id !== id) return;
      const x = c || { id, mode: 'x', exact: new Set() };
      x.exact.add(name);
      byKey.set(k, x);
    } else if (k.length >= 4 && !byKey.has(k)) byKey.set(k, { id, mode: tokenize(name).length > 1 ? 'i' : 's', country: true });
    // A single-word family or group named after a country ("Cuba" ransomware) keeps the name beside its cue word;
    // without one, the capitalized word is the country.
    else if (k.length >= 4 && ['s', 'w'].includes(byKey.get(k).mode) && byKey.get(k).id !== id) byKey.get(k).alt = id;
    maxN = Math.max(maxN, tokenize(name).length);
  };
  for (const [cc, names] of CA_NAMES) for (const n of names) addCountry(cc, n, 's');
  for (const s of DEMONYM.split('|')) addCountry(s.slice(0, 2), s.slice(3), 's');
  for (const s of COUNTRY_EXACT.split('|')) addCountry(s.slice(0, 2), s.slice(3), 'x');
  return { byKey, ents, vendorOf, maxN: Math.min(maxN, ENTITY.MAX_N), ambiguous: new Set(ambiguous), date: doc && doc.date, counts: doc && doc.counts };
}

// Entities named in one text: Map id -> the words that named it. Longest match at each position wins.
export function matchText(G, text) {
  const toks = tokenize(text), found = new Map(), pending = [];
  const cue = (i, n) => {
    for (let j = Math.max(0, i - ENTITY.CUE_SPAN); j < Math.min(toks.length, i + n + ENTITY.CUE_SPAN); j++) if ((j < i || j >= i + n) && isCue(toks[j].low)) return true;
    return false;
  };
  for (let i = 0; i < toks.length;) {
    const cv = /^CVE-(\d{4})-(\d{4,7})$/i.exec(toks[i].raw);
    if (cv) { const id = `cve:CVE-${cv[1]}-${cv[2]}`; if (!found.has(id)) found.set(id, id.slice(4)); i++; continue; }
    let best = null, key = '';
    for (let n = 1; n <= G.maxN && i + n <= toks.length; n++) {
      key += toks[i + n - 1].k;
      if (!toks[i + n - 1].k) break;
      const c = G.byKey.get(key);
      if (!c) continue;
      let ok;
      switch (c.mode) {
        case 'i': ok = true; break;
        case 'v': ok = true; break;
        case 's': ok = n === 1 && toks[i].cap && (!G.ambiguous.has(key) || cue(i, n)); break;
        case 'w': ok = n === 1 && toks[i].cap && cue(i, n); break;
        case 'x': ok = n === 1 && c.exact.has(toks[i].raw.replace(/\.$/, '')); break;
        default: ok = false;
      }
      if (ok) best = { c, n };
      else if (c.alt && n === 1 && toks[i].cap) best = { c: { id: c.alt, mode: 's' }, n };
    }
    if (!best) { i++; continue; }
    const words = toks.slice(i, i + best.n).map((t) => t.raw).join(' ');
    if (best.c.mode === 'v') pending.push([best.c.id, words]);
    else if (!found.has(best.c.id)) found.set(best.c.id, words);
    i += best.n;
  }
  for (const [id, words] of pending) if (found.has(G.vendorOf.get(id)) && !found.has(id)) found.set(id, words);
  // A product named with its vendor ("Ivanti Connect Secure") names the vendor too.
  for (const id of [...found.keys()]) if (G.vendorOf.has(id) && !found.has(G.vendorOf.get(id))) found.set(G.vendorOf.get(id), found.get(id));
  // Countries count beside another entity only.
  if (![...found.keys()].some((id) => !id.startsWith('country:'))) return new Map();
  return found;
}

// A title from a news aggregator ends with " - Publisher"; the publisher's name is not part of the story.
export function entryText(r) {
  let t = String(r.title || '');
  if (r.source && t.endsWith(' - ' + r.source)) t = t.slice(0, -(r.source.length + 3));
  return (t + ' . ' + String(r.summary || '')).slice(0, 2000);
}

let GAZ = null;
export function resetGazetteer() { GAZ = null; }
async function loadGazetteer() {
  if (GAZ && Date.now() - GAZ.at < 6 * 3600e3) return GAZ;
  let doc = null, via = 'site';
  const r = await get(ENV().TI_GAZETTEER_URL || ENTITY.GAZ_URL, { as: 'json', timeout: 30000 });
  if (r.ok && r.json && Array.isArray(r.json.entities) && r.json.entities.length > 1000) doc = r.json;
  if (!doc) {
    const o = await refGet('ref/entity_gazetteer.json');
    if (!o) throw new Error('the entity gazetteer is unreachable: site ' + (r.status || r.error) + ', and ref/entity_gazetteer.json is missing from the bucket');
    doc = JSON.parse(o.buf.toString('utf8'));
    via = 'bucket';
  }
  const hash = createHash('sha256').update(JSON.stringify([doc.entities, doc.edges])).digest('hex').slice(0, 16);
  GAZ = { at: Date.now(), doc, via, hash };
  return GAZ;
}

// ti.entity and ti.erel follow the gazetteer: rewritten only when its entities or edges change.
async function syncEntities(g) {
  const kv = (await sql(`SELECT v FROM ti.kv WHERE k = 'entities:gaz'`))[0];
  if (kv && kv.v && kv.v.hash === g.hash) return { synced: false };
  const rows = g.doc.entities.map((e) => ({ id: e.id, t: e.t, n: e.n, names: e.a.map((a) => a[0]).join(' | ').slice(0, 2000), m: e.m || {} }));
  const st = [];
  for (let i = 0; i < rows.length; i += 2000) {
    st.push([`INSERT INTO ti.entity (id, t, n, names, m) SELECT id, t, n, names, m FROM jsonb_to_recordset($1::jsonb) AS x(id text, t text, n text, names text, m jsonb)
      ON CONFLICT (id) DO UPDATE SET t = EXCLUDED.t, n = EXCLUDED.n, names = EXCLUDED.names, m = EXCLUDED.m, at = now()
      WHERE (ti.entity.t, ti.entity.n, ti.entity.names, ti.entity.m) IS DISTINCT FROM (EXCLUDED.t, EXCLUDED.n, EXCLUDED.names, EXCLUDED.m)`, [rows.slice(i, i + 2000)]]);
  }
  st.push([`DELETE FROM ti.erel WHERE basis <> 'observed'`]);
  const edges = (g.doc.edges || []).map(([a, b, rel, basis]) => ({ a, b, rel, basis }));
  for (let i = 0; i < edges.length; i += 4000) {
    st.push([`INSERT INTO ti.erel (a, b, rel, basis) SELECT a, b, rel, basis FROM jsonb_to_recordset($1::jsonb) AS x(a text, b text, rel text, basis text) ON CONFLICT DO NOTHING`, [edges.slice(i, i + 4000)]]);
  }
  st.push([`INSERT INTO ti.kv (k, v, at) VALUES ('entities:gaz', $1::jsonb, now()) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, at = now()`, [{ hash: g.hash, date: g.doc.date, entities: rows.length, edges: edges.length }]]);
  await sqlTx(st);
  // The bucket keeps the last gazetteer read from the site, so a site outage leaves the job its last good copy.
  if (g.via === 'site') await s3Put('ref/entity_gazetteer.json.gz', gzipSync(Buffer.from(JSON.stringify(g.doc)), { level: 9 }), 'application/gzip');
  return { synced: true, entities: rows.length, edges: edges.length };
}

// A single-word name is ambiguous when general news uses it (geopolitics, theater and maritime feeds) at more than
// AMB_RATIO times its rate in the cyber feeds, at least AMB_MIN times in the collection, or AMB_HARD times outright.
export function ambiguousWords(general, cyber, nGeneral, nCyber) {
  const cy = new Map(cyber.map((r) => [r.word, +r.ndoc]));
  return general.filter((r) => {
    const g = +r.ndoc, c = cy.get(r.word) || 0;
    return g >= ENTITY.AMB_HARD || (g >= ENTITY.AMB_MIN && g / Math.max(1, nGeneral) > ENTITY.AMB_RATIO * (c / Math.max(1, nCyber)));
  }).map((r) => r.word).sort();
}
async function ambiguity(g, force = false) {
  const kv = (await sql(`SELECT v, at FROM ti.kv WHERE k = 'entities:amb'`))[0];
  if (!force && kv && kv.v && Date.now() - new Date(kv.at).getTime() < ENTITY.AMB_EVERY_MS && kv.v.hash === g.hash) return kv.v.words || [];
  const words = [...new Set(g.doc.entities.flatMap((e) => e.a.filter((a) => a[1] === 's').map((a) => squashName(a[0]))))];
  const cats = [...CYBER_CATS];
  const [gen, cyb, n] = await sqlTx([
    [`SELECT word, ndoc FROM ts_stat($$SELECT tsv FROM ti.item WHERE category IN ('geopolitics','topic-theater','maritime','think-tank','defense','government')$$) WHERE word = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))`, [words]],
    [`SELECT word, ndoc FROM ts_stat($$SELECT tsv FROM ti.item WHERE category IN ('${cats.join("','")}')$$) WHERE word = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))`, [words]],
    [`SELECT count(*) FILTER (WHERE category IN ('geopolitics','topic-theater','maritime','think-tank','defense','government'))::int AS g, count(*) FILTER (WHERE category = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb))))::int AS c FROM ti.item`, [cats]],
  ]);
  const amb = ambiguousWords(gen, cyb, n[0].g, n[0].c);
  await sql(`INSERT INTO ti.kv (k, v, at) VALUES ('entities:amb', $1::jsonb, now()) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, at = now()`, [{ hash: g.hash, words: amb, checked: words.length, general: n[0].g, cyber: n[0].c }]);
  return amb;
}

const SOURCES_SQL = {
  item: `SELECT link, title, summary, source, host, feed, category, published, seen_at, seen_at::text AS mark_at FROM ti.item WHERE (seen_at, link) > ($1::timestamptz, $2::text) ORDER BY seen_at, link LIMIT $3`,
  advisory: `SELECT link, title, '' AS summary, NULL AS source, NULL AS host, feed, 'vulnerability' AS category, coalesce(published, seen_at) AS published, cves, seen_at, seen_at::text AS mark_at
    FROM ti.advisory WHERE (seen_at, link) > ($1::timestamptz, $2::text) ORDER BY seen_at, link LIMIT $3`,
};
export async function jobEntities(opts = {}) {
  const t0 = Date.now(), deadline = t0 + Math.min(ENTITY.BUDGET_MS, opts.budgetMs || ENTITY.BUDGET_MS);
  const g = await loadGazetteer();
  const sync = await syncEntities(g);
  const G = compileGazetteer(g.doc, { ambiguous: await ambiguity(g, !!opts.rebuild) });
  const kv = (await sql(`SELECT v FROM ti.kv WHERE k = 'entities:mark'`))[0];
  const mark = (kv && kv.v) || {};
  if (opts.reprocess) for (const s of Object.keys(SOURCES_SQL)) mark[s] = null;
  const out = { gazetteer: { date: g.doc.date, via: g.via, ...sync }, ambiguous: G.ambiguous.size, read: 0, entries: 0, mentions: 0, by_source: {} };
  for (const src of Object.keys(SOURCES_SQL)) {
    const s = out.by_source[src] = { read: 0, entries: 0, mentions: 0 };
    let m = mark[src] || { at: '1970-01-01T00:00:00Z', link: '' };
    while (Date.now() < deadline - 5000) {
      const rows = await sql(SOURCES_SQL[src], [m.at, m.link, ENTITY.BATCH]);
      if (!rows.length) break;
      const docs = [], ments = [], fresh = new Set();
      for (const r of rows) {
        const f = matchText(G, entryText(r));
        for (const c of Array.isArray(r.cves) ? r.cves : []) if (/^CVE-\d{4}-\d{4,7}$/i.test(c)) f.set('cve:' + String(c).toUpperCase(), String(c).toUpperCase());
        if (!f.size) continue;
        const host = r.host || hostOf(r.link), pub = r.published || r.seen_at;
        docs.push({ link: r.link, src, feed: r.feed, host, title: String(r.title || '').slice(0, 400), published: pub, category: r.category });
        for (const [eid, via] of f) {
          ments.push({ eid, link: r.link, published: pub, host, via: String(via).slice(0, 80) });
          if (!G.ents.has(eid) || eid.startsWith('country:')) fresh.add(eid);
        }
      }
      const st = [];
      if (docs.length) st.push([`INSERT INTO ti.mdoc (link, src, feed, host, title, published, category) SELECT link, src, feed, host, title, published, category
        FROM jsonb_to_recordset($1::jsonb) AS x(link text, src text, feed text, host text, title text, published timestamptz, category text) ON CONFLICT (link) DO NOTHING`, [docs]]);
      if (ments.length) st.push([`INSERT INTO ti.mention (eid, link, published, host, via) SELECT eid, link, published, host, via
        FROM jsonb_to_recordset($1::jsonb) AS x(eid text, link text, published timestamptz, host text, via text) ON CONFLICT DO NOTHING`, [ments]]);
      // CVEs outside KEV and countries are entities the gazetteer does not list: they are added on first mention.
      if (fresh.size) st.push([`INSERT INTO ti.entity (id, t, n, names, m) SELECT id, t, n, n, m FROM jsonb_to_recordset($1::jsonb) AS x(id text, t text, n text, m jsonb) ON CONFLICT (id) DO NOTHING`,
        [[...fresh].map((id) => { const e = G.ents.get(id); return e ? { id, t: e.t, n: e.n, m: e.m } : { id, t: 'cve', n: id.slice(4), m: {} }; })]]);
      // The watermark keeps seen_at at full precision, as text. The sources job stamps a whole insert with one now(), so
      // thousands of entries share one microsecond value; a millisecond copy of it sorts before all of them, and the
      // first deploy reread the same 3,000 entries 290 times in one run (19 November 2026).
      const last = rows[rows.length - 1];
      if (last.mark_at === m.at && last.link === m.link) throw new Error('the watermark did not move at ' + m.at);
      m = { at: last.mark_at, link: last.link };
      mark[src] = m;
      st.push([`INSERT INTO ti.kv (k, v, at) VALUES ('entities:mark', $1::jsonb, now()) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, at = now()`, [mark]]);
      await sqlTx(st);
      s.read += rows.length; s.entries += docs.length; s.mentions += ments.length;
      if (rows.length < ENTITY.BATCH) break;
    }
    out.read += s.read; out.entries += s.entries; out.mentions += s.mentions;
  }
  out.behind = Date.now() >= deadline - 5000;
  const d = (await sql(`SELECT at FROM ti.kv WHERE k = 'entities:doc'`))[0];
  if (opts.rebuild || out.mentions > 0 && (!d || Date.now() - new Date(d.at).getTime() > ENTITY.DOC_EVERY_MS) || !d) {
    const doc = await graphDoc(g);
    out.published = await putDoc('entities', doc);
    out.rising = doc.rising;
    await sql(`INSERT INTO ti.kv (k, v, at) VALUES ('entities:doc', $1::jsonb, now()) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, at = now()`, [{ rising: doc.rising, entities: doc.entities }]);
  }
  await recordVolume([['entity_mentions', out.mentions]]);
  return { ...out, ms: Date.now() - t0 };
}

// Rising: the last seven days against the 23 before them, as a Poisson z score on the daily rate, with at least five
// entries from three publishers in the seven days. New: first named by the collection in the last seven days.
export function riseScore(n7, n30) {
  const base = Math.max(0, n30 - n7) / 23 * 7, e = Math.max(base, 0.5);
  return Math.round(((n7 - e) / Math.sqrt(e)) * 10) / 10;
}
export function npmi(nab, na, nb, N) {
  if (!nab || !na || !nb || !N) return 0;
  const pab = nab / N, pa = na / N, pb = nb / N;
  if (pab >= 1) return 1;
  return Math.round((Math.log(pab / (pa * pb)) / -Math.log(pab)) * 1000) / 1000;
}
async function graphDoc(g) {
  const [stats, pairs, nd, firsts] = await sqlTx([
    [`SELECT m.eid, e.t, e.n, count(*) FILTER (WHERE m.published > now() - interval '1 day')::int AS n1, count(*) FILTER (WHERE m.published > now() - interval '7 days')::int AS n7,
        count(*)::int AS n30, count(DISTINCT m.host) FILTER (WHERE m.published > now() - interval '7 days')::int AS p7, count(DISTINCT m.host)::int AS p30, max(m.published) AS last
      FROM ti.mention m JOIN ti.entity e ON e.id = m.eid WHERE m.published > now() - interval '30 days' AND m.published <= now() + interval '1 day' GROUP BY 1, 2, 3`],
    [`SELECT a.eid AS a, b.eid AS b, count(*)::int AS n, count(DISTINCT a.host)::int AS p, max(a.published) AS last FROM ti.mention a JOIN ti.mention b ON b.link = a.link AND b.eid > a.eid
      WHERE a.published > now() - interval '30 days' AND NOT (a.eid LIKE 'country:%' AND b.eid LIKE 'country:%') GROUP BY 1, 2 HAVING count(DISTINCT a.host) >= 2 ORDER BY n DESC LIMIT 4000`],
    [`SELECT count(DISTINCT link)::int AS n FROM ti.mention WHERE published > now() - interval '30 days'`],
    [`SELECT eid, min(published) AS first FROM ti.mention GROUP BY 1`],
  ]);
  const first = new Map(firsts.map((r) => [r.eid, r.first])), N = nd[0].n, wk = Date.now() - 7 * 864e5;
  const st = new Map(stats.map((s) => [s.eid, s]));
  const ents = stats.map((s) => ({ id: s.eid, t: s.t, n: s.n, n1: s.n1, n7: s.n7, n30: s.n30, p7: s.p7, p30: s.p30, first: first.get(s.eid) || null, last: s.last, z: riseScore(s.n7, s.n30) }))
    .map((e) => ({ ...e, rising: e.n7 >= 5 && e.p7 >= 3 && e.z >= 3 && e.t !== 'country', new: !!e.first && new Date(e.first).getTime() > wk && e.p7 >= 2 && e.t !== 'country' }));
  const edges = pairs.map((p) => ({ a: p.a, b: p.b, n: p.n, p: p.p, last: p.last, npmi: npmi(p.n, (st.get(p.a) || {}).n30, (st.get(p.b) || {}).n30, N) }))
    .filter((e) => e.npmi > 0).sort((x, y) => y.n * Math.max(0.05, y.npmi) - x.n * Math.max(0.05, x.npmi)).slice(0, 1500);
  const top = new Map();
  const cnt = {};
  for (const e of ents.filter((x) => x.t !== 'country').sort((x, y) => y.n7 - x.n7 || y.n30 - x.n30)) {
    cnt[e.t] = (cnt[e.t] || 0) + 1;
    if (cnt[e.t] <= 25) top.set(e.id, cnt[e.t]);
  }
  const keep = new Set([...top.keys(), ...edges.flatMap((e) => [e.a, e.b]), ...ents.filter((e) => e.rising || e.new).map((e) => e.id)]);
  const nameOf = new Map(ents.map((e) => [e.id, e]));
  // Curated relationships among the entities the document carries, for the TAXII graph collection.
  const rels = keep.size ? await sql(`SELECT a, b, rel, basis FROM ti.erel WHERE a = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb))) AND b = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))`, [[...keep]]) : [];
  const rows = ents.filter((e) => keep.has(e.id)).sort((x, y) => y.n7 - x.n7 || y.n30 - x.n30).map((e) => ({ kind: 'entity', ...e, top_rank: top.get(e.id) || null }))
    .concat(edges.map((e) => ({ kind: 'edge', ...e, an: (nameOf.get(e.a) || {}).n || e.a, at: (nameOf.get(e.a) || {}).t || e.a.split(':')[0], bn: (nameOf.get(e.b) || {}).n || e.b, bt: (nameOf.get(e.b) || {}).t || e.b.split(':')[0] })))
    .concat(rels.map((r) => ({ kind: 'rel', ...r })));
  return {
    source: 'KTI entity graph over the source network and advisory feeds', generated: new Date().toISOString(), served_from: 'store', window_days: 30, entries_30d: N,
    gazetteer: { date: g.doc.date, counts: g.doc.counts, names: g.doc.names, terms: g.doc.terms },
    method: 'Each collected entry (title and publisher summary) is matched against the entity gazetteer: names of two or more words or with a digit in any case, single words only capitalized and, when common in general news, beside a cue word; product names beside their vendor; countries only beside another entity. Co-mention edges count entries that name both entities in the last 30 days, need two publishers, and rank by count times normalized PMI. Rising: a Poisson z of 3 or more for the last 7 days against the 23 before, with 5 entries from 3 publishers. Curated relationships (ATT&CK, MISP, KEV) are served per entity and kept apart from co-mentions.',
    rising: ents.filter((e) => e.rising).length, new: ents.filter((e) => e.new).length, entities: ents.length, edges: edges.length, curated: rels.length, count: rows.length, rows,
  };
}

// ---------------------------------------------------------------- graph queries (GET /graph on the HTTP surface)
const EID = /^(actor|extortion|malware|tool|campaign|vendor|product|cve|country):[A-Za-z0-9:._\-]{1,120}$/;
export async function entityCard(id, days = 90) {
  if (!EID.test(String(id || ''))) return { error: 'bad id', status: 400 };
  days = Math.max(7, Math.min(400, +days || 90));
  const [ent, series, nb, rel, docs, tot] = await sqlTx([
    [`SELECT id, t, n, names, m FROM ti.entity WHERE id = $1`, [id]],
    [`SELECT to_char(date_trunc('day', published), 'YYYY-MM-DD') AS day, count(*)::int AS n, count(DISTINCT host)::int AS p FROM ti.mention WHERE eid = $1 AND published > now() - make_interval(days => $2) GROUP BY 1 ORDER BY 1`, [id, days]],
    [`SELECT b.eid, count(*)::int AS n, count(DISTINCT a.host)::int AS p, max(a.published) AS last FROM ti.mention a JOIN ti.mention b ON b.link = a.link AND b.eid <> a.eid
      WHERE a.eid = $1 AND a.published > now() - make_interval(days => $2) GROUP BY 1 ORDER BY n DESC LIMIT 80`, [id, days]],
    [`SELECT a, b, rel, basis FROM ti.erel WHERE a = $1 OR b = $1 LIMIT 300`, [id]],
    [`SELECT d.link, d.title, d.host, d.published, d.src, d.category, m.via FROM ti.mention m JOIN ti.mdoc d ON d.link = m.link WHERE m.eid = $1 ORDER BY m.published DESC LIMIT 30`, [id]],
    [`SELECT count(DISTINCT link)::int AS n, (SELECT count(*)::int FROM ti.mention WHERE eid = $1 AND published > now() - make_interval(days => $2)) AS mine,
        (SELECT min(published) FROM ti.mention WHERE eid = $1) AS first FROM ti.mention WHERE published > now() - make_interval(days => $2)`, [id, days]],
  ]);
  if (!ent.length && !series.length) return { error: 'unknown entity', status: 404 };
  const ids = [...new Set([...nb.map((r) => r.eid), ...rel.flatMap((r) => [r.a, r.b])])].filter((x) => x !== id);
  const [names, df] = ids.length ? await sqlTx([
    [`SELECT id, t, n FROM ti.entity WHERE id = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))`, [ids]],
    [`SELECT eid, count(*)::int AS n FROM ti.mention WHERE eid = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb))) AND published > now() - make_interval(days => $2) GROUP BY 1`, [nb.map((r) => r.eid), days]],
  ]) : [[], []];
  const nm = new Map(names.map((r) => [r.id, r])), dfm = new Map(df.map((r) => [r.eid, r.n])), N = tot[0].n, mine = tot[0].mine;
  const label = (x) => { const e = nm.get(x); return e ? { id: x, t: e.t, n: e.n } : { id: x, t: x.split(':')[0], n: x.split(':').slice(1).join(':') }; };
  const e = ent[0] || { id, t: id.split(':')[0], n: id.split(':').slice(1).join(':'), names: '', m: {} };
  return {
    entity: { id: e.id, t: e.t, n: e.n, names: String(e.names || '').split(' | ').filter(Boolean).slice(0, 40), m: e.m || {} }, days, entries: mine, first_seen: tot[0].first, entries_window: N,
    series, co_mentioned: nb.map((r) => ({ ...label(r.eid), n: r.n, p: r.p, last: r.last, npmi: npmi(r.n, mine, dfm.get(r.eid), N) })),
    curated: rel.map((r) => ({ ...label(r.a === id ? r.b : r.a), rel: r.rel, basis: r.basis, dir: r.a === id ? 'out' : 'in' })),
    recent: docs,
  };
}
export async function entityPair(a, b, days = 90) {
  if (!EID.test(String(a || '')) || !EID.test(String(b || ''))) return { error: 'bad id', status: 400 };
  days = Math.max(7, Math.min(400, +days || 90));
  const docs = await sql(`SELECT d.link, d.title, d.host, d.published, d.src, x.via AS via_a, y.via AS via_b FROM ti.mention x JOIN ti.mention y ON y.link = x.link AND y.eid = $2
    JOIN ti.mdoc d ON d.link = x.link WHERE x.eid = $1 AND x.published > now() - make_interval(days => $3) ORDER BY x.published DESC LIMIT 40`, [a, b, days]);
  const rel = await sql(`SELECT a, b, rel, basis FROM ti.erel WHERE (a = $1 AND b = $2) OR (a = $2 AND b = $1)`, [a, b]);
  return { a, b, days, shared: docs.length, curated: rel, entries: docs };
}
export async function entitySearch(q, t = '', limit = 20) {
  q = String(q || '').trim().slice(0, 80);
  if (q.length < 2) return { q, hits: [] };
  limit = Math.max(1, Math.min(50, +limit || 20));
  const hits = await sql(`SELECT e.id, e.t, e.n, (SELECT count(*)::int FROM ti.mention m WHERE m.eid = e.id AND m.published > now() - interval '30 days') AS n30,
      CASE WHEN lower(e.n) = lower($1) THEN 3 WHEN lower(e.n) LIKE lower($1) || '%' THEN 2 WHEN e.names ILIKE '%' || $1 || '%' THEN 1 ELSE 0 END + similarity(e.n, $1) AS score
    FROM ti.entity e WHERE (e.names ILIKE '%' || $1 || '%' OR e.n % $1) AND ($2::text = '' OR e.t = $2) ORDER BY score DESC, n30 DESC LIMIT ${limit}`, [q, String(t || '')]);
  return { q, hits };
}
