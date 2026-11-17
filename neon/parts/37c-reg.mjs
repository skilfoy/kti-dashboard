// Registries read for context (split from 37-intel.mjs): Lanes outlets and naming, CTI blogs, link health, OFAC action pages.
// ---------------------------------------------------------------- Lanes outlet registry and naming choices (G66)
export const LANES_REG = { outlets: 'https://lanes.news/data/outlets.csv', naming: 'https://lanes.news/data/naming.csv' };
const col = (row, ...needles) => { for (const k of Object.keys(row)) { const lk = k.toLowerCase(); if (needles.some((n) => lk === n)) return row[k]; } for (const k of Object.keys(row)) { const lk = k.toLowerCase(); if (needles.some((n) => lk.includes(n))) return row[k]; } return ''; };
const lanesKey = (k) => String(k).toLowerCase().replace(/[^a-z0-9]/g, '');
function lanesPick(row, test) { for (const k of Object.keys(row)) if (test(lanesKey(k))) return row[k]; return ''; }
export function lanesRegistryDoc(outletsCsv, namingCsv, now = Date.now()) {
  const outlets = parseCsv(outletsCsv), naming = parseCsv(namingCsv);
  const oCols = outlets.length ? Object.keys(outlets[0]) : [], nCols = naming.length ? Object.keys(naming[0]) : [];
  const orows = outlets.map((o) => ({ kind: 'outlet', id: col(o, 'id', 'outlet_id', 'slug'), name: col(o, 'name', 'outlet'), country: col(o, 'country'), country_name: col(o, 'country_name'),
    language: col(o, 'language', 'lang'), funding: col(o, 'funding'), ownership: col(o, 'ownership_note', 'ownership', 'owner'), homepage: col(o, 'homepage', 'url', 'site'), lanes: col(o, 'lanes', 'lane') }));
  // naming.csv (checked 22 October 2026): date, conflict, refers_to, wording_side_a, wording_side_b, lane, lane_label,
  // uses_side_a_wording, uses_side_b_wording, english_words_counted, articles_not_counted_non_english; one row per day,
  // conflict, referent and lane (a, b or n). Rows aggregate 14 days per conflict, referent and lane, so each lane's
  // use of either side's wording can be compared.
  const cutoff = isoDay(now - 14 * IX_DAY);
  const agg = new Map();
  for (const r of naming) {
    const d = String(col(r, 'date')).slice(0, 10);
    if (d && d < cutoff) continue;
    const conflict = col(r, 'conflict'), ref = col(r, 'refers_to', 'refers', 'referent', 'concept');
    const a = col(r, 'wording_side_a') || lanesPick(r, (k) => /sidea/.test(k) && !/use|count/.test(k));
    const b = col(r, 'wording_side_b') || lanesPick(r, (k) => /sideb/.test(k) && !/use|count/.test(k));
    const lane = col(r, 'lane'), label = col(r, 'lane_label');
    const k = [conflict, ref, lane].join('|');
    const s = agg.get(k) || { kind: 'naming', conflict, refers_to: ref, side_a: a, side_b: b, lane, lane_label: label, dates: new Set(), uses_a: 0, uses_b: 0, words: 0, last: '' };
    if (d) s.dates.add(d);
    s.uses_a += Number(col(r, 'uses_side_a_wording') || lanesPick(r, (k2) => /use/.test(k2) && /sidea/.test(k2))) || 0;
    s.uses_b += Number(col(r, 'uses_side_b_wording') || lanesPick(r, (k2) => /use/.test(k2) && /sideb/.test(k2))) || 0;
    s.words += Number(col(r, 'english_words_counted')) || 0;
    if (d > s.last) s.last = d;
    agg.set(k, s);
  }
  const nrows = [...agg.values()].map(({ dates, ...x }) => ({ ...x, days: dates.size }))
    .sort((x, y) => String(x.conflict).localeCompare(String(y.conflict)) || String(x.refers_to).localeCompare(String(y.refers_to)) || String(x.lane).localeCompare(String(y.lane)));
  return { source: 'Lanes News open data: outlet registry and naming choices (lanes.news/data)', terms: 'CC BY 4.0', credit: 'Lanes News (2026). Outlet registry; Naming choices by side [data sets]. https://lanes.news/data. CC BY 4.0.',
    method: 'Naming counts are Lanes\' own: English-language articles only, up to eight a lane a day, a sample of each day\'s output. Rows sum the last 14 days by conflict, referent and lane (a and b are the two sides\' presses, n third-party press); uses_a and uses_b count articles using each side\'s wording.',
    columns: { outlets: oCols, naming: nCols }, outlets: orows.length, naming_rows: naming.length, generated: new Date(now).toISOString(), served_from: 'store', count: orows.length + nrows.length, rows: orows.concat(nrows.slice(0, 400)) };
}
export async function jobLanesreg() {
  const t0 = Date.now();
  const [o, n] = await Promise.all([get(LANES_REG.outlets, { timeout: 25000 }), get(LANES_REG.naming, { timeout: 25000 })]);
  if (!o.ok || !n.ok) throw new Error(`Lanes registry HTTP outlets ${o.status} naming ${n.status}`);
  const doc = lanesRegistryDoc(o.text, n.text);
  if (!doc.outlets) throw new Error('Lanes outlets.csv parsed to no rows');
  return { outlets: doc.outlets, naming_rows: doc.naming_rows, published: await putDoc('lanes-registry', doc), ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- CTI blogs (G57)
// The list (awesome_threat_intel_blogs, CC BY 4.0) is read from the repository's README each run. Its subscribe links point at
// a third-party reader, so each blog's own feed is discovered from its home page. Each scheduled run reads one sixth of
// the blogs, so every blog is read every six hours; titles, links and dates only.
export const BLOG_LIST = 'https://raw.githubusercontent.com/muchdogesec/awesome_threat_intel_blogs/main/README.md';
const FEED_GUESS = ['feed', 'feed/', 'rss', 'rss.xml', 'feed.xml', 'atom.xml', 'index.xml', 'feeds/posts/default', 'blog/feed', 'blog/rss.xml'];
export function discoverFeed(html, base) {
  const out = [];
  const re = /<link\b[^>]*>/gi;
  let m;
  while ((m = re.exec(String(html || '')))) {
    const tag = m[0];
    if (!/rel\s*=\s*["']?alternate/i.test(tag) || !/type\s*=\s*["']?application\/(rss|atom)\+xml/i.test(tag)) continue;
    const h = tag.match(/href\s*=\s*["']([^"']+)["']/i);
    if (h) { try { out.push(new URL(unent(h[1]), base).href); } catch { /* skip */ } }
  }
  return out.filter((u) => !/comments/i.test(u));
}
export function parseFeedItems(xml) {
  const s = String(xml || '');
  if (!/<(rss|feed|rdf:RDF)\b/i.test(s)) return null;
  const items = [];
  const blocks = s.match(/<item\b[\s\S]*?<\/item>/gi) || s.match(/<entry\b[\s\S]*?<\/entry>/gi) || [];
  for (const b of blocks.slice(0, 60)) {
    const tag = (n) => feedTag(b, n);
    let link = tag('link');
    if (!link) { const m = b.match(/<link\b[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i) || b.match(/<link\b[^>]*href=["']([^"']+)["']/i); link = m ? unent(m[1]) : ''; }
    const when = tag('pubDate') || tag('published') || tag('updated') || tag('dc:date');
    const t = Date.parse(when);
    items.push({ title: tag('title').slice(0, 300), link: link.trim(), published: isFinite(t) ? new Date(t).toISOString() : null });
  }
  return items.filter((i) => i.title && /^https?:\/\//.test(i.link));
}
export function parseBlogsReadme(md) {
  const rows = [];
  const re = /<tr>\s*<td>([\s\S]*?)<\/td>\s*<td>([\s\S]*?)<\/td>\s*<td>\s*<a href='([^']+)'/g;
  let m;
  while ((m = re.exec(String(md || '')))) { const name = ixText(m[1]), type = ixText(m[2]); if (name && name !== 'Name' && /^https?:/.test(m[3])) rows.push({ name, type, url: m[3] }); }
  return rows;
}
// Blogs job limits (2 November 2026: the 18:49 UTC run read 26 sources in 73 seconds, one hour after 36 in 7.5 seconds,
// because a slow blog could spend 12 seconds on its feed and 10 on each of six discovery guesses while the pool waited).
// Each source now has one deadline for all of its requests, one retry of a transient feed failure, and the pool is
// capped; sources the run budget leaves unread go first next run (oldest check first).
// Feeds for blogs whose home page hides its feed or refuses the collector, each confirmed on 17 November 2026 to answer
// with dated entries. Tried before discovery; a blog's stored feed still comes first once one has parsed.
export const BLOG_FEEDS = {
  'https://medium.com/falconforce': 'https://medium.com/feed/falconforce',
  'https://www.proofpoint.com/uk/blog': 'https://www.proofpoint.com/us/rss.xml',
  'https://www.fortinet.com/blog': 'https://feeds.fortinet.com/fortinet/blog/threat-research',
  'https://isc.sans.edu/diary': 'https://isc.sans.edu/rssfeed_full.xml',
  'https://www.hackread.com/': 'https://www.hackread.com/feed/',
  'https://cofense.com/blog/': 'https://cofense.com/feed/',
  'https://www.bitdefender.com/blog/labs/': 'https://www.bitdefender.com/blog/api/rss/labs/',
  'https://heimdalsecurity.com/blog/posts/': 'https://heimdalsecurity.com/blog/feed/',
  'https://www.ncsc.gov.uk/information/rss-feeds': 'https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml',
  'https://cloud.google.com/blog/topics/threat-intelligence': 'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/',
  'https://securityonline.info': 'https://securityonline.info/feed/',
  'https://www.nextgov.com/cybersecurity/': 'https://www.nextgov.com/rss/cybersecurity/',
  'https://securitylabs.datadoghq.com/articles/': 'https://securitylabs.datadoghq.com/rss/feed.xml',
  'https://www.zscaler.com/blogs': 'https://www.zscaler.com/blogs/feeds/security-research',
  'https://www.cisecurity.org/insights/blog': 'https://www.cisecurity.org/feed/blog',
  'https://www.cyber.gc.ca/en': 'https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en',
  'https://www.theregister.com/security/': 'https://www.theregister.com/security/headlines.atom',
  'https://www.halcyon.ai/': 'https://www.halcyon.ai/blog/rss.xml',
  'https://www.labs.greynoise.io/': 'https://www.greynoise.io/blog/rss.xml',
  'https://www.welivesecurity.com/en/about-eset-research': 'https://feeds.feedburner.com/eset/blog',
  'https://threats.wiz.io/': 'https://www.wiz.io/feed/rss.xml',
  'https://www.infosecurity-magazine.com/news': 'https://www.infosecurity-magazine.com/rss/news/',
  'https://www.volexity.com/blog/': 'https://www.volexity.com/feed/',
};
export const BLOG_LIMITS = { PER_SOURCE_MS: 15000, CONCURRENCY: 6, BUDGET_MS: 40000, RETRY_DELAY_MS: 1500, MAX_GUESSES: 4, OVERDUE_H: 7, MAX_PER_RUN: 60 };
const transient = (r) => !r.ok && (r.status === 0 || r.status === 429 || r.status >= 500);
// Whether a new blogs document is materially smaller than the last good one: fewer blogs with a working feed (more than
// 15 percent and at least 4 fewer) or fewer recent items (more than 40 percent, judged once the last one held 50).
export function blogsShrink(prev, next) {
  if (!prev) return null;
  const items = (d) => (d.rows || []).filter((r) => r.kind === 'item').length;
  const po = +prev.blogs_ok || 0, no = +next.blogs_ok || 0, pi = items(prev), ni = items(next);
  if (po - no >= 4 && no < po * 0.85) return `blogs with a working feed fell from ${po} to ${no}`;
  if (pi >= 50 && ni < pi * 0.6) return `items in the last 7 days fell from ${pi} to ${ni}`;
  return null;
}
export async function jobBlogs(opts = {}) {
  const t0 = Date.now(), L = { ...BLOG_LIMITS, ...(opts.blogLimits || {}) };
  const md = await get(BLOG_LIST, { timeout: 20000 });
  const seen = new Set();
  const blogs = md.ok ? parseBlogsReadme(md.text).filter((b) => !seen.has(b.url) && seen.add(b.url)) : [];
  if (blogs.length < 50) throw new Error('blog list: ' + (md.ok ? blogs.length + ' rows parsed' : 'HTTP ' + md.status));
  const known = new Map((await sql(`SELECT url, feed, status, fails, checked_at FROM ti.blog`)).map((b) => [b.url, b]));
  const slot = new Date().getUTCHours() % 6;
  // This hour's sixth of the list plus any blog not read for OVERDUE_H hours, oldest check first.
  const checked = (b) => { const k = known.get(b.url); return k && k.checked_at ? Date.parse(k.checked_at) : 0; };
  const due = opts.holder === 'cron'
    ? blogs.filter((b) => ixHash(b.url) % 6 === slot || Date.now() - checked(b) > L.OVERDUE_H * 3600000)
    : blogs.slice(0, 40);
  const todo = due.slice().sort((a, b) => checked(a) - checked(b)).slice(0, L.MAX_PER_RUN);
  const items = [], upd = [], failures = [], took = [];
  let unread = due.length - todo.length, retried = 0;
  const budget = t0 + L.BUDGET_MS;
  await pool(todo, L.CONCURRENCY, async (b) => {
    if (Date.now() > budget - 1000) { unread++; return; }
    const s0 = Date.now(), deadline = Math.min(s0 + L.PER_SOURCE_MS, budget);
    const left = () => deadline - Date.now();
    const ask = (u, accept) => (left() < 500 ? Promise.resolve({ ok: false, status: 0, error: 'source deadline' })
      : get(u, { timeout: Math.min(12000, left()), headers: { accept: accept || 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5' } }));
    const k = known.get(b.url) || {};
    let feed = k.feed || null, parsed = null, status = 'ok', note = null;
    if (feed) {
      let r = await ask(feed);
      if (transient(r) && left() > L.RETRY_DELAY_MS + 1000) { retried++; await new Promise((ok) => setTimeout(ok, L.RETRY_DELAY_MS)); r = await ask(feed); }
      parsed = r.ok ? parseFeedItems(r.text) : null;
      if (!parsed) { note = 'feed ' + (r.status || r.error); feed = null; }
    }
    if (!feed && BLOG_FEEDS[b.url] && left() > 1000) {
      const r = await ask(BLOG_FEEDS[b.url]);
      const p = r.ok ? parseFeedItems(r.text) : null;
      if (p) { feed = BLOG_FEEDS[b.url]; parsed = p; }
    }
    if (!feed && left() > 1000) {
      const h = await ask(b.url, 'text/html');
      const cands = h.ok ? discoverFeed((h.text || '').slice(0, 400000), b.url) : [];
      for (const g of FEED_GUESS) { try { cands.push(new URL(g, b.url.endsWith('/') ? b.url : b.url + '/').href); } catch { /* skip */ } }
      for (const c of [...new Set(cands)].slice(0, L.MAX_GUESSES)) {
        if (left() < 1000) break;
        const r = await ask(c);
        const p = r.ok ? parseFeedItems(r.text) : null;
        if (p) { feed = c; parsed = p; break; }
      }
      if (!feed) status = left() < 1000 ? 'source deadline' : h.ok ? 'no feed found' : 'home page ' + (h.status || h.error);
    } else if (!feed) status = 'source deadline';
    const ms = Date.now() - s0;
    took.push(ms);
    if (!feed) failures.push({ url: b.url, name: b.name, why: status, note: note || undefined, ms });
    const fresh = (parsed || []).filter((i) => i.published && Date.now() - Date.parse(i.published) < 14 * IX_DAY);
    for (const i of fresh) items.push({ ...i, blog_url: b.url });
    upd.push({ url: b.url, name: b.name, type: b.type, feed, status: feed ? 'ok' : status, note, items: (parsed || []).length, newest: (parsed || []).map((i) => i.published).filter(Boolean).sort().pop() || null });
  });
  if (upd.length) await sqlTx([
    [`INSERT INTO ti.blog (url, name, type, feed, status, note, items, newest, checked_at, fails) SELECT url, name, type, feed, status, note, items, newest, now(), CASE WHEN feed IS NULL THEN 1 ELSE 0 END
      FROM jsonb_to_recordset($1::jsonb) AS x(url text, name text, type text, feed text, status text, note text, items int, newest timestamptz)
      ON CONFLICT (url) DO UPDATE SET name = EXCLUDED.name, type = EXCLUDED.type, feed = coalesce(EXCLUDED.feed, CASE WHEN ti.blog.fails >= 3 THEN NULL ELSE ti.blog.feed END),
        status = EXCLUDED.status, note = EXCLUDED.note, items = EXCLUDED.items, newest = coalesce(EXCLUDED.newest, ti.blog.newest), checked_at = now(),
        fails = CASE WHEN EXCLUDED.feed IS NULL THEN ti.blog.fails + 1 ELSE 0 END`, [upd]],
    [`INSERT INTO ti.blog_item (link, blog_url, title, published, seen_at) SELECT link, blog_url, title, published, now() FROM jsonb_to_recordset($1::jsonb) AS x(link text, blog_url text, title text, published timestamptz)
      ON CONFLICT (link) DO NOTHING`, [items]],
  ]);
  const [bl, it] = await sqlTx([
    [`SELECT url, name, type, feed, status, items, newest, checked_at FROM ti.blog ORDER BY name`],
    [`SELECT i.link, i.title, i.published, b.name AS blog, b.type FROM ti.blog_item i JOIN ti.blog b ON b.url = i.blog_url WHERE i.published > now() - interval '7 days' ORDER BY i.published DESC LIMIT 400`],
  ]);
  const doc = { source: 'First-party CTI blogs listed by awesome_threat_intel_blogs (muchdogesec, CC BY 4.0), read from each blog\'s own feed',
    terms: 'List: CC BY 4.0. Items: titles and links only, each to its publisher.', method: 'Feeds are discovered from each blog\'s home page (link rel=alternate), with common feed paths as a fallback. Each blog is read every six hours; items from the last 7 days are candidates for the daily run, which fetches and confirms any item it cites.',
    blogs: bl.length, blogs_ok: bl.filter((b) => b.feed).length, listed: blogs.length, generated: new Date().toISOString(), served_from: 'store',
    count: bl.length + it.length, rows: bl.map((b) => ({ kind: 'blog', ...b })).concat(it.map((i) => ({ kind: 'item', ...i }))) };
  // Never publish a document materially smaller than the last good one: the run is recorded, the old document stays.
  let prev = null;
  try { prev = await getDoc('blogs'); } catch { /* no previous document readable: publish */ }
  const shrink = blogsShrink(prev, doc);
  const run = { due: due.length, read: upd.length, unread, with_feed: upd.filter((u) => u.feed).length, retried, failed: failures.length,
    failures: failures.sort((a, b) => b.ms - a.ms).slice(0, 25), items: items.length, slowest_ms: Math.max(0, ...took) };
  // A held document fails the run (run_failed), so the health record and the alerting workflow see it.
  if (shrink) return { ...run, held: { reason: shrink, last_good: prev && prev.generated }, published: null, run_failed: 'blogs document held: ' + shrink, ms: Date.now() - t0 };
  await recordVolume([['blog_items_7d', it.length]]);
  return { ...run, published: await putDoc('blogs', doc), ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- link health (G62)
// ref/links.json (pushed at build time) holds the registry and toolkit URLs and one known-good sample of each pivot
// pattern. Every scheduled run checks the twenty-fourth of them its hour selects, so each link is checked daily.
export function linkStatus(r, url) {
  if (!r || r.status === 0) return { status: 'review', why: r && r.error ? r.error : 'no response' };
  if (r.status >= 200 && r.status < 300) {
    const final = r.final || url;
    try { if (new URL(final).hostname.replace(/^www\./, '') !== new URL(url).hostname.replace(/^www\./, '')) return { status: 'review', why: 'redirected off site to ' + new URL(final).hostname }; } catch { /* keep ok */ }
    return { status: 'ok', why: null };
  }
  if ([401, 403, 429, 503].includes(r.status)) return { status: 'blocked', why: 'HTTP ' + r.status };
  return { status: 'review', why: 'HTTP ' + r.status };
}
export async function jobLinks(opts = {}) {
  const t0 = Date.now();
  const ref = await s3Get('ref/links.json');
  if (!ref) throw new Error('ref/links.json is missing from the bucket');
  const links = JSON.parse(ref.buf.toString('utf8'));
  const slot = new Date().getUTCHours();
  const todo = opts.holder === 'cron' ? links.filter((l) => ixHash(l.url) % 24 === slot) : links.slice(0, 60);
  const res = await pool(todo, 4, async (l) => {
    const r = await fetchT(l.url, { timeout: 15000, redirect: 'follow', headers: { accept: 'text/html,application/json;q=0.9,*/*;q=0.8' } }).then(async (x) => { try { await x.body?.cancel(); } catch { /* ignore */ } return { status: x.status, final: x.url }; })
      .catch((e) => ({ status: 0, error: String((e && e.name === 'AbortError') ? 'timeout' : (e && e.message) || e) }));
    const s = linkStatus(r, l.url);
    return { url: l.url, label: l.label || '', kind: l.kind || '', status: s.status, why: s.why, code: r.status || null };
  });
  if (res.length) await sql(`INSERT INTO ti.link_check (url, label, kind, status, why, code, checked_at, ok_at) SELECT url, label, kind, status, why, code, now(), CASE WHEN status = 'ok' THEN now() END
    FROM jsonb_to_recordset($1::jsonb) AS x(url text, label text, kind text, status text, why text, code int)
    ON CONFLICT (url) DO UPDATE SET label = EXCLUDED.label, kind = EXCLUDED.kind, status = EXCLUDED.status, why = EXCLUDED.why, code = EXCLUDED.code, checked_at = now(),
      ok_at = CASE WHEN EXCLUDED.status = 'ok' THEN now() ELSE ti.link_check.ok_at END`, [res]);
  const all = await sql(`SELECT url, label, kind, status, why, code, checked_at, ok_at FROM ti.link_check WHERE url IN (SELECT jsonb_array_elements_text($1::jsonb)) ORDER BY status DESC, label`,
    [links.map((l) => l.url)]);
  const by = all.reduce((t, r) => { t[r.status] = (t[r.status] || 0) + 1; return t; }, {});
  const doc = { source: 'threat-feeds link checks of the source registry, the OSINT toolkit and the pivot patterns', method: 'ok: 2xx, or a redirect within the same site. blocked: 401, 403, 429 or 503 (many sites refuse automated requests; the link stays). review: 404, 410, other errors, timeouts and redirects to another site. Each link is checked once a day.',
    listed: links.length, checked: all.length, by_status: by, generated: new Date().toISOString(), served_from: 'store', count: all.length, rows: all.map((r) => ({ kind: 'link', ...r })) };
  return { checked: res.length, by_status: by, published: await putDoc('links', doc), ms: Date.now() - t0 };
}

// ---------------------------------------------------------------- OFAC action pages (G61)
// Each Recent Actions entry links to a page listing the SDN entries it adds, removes or updates, under headings such as
// "The following vessels have been added to OFAC's SDN List:" or "The following deletions have been made to OFAC's SDN
// List:". Entries are text blocks in OFAC's list format: name, identifiers and program tags in brackets. A vessel entry
// opens "NAME (call sign or a.k.a. NAME) Type [tonnage] Country flag;" and carries "Vessel Registration Identification
// IMO". A heading this parser does not name closes the current section, so an unrecognized list never counts as added.
const OFAC_SECTION = [
  [/have been added to OFAC's SDN List/i, 'added'],
  [/have been (?:removed|deleted) from OFAC's SDN List|deletions have been made to OFAC's SDN List/i, 'removed'],
  [/updated on OFAC's SDN List|changes have been made to OFAC's SDN List|have been updated/i, 'updated'],
  [/Unrelated Administrative List Changes/i, 'admin'],
];
const OFAC_HEADING = /^(?:The following\b.*|.*\bList(?: Updates| Changes)?:?)$/i;
const OFAC_TAG = /\[([A-Z0-9][A-Z0-9_-]{1,30})\]/g;
const OFAC_KIND = [[/\bvessels?\b/i, 'vessel'], [/\bindividuals?\b/i, 'individual'], [/\baircraft\b/i, 'aircraft'], [/\bentit(?:y|ies)\b/i, 'entity']];
const VESSEL_KEY = /^(.*\b(?:Tanker|Carrier|Ship|Vessel|Cargo|Tug|Yacht|Barge|Dredger|Trawler|Reefer|Boat|Ferry|Tender))\b\s*(.*)$/;
const VESSEL_ACRONYM = /\s+((?:LPG|LNG|CNG|FPSO|FSO|FSU|VLCC|ULCC|RORO|Ro-Ro)(?:\/(?:LPG|LNG|CNG))?)$/;
// The entry's first clause, cut at the first semicolon outside parentheses (aliases can hold semicolons).
export function ofacHead(b) {
  let d = 0;
  for (let i = 0; i < b.length; i++) { const c = b[i]; if (c === '(') d++; else if (c === ')') d = Math.max(0, d - 1); else if (c === ';' && !d) return b.slice(0, i).trim(); }
  return b.trim();
}
// Name, call sign, aliases, type, flag, IMO and MMSI from a vessel entry, as OFAC prints them.
export function ofacVessel(b) {
  const v = { name: null, call_sign: null, aliases: [], type: null, flag: null, imo: null, mmsi: null };
  let rest = ofacHead(b);
  const open = rest.indexOf('(');
  if (open > 0) {
    v.name = rest.slice(0, open).trim();
    rest = rest.slice(open);
    while (rest[0] === '(') {
      let d = 0, i = 0;
      for (; i < rest.length; i++) { if (rest[i] === '(') d++; else if (rest[i] === ')' && --d === 0) break; }
      for (const part of rest.slice(1, i).split(';').map((x) => x.trim()).filter(Boolean)) {
        const ak = part.match(/^(?:a\.k\.a\.|f\.k\.a\.|n\.k\.a\.)\s*(.+)$/i);
        if (ak) v.aliases.push(ak[1].replace(/^["']|["']$/g, '').trim());
        else if (/^[A-Z0-9]{3,10}$/.test(part)) v.call_sign = part;
      }
      rest = rest.slice(i + 1).trim();
    }
  } else {
    // No parenthesis: the name is the leading run of words with no lower-case letter (OFAC prints vessel names in capitals).
    const words = rest.split(/\s+/);
    let n = 0;
    while (n < words.length && !/[a-z]/.test(words[n])) n++;
    v.name = words.slice(0, n).join(' ');
    rest = words.slice(n).join(' ');
    const ac = v.name.match(VESSEL_ACRONYM);
    if (ac && v.name.length > ac[0].length) { v.name = v.name.slice(0, -ac[0].length).trim(); rest = (ac[1] + ' ' + rest).trim(); }
  }
  rest = rest.replace(/\b[\d][\d,.]*\s*(?:DWT|GRT|NRT|GT|TEU)\b/g, ' ').replace(/\s+/g, ' ').trim();
  const fl = rest.match(/^(.*?)\s*\bflag$/i);
  const body = fl ? fl[1].trim() : rest;
  const k = body.match(VESSEL_KEY);
  if (k) { v.type = k[1].trim() || null; if (fl) v.flag = k[2].trim() || null; }
  else if (fl) v.flag = body || null;
  const vf = b.match(/Vessel Flag ([^;()]+?)\s*(?:;|\(|$)/);
  if (vf) v.flag = vf[1].trim();
  v.imo = (b.match(/\bIMO\s*(\d{7})\b/) || [])[1] || null;
  v.mmsi = (b.match(/\bMMSI\s*(\d{9})\b/) || [])[1] || null;
  if (!v.name) v.name = ofacHead(b).split(/\s\(/)[0].slice(0, 160);
  return v;
}
export function parseOfacAction(html) {
  const s = String(html || '').replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, ' ');
  const blocks = s.split(/<\/(?:p|li|h[1-6]|div|td|tr)>|<br\s*\/?>/i).map((b) => ixText(b)).filter(Boolean);
  let section = null, hint = null;
  const entries = [];
  for (const b of blocks) {
    const tagged = /\[[A-Z0-9][A-Z0-9_-]{1,30}\]/.test(b);
    if (!tagged && b.length < 200) {
      const sec = OFAC_SECTION.find(([re]) => re.test(b));
      if (sec || OFAC_HEADING.test(b)) {
        section = sec ? sec[1] : 'other';
        hint = (OFAC_KIND.find(([re]) => re.test(b)) || [])[1] || null;
      }
      continue;
    }
    if (!tagged || !section || section === 'admin' || section === 'other' || b.length < 15) continue;
    const tags = [...b.matchAll(OFAC_TAG)].map((m) => m[1]);
    const kind = /\(vessel\)/i.test(b) ? 'vessel' : /\(individual\)/i.test(b) ? 'individual' : /\(aircraft\)/i.test(b) ? 'aircraft'
      : hint || (/Vessel Registration Identification IMO/i.test(b) ? 'vessel' : 'entity');
    const head = ofacHead(b).split(/\s\(/)[0];
    const e = { section, kind, programs: [...new Set(tags)], cyber: tags.some((t) => /^CYBER/.test(t)) };
    if (kind === 'vessel') Object.assign(e, ofacVessel(b));
    else e.name = (kind === 'individual' ? head.split(',').slice(0, 2).join(',') : head.split(',')[0]).trim().slice(0, 160);
    entries.push(e);
  }
  return entries;
}
export function ofacSummary(entries) {
  const s = { added: 0, removed: 0, updated: 0, by_kind: {}, removed_by_kind: {}, programs: {}, vessels: [], cyber: [] };
  const byKey = new Map();
  for (const e of entries) {
    s[e.section] = (s[e.section] || 0) + 1;
    if (e.section === 'added') {
      s.by_kind[e.kind] = (s.by_kind[e.kind] || 0) + 1;
      for (const p of e.programs) s.programs[p] = (s.programs[p] || 0) + 1;
    } else if (e.section === 'removed') s.removed_by_kind[e.kind] = (s.removed_by_kind[e.kind] || 0) + 1;
    if (e.kind === 'vessel' && e.section !== 'updated') {
      // OFAC lists a vessel once per name it carries ("MARAYA (f.k.a. MED PATRON)" and "MED PATRON (a.k.a. MARAYA)").
      const key = e.section + ':' + (e.imo || e.name);
      const have = byKey.get(key);
      if (have) { for (const a of [e.name, ...e.aliases]) if (a && a !== have.name && !have.aliases.includes(a)) have.aliases.push(a); continue; }
      const v = { action: e.section, name: e.name, aliases: e.aliases.slice(), call_sign: e.call_sign, imo: e.imo, mmsi: e.mmsi, flag: e.flag, type: e.type, programs: e.programs };
      byKey.set(key, v);
      s.vessels.push(v);
    }
    if (e.cyber) s.cyber.push({ action: e.section, name: e.name, kind: e.kind, programs: e.programs });
  }
  return s;
}
// Adds page summaries to the snap-ofac document: cached by entry id in ti.kv, at most `max` new pages a run. The cache key
// carries the parser version, so a parser change re-reads every page once instead of keeping summaries from the old rules.
export const OFAC_CACHE = 'ofac-pages-v2';
export async function enrichOfacDoc(doc, fetchText, max = 10) {
  const cache = (await kvGet(OFAC_CACHE)) || {};
  const todo = (doc.rows || []).filter((r) => !cache[r.id]).slice(0, max);
  for (const r of todo) {
    const p = await fetchText(r.url);
    if (p && p.ok) cache[r.id] = { at: new Date().toISOString(), ...ofacSummary(parseOfacAction(p.text)) };
  }
  const keep = new Set((doc.rows || []).map((r) => r.id));
  for (const k of Object.keys(cache)) if (!keep.has(k)) delete cache[k];
  if (todo.length) await kvPut(OFAC_CACHE, cache);
  for (const r of doc.rows || []) {
    const c = cache[r.id];
    if (!c) continue;
    r.page_read = c.at; r.added = c.added; r.removed = c.removed; r.updated = c.updated; r.by_kind = c.by_kind; r.removed_by_kind = c.removed_by_kind || {};
    r.sdn_programs = c.programs; r.vessels = c.vessels; r.cyber_entries = c.cyber;
    if (c.cyber && c.cyber.some((x) => x.action === 'added')) r.cyber = 'Yes';
  }
  doc.pages_read = Object.keys(cache).length;
  doc.page_method = 'Each action page is read once: SDN entries counted by section (added, removed, updated) under OFAC\'s own headings, with type (individual, entity, vessel, aircraft) and program tag; a heading the parser does not recognize is skipped, never counted. Vessels carry name, call sign, aliases, IMO, MMSI, type and flag as OFAC prints them, one row per IMO. An entry tagged CYBER* is listed as a cyber designation and, when added, sets the cyber flag.';
  return doc;
}

