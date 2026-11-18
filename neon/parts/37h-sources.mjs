// Source network (3.0). The registry (data/feeds.json, built and validated by pipeline/feeds_build.py, pushed to the
// bucket as ref/feeds.json) lists every feed with a category, a theater region and a tier. ti.feed keeps each feed's
// state; ti.item keeps the entries (title, publisher summary, link, time) for 45 days, indexed for search. Each run reads
// the feeds that are due (tier 1 every 20 minutes, tier 2 hourly, tier 3 every four hours), oldest first, inside a time
// budget. A feed that fails heals itself in order: its stored alternate, a feed found on the publisher's own pages, then a
// Google News site: feed for the publisher (titles and links as Google syndicates them). A healed feed tries its own
// address again every twelve hours. Titles are fingerprinted with the publisher host, so a story read both directly and
// through Google News is stored once.
export const SOURCE_LIMITS = { BUDGET_MS: 170000, CONCURRENCY: 28, TIMEOUT_MS: 15000, MAX_PER_RUN: 520, KEEP_DAYS: 45, SUMMARY: 420,
  EVERY_MIN: { 1: 20, 2: 60, 3: 240 }, RETRY_PRIMARY_H: 12, MAX_BACKOFF_MIN: 720 };
export const gnewsUrl = (q, days = 2) => 'https://news.google.com/rss/search?' + new URLSearchParams({ q: `${q} when:${days}d`, hl: 'en-US', gl: 'US', ceid: 'US:en' });
export const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ''); } catch { return ''; } };
const stripTags = (s) => unent(String(s || '')).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
// Entries with the publisher's own summary and, for Google News items, the publisher named by <source url=...>.
export function parseEntries(xml) {
  const s = String(xml || '');
  if (!/<(rss|feed|rdf:RDF)\b/i.test(s.slice(0, 5000))) return null;
  const blocks = s.match(/<item\b[\s\S]*?<\/item>/gi) || s.match(/<entry\b[\s\S]*?<\/entry>/gi) || [];
  const out = [];
  for (const b of blocks.slice(0, 100)) {
    const tag = (n) => feedTag(b, n);
    let link = tag('link');
    if (!/^https?:\/\//.test(link)) { const m = b.match(/<link\b[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i) || b.match(/<link\b[^>]*href=["']([^"']+)["']/i); link = m ? unent(m[1]) : ''; }
    const t = Date.parse(tag('pubDate') || tag('published') || tag('updated') || tag('dc:date'));
    let title = stripTags(tag('title')).slice(0, 300);
    const src = b.match(/<source\b[^>]*url=["']([^"']+)["'][^>]*>([\s\S]*?)<\/source>/i);
    const publisher = src ? stripTags(src[2]) : '', phost = src ? hostOf(unent(src[1])) : '';
    if (publisher && title.endsWith(' - ' + publisher)) title = title.slice(0, -(publisher.length + 3));
    const summary = stripTags(tag('description') || tag('summary') || tag('content:encoded') || tag('content')).slice(0, SOURCE_LIMITS.SUMMARY);
    if (title && /^https?:\/\//.test(link.trim())) out.push({ title, link: link.trim(), published: isFinite(t) ? new Date(t).toISOString() : null, summary: phost ? '' : summary, publisher, phost });
  }
  return out;
}
const fp = (title, host) => createHash('md5').update(String(title).toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '') + '|' + host).digest('hex');
let REG = null;
export async function sourceRegistry(force = false) {
  if (REG && !force && Date.now() - REG.at < 3600000) return REG;
  // The published registry first (the site deploy carries every registry change), the bucket copy if the site is down.
  let doc = null;
  const r = await get(ENV().TI_FEEDS_URL || 'https://intel.kilfoycyber.com/data/feeds.json', { as: 'json', timeout: 20000 });
  if (r.ok && r.json && Array.isArray(r.json.feeds) && r.json.feeds.length >= 50) doc = r.json;
  if (!doc) {
    const o = await refGet('ref/feeds.json');
    if (!o) throw new Error('the source registry is unreachable: site ' + (r.status || r.error) + ', and ref/feeds.json is missing from the bucket (push asset=feeds)');
    doc = JSON.parse(o.buf.toString('utf8'));
  }
  REG = { at: Date.now(), doc, byId: new Map(doc.feeds.map((f) => [f.id, f])) };
  return REG;
}
async function readOne(f, st, url, deadline) {
  const left = deadline - Date.now();
  if (left < 800) return { ok: false, status: 0, error: 'run deadline' };
  const h = { accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5' };
  if (url === st.url_used && st.etag) h['if-none-match'] = st.etag;
  if (url === st.url_used && st.last_modified) h['if-modified-since'] = st.last_modified;
  const r = await get(url, { timeout: Math.min(SOURCE_LIMITS.TIMEOUT_MS, left), headers: h });
  if (r.status === 304) return { ok: true, status: 304, entries: [], unchanged: true, ms: r.ms };
  const entries = r.ok ? parseEntries(r.text) : null;
  if (!entries) return { ok: false, status: r.status, error: r.ok ? 'answer is not a feed' : (r.error || 'HTTP ' + r.status), ms: r.ms };
  return { ok: true, status: r.status, entries, etag: r.headers && r.headers.get('etag'), last_modified: r.headers && r.headers.get('last-modified'), ms: r.ms };
}
export async function jobSources(opts = {}) {
  const t0 = Date.now(), L = { ...SOURCE_LIMITS, ...(opts.sourceLimits || {}) }, reg = await sourceRegistry(!!opts.rebuild);
  // The registry's rows enter ti.feed when the registry changes (its generated stamp), not every run.
  const stamp = await kvGet('sources:registry');
  if (!stamp || stamp.generated !== reg.doc.generated || opts.rebuild) {
    await sqlTx([
      [`INSERT INTO ti.feed (id, url, next_at) SELECT id, url, now() FROM jsonb_to_recordset($1::jsonb) AS x(id text, url text) ON CONFLICT (id) DO UPDATE SET url = EXCLUDED.url, active = true`,
        [reg.doc.feeds.map((f) => ({ id: f.id, url: f.url }))]],
      [`UPDATE ti.feed SET active = false WHERE id NOT IN (SELECT jsonb_array_elements_text($1::jsonb))`, [reg.doc.feeds.map((f) => f.id)]],
    ]);
    await kvPut('sources:registry', { generated: reg.doc.generated, count: reg.doc.feeds.length, at: new Date().toISOString() });
  }
  const due = await sql(`SELECT id, url, alt, via, url_used, etag, last_modified, fails, primary_at FROM ti.feed WHERE active AND next_at <= now() ORDER BY next_at LIMIT $1`,
    [opts.holder === 'cron' || opts.holder === undefined ? L.MAX_PER_RUN : Math.min(L.MAX_PER_RUN, 120)]);
  const deadline = t0 + Math.min(L.BUDGET_MS, opts.budgetMs || L.BUDGET_MS), items = [], upd = [];
  let healed = 0, failed = 0, unchanged = 0, unread = 0;
  await pool(due, L.CONCURRENCY, async (st) => {
    const f = reg.byId.get(st.id);
    if (!f) return;
    if (Date.now() > deadline - 1000) { unread++; return; }
    const tryPrimary = st.via && st.via !== 'primary' && Date.now() - Date.parse(st.primary_at || 0) > L.RETRY_PRIMARY_H * 3600000;
    const ladder = [];
    if (!st.via || st.via === 'primary' || tryPrimary) ladder.push(['primary', f.url]);
    if (st.alt) ladder.push([st.via && st.via !== 'primary' ? st.via : 'alt', st.alt]);
    let got = null, via = null, url = null, err = null;
    for (const [v, u] of ladder) { const r = await readOne(f, st, u, deadline); if (r.ok) { got = r; via = v; url = u; break; } err = err || r; }
    // Heal: discovery on the publisher's pages, then Google News for the publisher's host. Not for Google News feeds.
    if (!got && !f.gnews && Date.now() < deadline - 3000) {
      const home = (() => { try { const x = new URL(f.url); return x.origin + '/'; } catch { return null; } })();
      const h = home ? await get(home, { timeout: 8000, headers: { accept: 'text/html' } }) : { ok: false };
      for (const c of (h.ok ? discoverFeed(String(h.text || '').slice(0, 400000), home) : []).filter((u) => u !== f.url).slice(0, 3)) {
        const r = await readOne(f, st, c, deadline);
        if (r.ok) { got = r; via = 'discovered'; url = c; break; }
      }
      if (!got && hostOf(f.url)) {
        const g = gnewsUrl('site:' + (f.publisher || hostOf(f.url)));
        const r = await readOne(f, st, g, deadline);
        if (r.ok) { got = r; via = 'gnews'; url = g; }
      }
      if (got) healed++;
    }
    const fails = got ? 0 : (st.fails || 0) + 1;
    const every = L.EVERY_MIN[f.tier] || 60, wait = got ? every : Math.min(L.MAX_BACKOFF_MIN, every * 2 ** Math.min(fails, 5));
    if (!got) failed++;
    if (got && got.unchanged) unchanged++;
    const host = hostOf(f.url);
    for (const e of (got && got.entries) || []) {
      if (!e.published || Date.now() - Date.parse(e.published) > L.KEEP_DAYS * 86400000 || Date.parse(e.published) > Date.now() + 3600000) continue;
      const ph = e.phost || (f.gnews ? (f.publisher || '') : host);
      items.push({ link: e.link, fp: fp(e.title, ph || host), feed: f.id, source: e.publisher || (f.gnews && !f.publisher ? '' : f.name.replace(/ \(via Google News\)$/, '')), host: ph || host,
        title: e.title, summary: e.summary || null, published: e.published, category: f.category, region: f.region, lang: f.lang || 'en' });
    }
    upd.push({ id: f.id, ok: !!got, via: got ? via : st.via, alt: got && via !== 'primary' ? url : st.alt, url_used: got ? url : st.url_used,
      etag: got && !got.unchanged ? got.etag || null : st.etag, last_modified: got && !got.unchanged ? got.last_modified || null : st.last_modified,
      status: got ? (got.unchanged ? 'unchanged' : 'ok') : String((err && err.error) || 'failed').slice(0, 120), entries: got && !got.unchanged ? got.entries.length : null,
      fails, wait, primary: ladder.length && ladder[0][0] === 'primary' ? 1 : 0 });
  });
  const byLink = new Map();
  for (const i of items) if (!byLink.has(i.link)) byLink.set(i.link, i);
  const rows = [...byLink.values()];
  const CH = 800;
  for (let i = 0; i < rows.length; i += CH)
    await sql(`INSERT INTO ti.item (link, fp, feed, source, host, title, summary, published, category, region, lang)
      SELECT DISTINCT ON (fp) link, fp, feed, source, host, title, summary, published, category, region, lang FROM jsonb_to_recordset($1::jsonb)
        AS x(link text, fp text, feed text, source text, host text, title text, summary text, published timestamptz, category text, region text, lang text)
      ORDER BY fp, published ON CONFLICT DO NOTHING`, [rows.slice(i, i + CH)]);
  if (upd.length) await sql(`UPDATE ti.feed f SET via = x.via, alt = x.alt, url_used = x.url_used, etag = x.etag, last_modified = x.last_modified, status = x.status,
      fails = x.fails, checked_at = now(), ok_at = CASE WHEN x.ok THEN now() ELSE f.ok_at END, entries = coalesce(x.entries, f.entries),
      primary_at = CASE WHEN x.primary = 1 THEN now() ELSE f.primary_at END, next_at = now() + make_interval(mins => x.wait)
    FROM jsonb_to_recordset($1::jsonb) AS x(id text, ok boolean, via text, alt text, url_used text, etag text, last_modified text, status text, entries int, fails int, wait int, "primary" int)
    WHERE f.id = x.id`, [upd]);
  if (new Date().getUTCMinutes() < 15) await sql(`DELETE FROM ti.item WHERE published < now() - make_interval(days => $1)`, [L.KEEP_DAYS]);
  const [n] = await sql(`SELECT count(*)::int AS items, count(*) FILTER (WHERE seen_at > now() - interval '24 hours')::int AS new_24h, count(DISTINCT host)::int AS publishers FROM ti.item`);
  await recordVolume([['source_items_24h', n.new_24h]]);
  const published = new Date().getUTCMinutes() % 30 < 15 || opts.holder === 'manual' ? await putDoc('sources', await sourcesDoc(reg)) : null;
  return { due: due.length, read: upd.length, unread, ok: upd.length - failed, failed, healed, unchanged, entries: rows.length, items: n.items, new_24h: n.new_24h, publishers: n.publishers, published, ms: Date.now() - t0 };
}
export async function sourcesDoc(reg) {
  reg = reg || await sourceRegistry();
  const st = await sql(`SELECT f.id, f.status, f.via, f.fails, f.ok_at, f.checked_at, (SELECT count(*)::int FROM ti.item i WHERE i.feed = f.id AND i.published > now() - interval '7 days') AS items_7d,
    (SELECT max(published) FROM ti.item i WHERE i.feed = f.id) AS newest FROM ti.feed f WHERE f.active`);
  const S = new Map(st.map((r) => [r.id, r]));
  const rows = reg.doc.feeds.map((f) => { const s = S.get(f.id) || {}; return { kind: 'feed', id: f.id, name: f.name, url: f.url, category: f.category, region: f.region, tier: f.tier, lang: f.lang,
    origin: f.origin, status: s.status || 'not yet read', via: s.via || null, ok: s.fails === 0 && !!s.ok_at, fails: s.fails || 0, items_7d: s.items_7d || 0, newest: s.newest || null, checked_at: s.checked_at || null }; });
  const [t] = await sql(`SELECT count(*)::int AS items, count(DISTINCT host)::int AS publishers, count(*) FILTER (WHERE published > now() - interval '24 hours')::int AS d1 FROM ti.item`);
  const by = (k) => rows.reduce((a, r) => ((a[r[k]] = (a[r[k]] || 0) + 1), a), {});
  return { source: 'The KTI source network: CTI blogs, security news, CERTs and agencies, vulnerability sources, think tanks, regional and maritime press, and Google News query feeds, each read from its own feed',
    terms: 'Titles, summaries and links belong to their publishers; Google News items are as Google syndicates them.',
    method: 'pipeline/feeds_build.py merges a curated core with four open lists and keeps feeds that answer with an entry in the last 180 days; the collector reads each on its tier and heals a failing feed through discovery or Google News.',
    lists: reg.doc.lists, registry_generated: reg.doc.generated, generated: new Date().toISOString(), served_from: 'store',
    feeds: rows.length, feeds_ok: rows.filter((r) => r.ok).length, healed: rows.filter((r) => r.ok && r.via && r.via !== 'primary').length, by_category: by('category'), by_via: by('via'),
    items_45d: t.items, publishers: t.publishers, items_24h: t.d1, rejected: (reg.doc.rejected || []).length, count: rows.length, rows };
}
// Search (3.0). Full-text over the collected entries (title and publisher summary) and the advisories, newest and best
// first, with each hit's triage label and the publishers that carried the same story. Query syntax is web-style
// ("quoted phrase", -exclude, OR); a word that the index does not hold as a whole word is matched as a prefix, then by
// substring of the title.
export async function search({ q = '', days = 30, category = '', region = '', limit = 50, offset = 0, relax = true, broaden = false } = {}) {
  q = String(q || '').trim().slice(0, 200);
  if (q.length < 2) return { q, hits: [], total: 0 };
  days = Math.max(1, Math.min(45, +days || 30)); limit = Math.max(1, Math.min(100, +limit || 50)); offset = Math.max(0, Math.min(1000, +offset || 0));
  const words = q.replace(/["()]/g, ' ').split(/\s+/).filter((w) => w && !/^(or|and|-.*)$/i.test(w));
  const lex = words.map((w) => w.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '')).filter(Boolean);
  const prefix = lex.map((w) => w + ':*').join(' & ');
  const like = '%' + words.join('%').replace(/[%_\\]/g, '') + '%';
  // Strict: every word (web syntax, then as prefixes, then the title as a substring). Relaxed (3.0.4), used only when a
  // query of three or more words matches nothing strictly, so a long agent query ("Optimizely security incident November
  // 2026 malicious code supply chain attack" found nothing on 18 November) still finds the reporting that names the
  // subject: see below.
  const strict = `(i.tsv @@ websearch_to_tsquery('simple', $1) OR i.tsv @@ to_tsquery('simple', $2) OR i.title ILIKE $6)`;
  const anyWords = [...new Set(lex.filter((w) => w.length >= 4 && !/^\d+$/.test(w)))].map((w) => w + ':*').join(' | ');
  const run = async (match, rankExpr, order, tq = '') => {
    const params = [q, prefix || 'zzzz', days, category || null, region || null, like, tq || 'zzzz'];
    // Every parameter is named once in the filter, so each statement can type all seven whichever match it uses.
    const where = `i.published > now() - make_interval(days => $3) AND ($4::text IS NULL OR i.category = $4) AND ($5::text IS NULL OR i.region = $5)
      AND coalesce($1::text, $2::text, $6::text, $7::text, '') IS NOT NULL AND ${match}`;
    const [hits, facets, cats, days_] = await sqlTx([
      [`SELECT i.link, i.title, i.source, i.host, i.published, i.category, i.region, i.lang, ts_headline('simple', coalesce(i.summary, ''), ${rankExpr.q}, 'MaxWords=40, MinWords=15, StartSel=«, StopSel=»') AS snippet,
          t.relevance, t.vector, t.theater, t.actors, t.why, t.verify, coalesce(t.cluster, t.link) AS story, ${rankExpr.rank} AS rank
        FROM ti.item i LEFT JOIN ti.triage t ON t.link = i.link WHERE ${where}
        ORDER BY ${order} LIMIT ${limit} OFFSET ${offset}`, params],
      [`SELECT count(*)::int AS total, count(DISTINCT i.host)::int AS publishers, min(i.published) AS first_seen, max(i.published) AS last_seen FROM ti.item i WHERE ${where}`, params],
      [`SELECT i.category, count(*)::int AS n FROM ti.item i WHERE ${where} GROUP BY 1 ORDER BY 2 DESC`, params],
      [`SELECT to_char(date_trunc('day', i.published), 'YYYY-MM-DD') AS day, count(*)::int AS n, count(DISTINCT i.host)::int AS publishers FROM ti.item i WHERE ${where} GROUP BY 1 ORDER BY 1`, params],
    ]);
    return { hits, f: facets[0] || {}, cats, days_ };
  };
  let r = await run(strict, { q: `websearch_to_tsquery('simple', $1)`, rank: `ts_rank(i.tsv, websearch_to_tsquery('simple', $1)) + CASE WHEN i.title ILIKE $6 THEN 0.5 ELSE 0 END` },
    `date_trunc('day', i.published) DESC, rank DESC, i.published DESC`), relaxed = false;
  // Broaden (reports, 3.0.5): a subject of two or more words with fewer than BROADEN strict entries ("Optimizely breach":
  // 6, against 114 on "Optimizely") adds the distinctive-word entries after the strict ones.
  const BROADEN = 15, wantRelax = (relax && !r.f.total && lex.length >= 3) || (broaden && lex.length >= 2 && (r.f.total || 0) < BROADEN);
  let broadened = false;
  if (wantRelax && anyWords) {
    // The distinctive words carry the subject: those in at most 3 percent of the window's entries. The rarest name (or,
    // without one, the rarest word) is required and the others rank the entries that also carry them first, so the subject keeps its full breadth (18
    // November: "Optimizely ... malicious code supply chain attack"; an any-word match had ranked generic supply chain
    // stories above the 108 Optimizely entries). A query with no distinctive word falls back to any of its words.
    const terms = [...new Set(lex.filter((w) => w.length >= 4 && !/^\d+$/.test(w)))].slice(0, 10);
    const df = await sql(`SELECT w, (SELECT count(*)::int FROM ti.item i WHERE i.published > now() - make_interval(days => $2) AND i.tsv @@ to_tsquery('simple', w || ':*')) AS n,
        (SELECT count(*)::int FROM ti.item i WHERE i.published > now() - make_interval(days => $2)) AS of FROM jsonb_array_elements_text($1::jsonb) AS w`, [terms, days]);
    // A capitalised word (a name: Optimizely, Bybit, Salt Typhoon) is the subject before a rarer common word ("skimmer").
    const proper = new Set(words.filter((w) => /^\p{Lu}/u.test(w)).map((w) => w.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '')));
    const rareD = df.filter((d) => d.n > 0 && d.n <= Math.max(50, 0.03 * d.of)).sort((a, b) => (proper.has(b.w) - proper.has(a.w)) || a.n - b.n);
    const rare = rareD.map((d) => d.w + ':*');
    const tries = rare.length ? [`${rare[0]} & (${rare.join(' | ')})`] : [anyWords];
    const rq = { q: `to_tsquery('simple', $7)`, rank: `ts_rank(i.tsv, to_tsquery('simple', $7))` };
    const r2 = await run(`i.tsv @@ to_tsquery('simple', $7)`, rq, `rank DESC, i.published DESC`, tries[0]);
    if (r.f.total && r2.f.total > r.f.total) {
      const seen = new Set(r.hits.map((h) => h.link));
      r = { ...r2, hits: [...r.hits, ...r2.hits.filter((h) => !seen.has(h.link))].slice(0, limit), strict: r.hits.length }; broadened = true;
    } else if (!r.f.total && r2.f.total) { r = r2; relaxed = true; }
  }
  const [adv] = await sqlTx([[`SELECT a.link, a.title, a.feed AS source, coalesce(a.published, a.seen_at) AS published, a.cves FROM ti.advisory a
      WHERE coalesce(a.published, a.seen_at) > now() - make_interval(days => $2) AND (a.title ILIKE $1 OR a.cves::text ILIKE $1) ORDER BY 4 DESC LIMIT 20`, [like, days]]]);
  const f = r.f;
  return { q, days, relaxed, broadened, strict: broadened ? r.strict : undefined, total: f.total || 0, publishers: f.publishers || 0, first_seen: f.first_seen || null, last_seen: f.last_seen || null,
    by_category: Object.fromEntries(r.cats.map((c) => [c.category, c.n])), by_day: r.days_, advisories: adv, hits: r.hits, limit, offset };
}
