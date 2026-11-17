// Theater news feeds (G74). The CTI blogs and the advisory feeds cover the cyber picture; the seventeen geopolitical
// theaters had no collected titles at all, so the triage tier could hand the analyst run nothing for them. This job reads
// open RSS and Atom feeds of news outlets, wire services and regional publishers, keeps title, link and date, and leaves
// the labelling to the triage job, which reads these titles beside the blog and advisory titles. Each theater has at least
// one feed, and where a theater has two parties with their own press both are read (Dawn and The Hindu; Middle East Eye
// and The Jerusalem Post). Titles and links only; every article belongs to its publisher.
// Tried and refused the collector from cloud egress on 17 November 2026 (not retried): ReliefWeb (406), The EastAfrican
// (404), Dawn, Addis Standard, Pakistan Today, The News International and the Associated Press of Pakistan (403),
// Borkena (a challenge page) and The Reporter Ethiopia (304). Pakistani press comes from The Express Tribune.
export const NEWS_FEEDS = [
  // Wire services and global desks
  { id: 'bbcworld', name: 'BBC News (World)', region: 'Global', url: 'https://feeds.bbci.co.uk/news/world/rss.xml' },
  { id: 'aljazeera', name: 'Al Jazeera', region: 'Global', url: 'https://www.aljazeera.com/xml/rss/all.xml' },
  { id: 'france24', name: 'France 24', region: 'Global', url: 'https://www.france24.com/en/rss' },
  { id: 'dw', name: 'Deutsche Welle', region: 'Global', url: 'https://rss.dw.com/rdf/rss-en-all' },
  { id: 'guardianworld', name: 'The Guardian (World)', region: 'Global', url: 'https://www.theguardian.com/world/rss' },
  { id: 'unnews', name: 'UN News', region: 'Global', url: 'https://news.un.org/feed/subscribe/en/news/all/rss.xml' },
  // Defence and security press
  { id: 'defenseone', name: 'Defense One', region: 'Global', url: 'https://www.defenseone.com/rss/all/' },
  { id: 'breakingdefense', name: 'Breaking Defense', region: 'Global', url: 'https://breakingdefense.com/feed/' },
  { id: 'warontherocks', name: 'War on the Rocks', region: 'Global', url: 'https://warontherocks.com/feed/' },
  { id: 'therecord', name: 'The Record', region: 'Global', url: 'https://therecord.media/feed' },
  // Maritime
  { id: 'gcaptain', name: 'gCaptain', region: 'Maritime', url: 'https://gcaptain.com/feed/' },
  { id: 'maritimeexec', name: 'The Maritime Executive', region: 'Maritime', url: 'https://maritime-executive.com/articles.rss' },
  { id: 'splash247', name: 'Splash247', region: 'Maritime', url: 'https://splash247.com/feed/' },
  // Theaters
  { id: 'mee', name: 'Middle East Eye', region: 'T-LEV', url: 'https://www.middleeasteye.net/rss' },
  { id: 'jpost', name: 'The Jerusalem Post', region: 'T-LEV', url: 'https://www.jpost.com/rss/rssfeedsfrontpage.aspx' },
  { id: 'iranintl', name: 'Iran International', region: 'T-HRM', url: 'https://www.iranintl.com/en/feed' },
  { id: 'arabnews', name: 'Arab News', region: 'T-RSY', url: 'https://www.arabnews.com/rss.xml' },
  { id: 'meduza', name: 'Meduza (English)', region: 'T-UKR', url: 'https://meduza.io/rss/en/all' },
  { id: 'ukrinform', name: 'Ukrinform', region: 'T-UKR', url: 'https://www.ukrinform.net/rss/block-lastnews' },
  { id: 'notesfrompoland', name: 'Notes from Poland', region: 'T-EUH', url: 'https://notesfrompoland.com/feed/' },
  { id: 'lrt', name: 'LRT (Lithuania)', region: 'T-EUH', url: 'https://www.lrt.lt/en/news-in-english?rss' },
  { id: 'err', name: 'ERR News (Estonia)', region: 'T-EUH', url: 'https://news.err.ee/rss' },
  { id: 'balkaninsight', name: 'Balkan Insight', region: 'T-BAL', url: 'https://balkaninsight.com/feed/' },
  { id: 'radiotamazuj', name: 'Radio Tamazuj', region: 'T-SDN', url: 'https://www.radiotamazuj.org/en/rss' },
  { id: 'dabanga', name: 'Dabanga', region: 'T-SDN', url: 'https://www.dabangasudan.org/en/feed' },
  { id: 'somaliguardian', name: 'Somali Guardian', region: 'T-HOA', url: 'https://www.somaliguardian.com/feed/' },
  { id: 'shabelle', name: 'Shabelle Media', region: 'T-HOA', url: 'https://shabellemedia.com/feed/' },
  { id: 'africanews', name: 'Africanews', region: 'T-SAH', url: 'https://www.africanews.com/feed/rss' },
  { id: 'amutv', name: 'Amu TV', region: 'T-AFP', url: 'https://amu.tv/feed/' },
  { id: 'afintl', name: 'Afghanistan International', region: 'T-AFP', url: 'https://www.afintl.com/en/feed' },
  { id: 'tribunepk', name: 'The Express Tribune', region: 'T-AFP', url: 'https://tribune.com.pk/feed/home' },
  { id: 'thehindu', name: 'The Hindu (National)', region: 'T-SAS', url: 'https://www.thehindu.com/news/national/feeder/default.rss' },
  { id: 'timesca', name: 'The Times of Central Asia', region: 'T-CAS', url: 'https://timesca.com/feed/' },
  { id: 'kunuz', name: 'Kun.uz', region: 'T-CAS', url: 'https://kun.uz/en/news/rss' },
  { id: '24kg', name: '24.kg', region: 'T-CAS', url: 'https://24.kg/english/rss/' },
  { id: 'thediplomat', name: 'The Diplomat', region: 'Asia', url: 'https://thediplomat.com/feed/' },
  { id: 'yonhap', name: 'Yonhap', region: 'T-KOR', url: 'https://en.yna.co.kr/RSS/news.xml' },
  { id: 'nknews', name: 'NK News', region: 'T-KOR', url: 'https://www.nknews.org/feed/' },
  { id: 'taipeitimes', name: 'Taipei Times', region: 'T-TWN', url: 'https://www.taipeitimes.com/xml/index.rss' },
  { id: 'inquirer', name: 'Inquirer Global Nation', region: 'T-SCS', url: 'https://globalnation.inquirer.net/feed' },
  { id: 'rappler', name: 'Rappler', region: 'T-SCS', url: 'https://www.rappler.com/feed/' },
  { id: 'mexiconewsdaily', name: 'Mexico News Daily', region: 'T-MEX', url: 'https://mexiconewsdaily.com/feed/' },
  { id: 'insightcrime', name: 'InSight Crime', region: 'T-MEX', url: 'https://insightcrime.org/feed/' },
  { id: 'mercopress', name: 'MercoPress', region: 'T-VEN', url: 'https://en.mercopress.com/rss' },
];
export const NEWS_LIMITS = { TIMEOUT_MS: 15000, CONCURRENCY: 8, KEEP_DAYS: 7, FRESH_H: 72, MAX_PER_FEED: 80 };
export async function jobNews(opts = {}) {
  const t0 = Date.now(), L = { ...NEWS_LIMITS, ...(opts.newsLimits || {}) };
  const feeds = await pool(NEWS_FEEDS, L.CONCURRENCY, async (f) => {
    const r = await get(f.url, { timeout: L.TIMEOUT_MS, headers: { accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5' } });
    const items = r.ok ? parseFeedItems(r.text) : null;
    return { ...f, ok: !!items, status: r.status, ms: r.ms, error: items ? null : r.ok ? 'answer is not a feed' : (r.error || `HTTP ${r.status}`), items: (items || []).slice(0, L.MAX_PER_FEED) };
  });
  if (!feeds.some((f) => f.ok)) throw new Error('no news feed answered: ' + feeds.map((f) => `${f.id} ${f.error}`).join('; '));
  // Dated entries inside the window only: the triage window runs on publication time, and an undated entry cannot be
  // placed in it. One row per link (a page can sit in two feeds; the first feed in NEWS_FEEDS order keeps it).
  const byLink = new Map();
  for (const f of feeds) for (const i of f.items) {
    if (!i.published || Date.now() - Date.parse(i.published) > L.FRESH_H * 3600000 || !/^https?:\/\//.test(i.link) || byLink.has(i.link)) continue;
    byLink.set(i.link, { link: i.link, feed: f.id, source: f.name, title: String(i.title).slice(0, 300), published: i.published });
  }
  const rows = [...byLink.values()];
  if (rows.length) {
    await sql(`INSERT INTO ti.news (link, feed, source, title, published) SELECT link, feed, source, title, published
      FROM jsonb_to_recordset($1::jsonb) AS x(link text, feed text, source text, title text, published timestamptz) ON CONFLICT (link) DO NOTHING`, [rows]);
    // The source network's searchable store (37h-sources.mjs) takes the same entries.
    await sql(`INSERT INTO ti.item (link, fp, feed, source, host, title, published, category, region, lang) SELECT DISTINCT ON (fp) link, fp, feed, source, host, title, published, 'geopolitics', region, 'en'
      FROM jsonb_to_recordset($1::jsonb) AS x(link text, fp text, feed text, source text, host text, title text, published timestamptz, region text) ORDER BY fp ON CONFLICT DO NOTHING`,
      [rows.map((r) => { const h = hostOf(r.link); const f = NEWS_FEEDS.find((x) => x.id === r.feed) || {}; return { ...r, host: h, fp: fp(r.title, h), region: f.region || 'Global' }; })]);
  }
  await sql(`DELETE FROM ti.news WHERE published < now() - make_interval(days => $1)`, [L.KEEP_DAYS]);
  const [{ n: held }] = await sql(`SELECT count(*)::int AS n FROM ti.news WHERE published > now() - make_interval(hours => $1)`, [L.FRESH_H]);
  const per = new Map(rows.map((r) => [r.feed, 0]));
  for (const r of rows) per.set(r.feed, per.get(r.feed) + 1);
  const feedRows = feeds.map(({ items, ...f }) => ({ kind: 'feed', ...f, entries: items.length, fresh: per.get(f.id) || 0,
    newest: items.map((i) => i.published).filter(Boolean).sort().pop() || null }));
  const doc = { source: 'News outlets, wire services and regional publishers, each read from its own RSS or Atom feed',
    terms: 'Titles, links and dates only; every article belongs to its publisher.',
    method: `Each feed is read every hour. Entries published in the last ${L.FRESH_H} hours are kept for the machine triage tier, which labels them with relevance, intrusion vector, theater and actors beside the CTI blog and advisory titles. The list names each feed with the region it was chosen for; the theater a title belongs to comes from the triage label, not from the feed.`,
    generated: new Date().toISOString(), served_from: 'store', feeds_ok: feeds.filter((f) => f.ok).length, titles_72h: held, count: feedRows.length, rows: feedRows };
  await recordVolume([['news_titles_72h', held]]);
  const failed = feeds.filter((f) => !f.ok).map((f) => ({ feed: f.id, status: f.status, error: f.error }));
  return { feeds: feeds.length, feeds_ok: feeds.length - failed.length, failed, read: rows.length, held_72h: held, published: await putDoc('news', doc), ms: Date.now() - t0 };
}
