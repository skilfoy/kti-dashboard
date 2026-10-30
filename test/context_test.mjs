// Offline tests for neon/parts/36-context.mjs (Lanes temperatures and daily RSS, OFAC Recent Actions).
// Run from the working root: node test/context_test.mjs .
// Fixtures: the Lanes header and the six rows marked REAL are verbatim from lanes.news/data/temperatures.csv as read
// on 2026-10-19; the other Lanes rows are synthetic, built to exercise the 7-day windows. The OFAC listing is
// synthetic markup in the shape of ofac.treasury.gov/recent-actions carrying the ten entries listed there on
// 2026-10-19 (titles, dates and addresses as published), with sidebar links, entities and a duplicate added.
import assert from 'node:assert';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const SCR = path.resolve(process.argv[2] || '.');
const M = await import(pathToFileURL(path.join(SCR, 'neon', 'parts', '36-context.mjs')).href);
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };

// ---------------------------------------------------------------- CSV
ok(JSON.stringify(M.parseCsv('a,b\n1,"x, ""y"""\n\n2,z')) === JSON.stringify([{ a: '1', b: 'x, "y"' }, { a: '2', b: 'z' }]), 'CSV quotes, doubled quotes and blank lines');
ok(JSON.stringify(M.parseCsv('a,b\r\n1,2\r\n')) === JSON.stringify([{ a: '1', b: '2' }]), 'CSV with CRLF');
ok(M.parseCsv('').length === 0 && M.parseCsv(null).length === 0, 'empty CSV');

// ---------------------------------------------------------------- Lanes
const HEAD = 'date,conflict,country_a,country_a_name,country_b,country_b_name,events,articles,goldstein_mean,tone_mean,verbal_cooperation_share,material_cooperation_share,verbal_conflict_share,material_conflict_share,temperature';
const REAL = [
  '2026-08-22,afghanistan-pakistan,AFG,Afghanistan,PAK,Pakistan,17,69,-0.609,-8.425,0.4493,0,0.4058,0.1449,0.446',
  '2026-08-22,china-taiwan,CHN,China,TWN,Taiwan,44,380,-0.617,-3.281,0.6658,0.0105,0.3026,0.0211,0.211',
  '2026-08-22,india-pakistan,IND,India,PAK,Pakistan,7,13,-0.385,-6.576,0.1538,0.3846,0,0.4615,0.646',
  '2026-10-06,uk-argentina,ARG,Argentina,GBR,United Kingdom,11,60,-1.547,-3.369,0.5333,0,0.4667,0,0.28',
  '2026-10-06,usa-china,CHN,China,USA,United States,401,2928,-1.202,-3.022,0.3586,0.1513,0.3128,0.1773,0.436',
  '2026-10-06,usa-iran,IRN,Iran,USA,United States,615,3918,0.082,-3.659,0.6759,0.0151,0.2078,0.1013,0.267',
];
// Synthetic russia-ukraine: 14 days ending 2026-10-06; the earlier 7 at 0.5 (100 articles), the later 7 at 0.7 and 0.9.
const SYN = [];
for (let i = 13; i >= 0; i--) {
  const d = new Date(Date.parse('2026-10-06T00:00:00Z') - i * 864e5).toISOString().slice(0, 10);
  const later = i < 7;
  const t = later ? (i % 2 ? 0.9 : 0.7) : 0.5, a = later ? (i % 2 ? 300 : 100) : 100;
  SYN.push(`${d},russia-ukraine,RUS,Russia,UKR,Ukraine,50,${a},-3,-5,0.2,0.05,0.35,0.4,${t}`);
}
SYN.push('2026-10-06,"israel-palestine",ISR,"Israel",PSE,"Palestine, State of",20,40,-2,-6,0.1,0,0.5,0.4,0.62');
SYN.push('bad-date,russia-ukraine,RUS,Russia,UKR,Ukraine,1,1,0,0,0,0,0,0,0.1');
SYN.push('2026-10-05,russia-ukraine,RUS,Russia,UKR,Ukraine,1,1,0,0,0,0,0,0,');
const CSV = [HEAD, ...REAL, ...SYN].join('\n') + '\n';
const RSS = `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel><title>Lanes News</title>
<atom:link href="https://lanes.news/feed.xml" rel="self" type="application/rss+xml"/>
<item><title><![CDATA[Pakistan carries out new airstrikes inside Afghanistan as both sides trade blame]]></title><link>https://lanes.news/daily/afghanistan-pakistan/2026-10-07</link><pubDate>Wed, 07 Oct 2026 16:56:52 GMT</pubDate><description>x</description></item>
<item><title>Earlier Afghanistan &amp; Pakistan day</title><link>https://lanes.news/daily/afghanistan-pakistan/2026-10-06</link><pubDate>Tue, 06 Oct 2026 16:50:00 GMT</pubDate></item>
<item><title>Old item</title><link>https://lanes.news/daily/afghanistan-pakistan/2026-09-20</link><pubDate>Sun, 20 Sep 2026 10:00:00 GMT</pubDate></item>
<item><title>UN chief Guterres meets Pakistan army chief Munir in Rawalpindi</title><link>https://lanes.news/daily/india-pakistan/2026-10-07</link><pubDate>Wed, 07 Oct 2026 16:50:42 GMT</pubDate></item>
<item><title>Off-site link</title><link>https://evil.example/daily/usa-iran/2026-10-07</link><pubDate>Wed, 07 Oct 2026 10:00:00 GMT</pubDate></item>
<item><titlex>not a title</titlex><link>https://lanes.news/daily/usa-iran/2026-10-07</link></item>
</channel></rss>`;

const items = M.parseLanesRss(RSS);
ok(items.length === 4 && items[0].title.startsWith('Pakistan carries out') && items[0].conflict === 'afghanistan-pakistan' && items[0].day === '2026-10-07', 'RSS items with CDATA ' + JSON.stringify(items[0]));
ok(items[1].title === 'Earlier Afghanistan & Pakistan day', 'RSS entities decoded');
ok(!items.some((i) => /evil/.test(i.url)) && !items.some((i) => i.title === 'not a title'), 'off-site links and look-alike tags dropped');
ok(items[0].published === '2026-10-07T16:56:52.000Z', 'pubDate as ISO');

const L = M.lanesDoc(CSV, RSS, '2026-10-19T15:00:00Z');
ok(L.count === 8 && L.license === 'CC BY 4.0' && /GDELT/.test(L.credit), 'eight pairs with licence and credit');
ok(L.first_date === '2026-08-22' && L.latest_date === '2026-10-06' && L.upstream_age_days === 13, 'date range and upstream age ' + JSON.stringify([L.first_date, L.latest_date, L.upstream_age_days]));
const ru = L.rows.find((r) => r.conflict === 'russia-ukraine');
ok(ru.a2 === 'RU' && ru.b2 === 'UA' && ru.date === '2026-10-06' && ru.temperature === 0.7, 'latest day ' + JSON.stringify([ru.date, ru.temperature]));
// Later 7 days: i=6..0 -> i odd (5,3,1) 0.9 x 300, i even (6,4,2,0) 0.7 x 100: (3*270 + 4*70) / (900 + 400) = 1090/1300.
ok(ru.t7 === Math.round((1090 / 1300) * 1000) / 1000 && ru.t7_prev === 0.5 && ru.delta7 === Math.round((1090 / 1300 - 0.5) * 1000) / 1000 && ru.days7 === 7, 'article-weighted 7-day means ' + JSON.stringify([ru.t7, ru.t7_prev, ru.delta7, ru.days7]));
ok(ru.series.length === 14 && ru.series[13][0] === '2026-10-06' && ru.series.every((p) => p.length === 3), 'series as [date, temperature, articles]');
ok(ru.bridge_url === 'https://lanes.news/bridge/russia-ukraine', 'bridge link');
const ip = L.rows.find((r) => r.conflict === 'israel-palestine');
ok(ip && ip.b_name === 'Palestine, State of' && ip.b2 === 'PS' && ip.a2 === 'IL', 'quoted CSV fields and PSE');
const af = L.rows.find((r) => r.conflict === 'afghanistan-pakistan');
ok(af.daily_title.startsWith('Pakistan carries out') && af.daily_url === 'https://lanes.news/daily/afghanistan-pakistan/2026-10-07' && af.daily_7d === 2, 'latest daily item and 7-day count ' + af.daily_7d);
ok(af.t7 === 0.446 && af.t7_prev === null && af.delta7 === null, 'one day of data gives no change');
const uk = L.rows.find((r) => r.conflict === 'uk-argentina');
ok(uk.a2 === 'AR' && uk.b2 === 'GB' && uk.daily_title === '', 'pairs without a daily item');
ok(L.rows[0].conflict === 'russia-ukraine', 'hottest 7-day mean first');
ok(M.lanesDoc('', '', '2026-10-19T00:00:00Z').count === 0, 'empty input gives no rows');
let threw = '';
await M.fetchLanes(async () => ({ ok: false, status: 503, text: '' })).catch((e) => { threw = e.message; });
ok(threw === 'Lanes temperatures HTTP 503', 'Lanes outage throws ' + threw);
const f = await M.fetchLanes(async (u) => (u.endsWith('.csv') ? { ok: true, status: 200, text: CSV } : { ok: false, status: 404, text: '' }));
ok(f.count === 8 && f.rss_status === 404 && f.rows.every((r) => r.daily_title === ''), 'RSS failure keeps the temperatures');

// ---------------------------------------------------------------- OFAC
const ENTRIES = [
  ['20261019', 'Protecting American Intellectual Property Act of 2022 (PAIPA) Designations; Issuance of Associated General Licenses', 'October 19, 2026', 'sanctions-list-updates', 'Sanctions List Updates'],
  ['20261016', 'Issuance of Amended Venezuela-related General License and Frequently Asked Question', 'October 16, 2026', 'general-licenses', 'General Licenses'],
  ['20261015', 'Iran-related Designations; Cuba Designation; Issuance of New and Amended General Licenses and Frequently Asked Questions', 'October 15, 2026', 'sanctions-list-updates', 'Sanctions List Updates'],
  ['20261014', 'Venezuela-related Designation Removal', 'October 14, 2026', 'sanctions-list-updates', 'Sanctions List Updates'],
  ['20261013', 'Counter Narcotics and Counter Terrorism Designations', 'October 13, 2026', 'sanctions-list-updates', 'Sanctions List Updates'],
  ['20261013_33', "Settlement Agreement between the U.S. Department of the Treasury's Office of Foreign Assets Control and Bank of America, N.A.", 'October 13, 2026', 'enforcement-actions', 'Enforcement Actions'],
  ['20261009_33', 'Issuance of Russia-related General License', 'October 09, 2026', 'general-licenses', 'General Licenses'],
  ['20261008', 'Iran-related Designations; Issuance of Iran-related General License; Issuance of Amended Russia-related General License', 'October 08, 2026', 'sanctions-list-updates', 'Sanctions List Updates'],
];
const row = ([id, t, d, slug, cat], abs) => `<div class="views-row"><div class="margin-top-4"><a href="${abs ? 'https://ofac.treasury.gov' : ''}/recent-actions/${id}" hreflang="en">${t.replace(/&/g, '&amp;').replace(/'/g, '&#039;')}</a></div>
<div class="margin-top-1">${d} - <a href="/recent-actions/${slug}" hreflang="en">${cat}</a></div></div>`;
const SIDEBAR = '<nav><a href="/recent-actions/sanctions-list-updates">Sanctions List Updates</a><a href="/recent-actions/general-licenses">General Licenses</a></nav>';
const PAGE0 = `<html><body>${SIDEBAR}<p>Displaying 1 - 10 of 3177 results</p>${ENTRIES.slice(0, 5).map((e, i) => row(e, i === 1)).join('\n')}<a href="/recent-actions?page=1">Next</a></body></html>`;
const PAGE1 = `<html><body>${ENTRIES.slice(4).map((e) => row(e)).join('\n')}<footer><a href="/recent-actions/enforcement-actions">Enforcement</a></footer></body></html>`;

const list = M.parseOfacList(PAGE0);
ok(list.length === 5 && list[0].id === '20261019' && list[0].date === '2026-10-19' && list[0].category === 'Sanctions List Updates' && list[0].category_slug === 'sanctions-list-updates', 'entry with its category ' + JSON.stringify(list[0]));
ok(list[1].url === 'https://ofac.treasury.gov/recent-actions/20261016' && list[1].category_slug === 'general-licenses', 'absolute entry address');
ok(list.every((r) => r.category), 'sidebar links before the entries attach to nothing');
const O = M.ofacDoc([PAGE0, PAGE1], '2026-10-19T15:00:00Z');
ok(O.count === 8 && O.total_listed === 3177 && O.newest === '2026-10-19', 'two pages, duplicate dropped, total read ' + JSON.stringify([O.count, O.total_listed]));
const by = Object.fromEntries(O.rows.map((r) => [r.id, r]));
ok(by['20261013_33'].title.includes("Treasury's Office") && by['20261013_33'].actions === 'Enforcement' && by['20261013_33'].programs === '' && by['20261013_33'].theaters === '', 'enforcement action, entities decoded, no program');
ok(by['20261015'].programs === 'Iran; Cuba' && by['20261015'].theaters === 'T-HRM' && by['20261015'].actions === 'Designation; General license; FAQ', 'Iran and Cuba ' + JSON.stringify(by['20261015']));
ok(by['20261014'].actions === 'Designation removal' && by['20261014'].theaters === 'T-VEN', 'removal is not a designation');
ok(by['20261013'].programs === 'Counter Terrorism; Counter Narcotics' && by['20261013'].theaters === '', 'counter-narcotics alone maps to no theater');
ok(by['20261008'].theaters === 'T-HRM,T-UKR' && by['20261008'].programs === 'Iran; Russia', 'two programs, two theaters');
ok(by['20261019'].programs === 'PAIPA' && by['20261019'].actions === 'Designation; General license', 'PAIPA');
ok(O.rows.every((r, i) => !i || O.rows[i - 1].date >= r.date) && O.rows[4].id === '20261013_33' && O.rows[5].id === '20261013', 'newest first, same-day suffix first');
ok(by['20261013_33'].category === 'Enforcement Actions' && by['20261009_33'].category === 'General Licenses', 'each entry keeps its own category');
const tag = (t) => M.ofacTags(t);
ok(tag('Cyber-related Designations').cyber && tag('Cyber-related Designations').programs.join() === 'Cyber', 'cyber flag');
ok(tag('South Sudan-related Designations').programs.join() === 'South Sudan' && tag('Sudan-related Designations').theaters.join() === 'T-SDN', 'South Sudan is not Sudan');
ok(tag('Counter Terrorism Designations; Houthi-related').theaters.join() === 'T-RSY' && tag('North Korea-related Designations').theaters.join() === 'T-KOR', 'Houthi and DPRK');
ok(tag('Counter Narcotics Designations of Sinaloa Cartel members').theaters.join() === 'T-MEX', 'cartels map to the Mexico theater');
ok(tag('Counter Terrorism Designation Updates').actions.join() === 'Designation update', 'designation updates');
ok(M.ofacDoc(['<html>nothing</html>']).count === 0 && M.parseOfacList('<a href="/recent-actions/2026101">x</a><a href="javascript:x">y</a>').length === 0, 'no entries from junk');
threw = '';
await M.fetchOfac(async () => ({ ok: true, status: 200, text: '<html></html>' })).catch((e) => { threw = e.message; });
ok(threw === 'OFAC Recent Actions parsed to no entries', 'unparseable listing throws');
const seen = [];
const fo = await M.fetchOfac(async (u) => { seen.push(u); return u.endsWith('page=1') ? { ok: false, status: 403, text: '' } : { ok: true, status: 200, text: PAGE0 }; });
ok(fo.count === 5 && fo.pages_read === 1 && seen.join() === 'https://ofac.treasury.gov/recent-actions,https://ofac.treasury.gov/recent-actions?page=1', 'second page failure keeps the first');
ok(M.unent('&#x2019;&#8217;&rsquo;&bogus;') === String.fromCodePoint(0x2019, 0x2019) + "'&bogus;", 'entity decoding');
console.log(`PASS ${pass} checks`);
