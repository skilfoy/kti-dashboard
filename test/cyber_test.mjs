// Offline test of neon/parts/35-cyber.mjs, the country settlement for ransomware.live's press-reported cyberattacks.
// The fixture is the 100-row list read on 2026-10-19 (test/fixtures/rl_cyberattacks_20261019.json, compacted to
// [country, domain, article host, title, victim, date, added, claim_gang]); every miscoded row in it is asserted.
// node test/cyber_test.mjs <scratchpad>
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

const SCR = path.resolve(process.argv[2] || '.');
const M = await import(pathToFileURL(path.join(SCR, 'neon', 'parts', '35-cyber.mjs')).href);
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };

// Hosts.
for (const [h, want] of [['www.bbc.co.uk', 'GB'], ['southville.bristol.sch.uk', 'GB'], ['fjc.gov', 'US'], ['fmcsa.dot.gov', 'US'], ['army.mil', 'US'],
  ['zdrowit.pl', 'PL'], ['boryungbio.co.kr', 'KR'], ['venancioaires.rs.gov.br', 'BR'], ['iasd.cc', ''], ['startup.io', ''], ['lab.ai', ''], ['tv.tv', ''],
  ['europa.eu', ''], ['kremlin.su', ''], ['localhost', ''], ['', ''], ['example.com.', ''], ['ATB.UA', 'UA'], ['host.zz', '']]) {
  ok(M.ccOfHost(h) === want, `ccOfHost(${h}) = ${M.ccOfHost(h)}, want ${want}`);
}

// Abbreviations of English names.
for (const [code, cc, want] of [['DN', 'DK', true], ['KO', 'KR', true], ['UK', 'GB', true], ['SA', 'ZA', true], ['PO', 'PT', true], ['TU', 'TR', true],
  ['US', 'AE', false], ['IS', 'AT', false], ['JP', 'TW', false], ['DE', 'DK', true], ['BR', 'BO', false], ['us', 'US', true], ['U', 'US', false], ['', 'US', false]]) {
  ok(M.ccAbbrev(code, cc) === want, `ccAbbrev(${code}, ${cc}) want ${want}`);
}

// Settlement rules.
const P = (code, v, o, t) => M.placeCyberattack(code, v, o, t);
const eq = (got, cc, basis, m) => ok(got.cc === cc && got.basis === basis, `${m}: ${JSON.stringify(got)}`);
eq(P('PO', 'zdrowit.pl', 'cyberdefence24.pl', ''), 'PL', 'code+domain', 'alias confirmed by the victim domain');
eq(P('PO', 'firma.com', '', ''), 'PL', 'code-alias', 'alias without evidence');
eq(P('PO', 'cm-lisboa.pt', '', ''), 'PT', 'domain-abbrev', 'alias overridden by a domain it abbreviates');
eq(P('CH', 'fosko.cl', 'www.trendtic.cl', ''), 'CL', 'code+domain', 'colliding code settled by the domain');
eq(P('CH', 'srgssr.ch', '', ''), 'CH', 'code+domain', 'colliding code, ISO reading confirmed');
eq(P('UK', 'shop.com', 'www.bbc.co.uk', ''), 'GB', 'code+outlet', 'UK settled by a British outlet');
eq(P('IS', 'colmobil.at', 'www.calcalistech.com', 'Cyber incident disrupts operations at Israel’s largest car importer'), 'IL', 'code+title', 'headline names one reading');
eq(P('IS', 'x.com', '', 'Iceland and Israel both hit'), '', 'unresolved', 'headline naming both readings settles nothing');
eq(P('IR', 'mill.com', '', 'Northern Ireland plant hit'), '', 'unresolved', 'Northern Ireland is not Ireland');
eq(P('DE', 'firma.dk', '', ''), 'DK', 'domain-abbrev', 'valid code read as an abbreviation of the domain country');
eq(P('US', 'beyondgravity.de', '', ''), 'US', 'code', 'unrelated domain country leaves a valid code alone');
eq(P('US', 'acme.com', 'www.bluewin.ch', ''), 'US', 'code', 'an outlet never overrides a single reading');
eq(P('', 'gemeinde.de', '', ''), 'DE', 'domain', 'no code: the victim domain');
eq(P('SP', 'empresa.com', 'elpais.es', ''), 'ES', 'outlet-abbrev', 'unknown code read as an abbreviation of the outlet country');
eq(P('XX', 'acme.com', 'news.com', ''), '', 'unresolved', 'unknown code without evidence');
eq(P('BG', 'pathao.com', 'www.thedailystar.net', 'Pathao says cyber attack exposed users’ names'), '', 'unresolved', 'BG with no evidence: Bulgaria or Bangladesh');
ok(JSON.stringify(P('BG', 'pathao.com', '', '').candidates) === '["BG","BD"]', 'unresolved rows carry their candidates');
// AU also carries Austria (Loxone, coded AU in a collector copy of 2026-10-19).
eq(P('AU', 'loxone.com', 'borncity.com', 'Cyberangriff auf Loxone'), '', 'unresolved', 'AU with no evidence: Australia or Austria');
ok(JSON.stringify(P('AU', 'loxone.com', 'borncity.com', '').candidates) === '["AU","AT"]', 'AU candidates are Australia and Austria');
eq(P('AU', 'firma.at', '', ''), 'AT', 'code+domain', 'AU settled as Austria by the victim domain');
eq(P('AU', 'mandurahses.org.au', 'www.cyberdaily.au', ''), 'AU', 'code+domain', 'AU confirmed as Australia by the victim domain');
eq(P('AU', 'acme.com', 'www.derstandard.at', ''), 'AT', 'code+outlet', 'AU settled as Austria by an Austrian outlet');
eq(P('AU', 'acme.com', 'www.abc.net.au', ''), 'AU', 'code+outlet', 'AU settled as Australia by an Australian outlet');
eq(P('AU', 'acme.com', '', 'Australian logistics firm hit by ransomware'), 'AU', 'code+title', 'headline names Australia');
eq(P('AU', 'acme.com', '', 'Cyberangriff auf Unternehmen in Oesterreich'), 'AT', 'code+title', 'German headline names Austria');
eq(P('AU', 'acme.com', '', 'Austrian and Australian units hit'), '', 'unresolved', 'headline naming both readings settles nothing');

// The 2026-10-19 sample.
const fx = JSON.parse(fs.readFileSync(path.join(SCR, 'test', 'fixtures', 'rl_cyberattacks_20261019.json'), 'utf8'));
const arr = fx.map(([country, domain, host, title, victim, date, added, gang]) => ({ added, claim_gang: gang || false, claim_url: false, country, date, description: '',
  domain, has_infostealer_info: true, infostealer_data: { employees: 3, thirdparties: 243 }, link: 'https://www.ransomware.live/id/' + Buffer.from(domain + '@' + date).toString('base64'),
  summary: 'résumé', title, url: host ? `https://${host}/article` : '', victim }));
const doc = M.cyberattackDoc(arr, '2026-10-19T00:00:00Z');
ok(doc.count === 99 && doc.placed === 98 && doc.unplaced === 1 && doc.recoded === 10, 'sample totals ' + JSON.stringify({ c: doc.count, p: doc.placed, u: doc.unplaced, r: doc.recoded }));
ok(JSON.stringify(doc.by_basis) === JSON.stringify({ 'code+domain': 55, code: 41, 'code+title': 1, 'code-alias': 1, unresolved: 1 }), 'sample bases ' + JSON.stringify(doc.by_basis));
const want = { 'Zdrowit S.A.': 'PL', 'Boryung Biopharma': 'KR', 'Svedala kommun': 'SE', 'Yıldız Teknik Üniversitesi': 'TR', 'Femern Link Contractors (FLC)': 'DK',
  ATB: 'UA', 'Fosko S.A.': 'CL', 'Corby Rock Mill': 'IE', Colmobil: 'IL', "Municipalité d'Ovar": 'PT' };
for (const [v, cc] of Object.entries(want)) ok(doc.rows.find((r) => r.victim === v).cc === cc, `${v} placed in ${cc}`);
ok(doc.rows.filter((r) => r.cc && !(r.victim in want)).every((r) => r.cc === r.cc_feed), 'every other placed row keeps its feed code');
const pathao = doc.rows.find((r) => r.victim === 'Pathao');
ok(pathao.cc === '' && pathao.cc_basis === 'unresolved' && pathao.cc_candidates.join() === 'BG,BD' && pathao.cc_feed === 'BG', 'Pathao unplaced with both readings');
ok(doc.rows.every((r, i) => !i || doc.rows[i - 1].added >= r.added), 'newest addition first');
ok(doc.rows.filter((r) => r.victim === 'Genesis Healthcare Management').length === 1 && arr.length - doc.count === 1, 'the exact duplicate is dropped');
const text = JSON.stringify(doc);
ok(!/infostealer|thirdparties|résumé|"domain"|"summary"|"description"/.test(text), 'domains, summaries and infostealer counts are dropped');
ok(doc.rows.every((r) => /^https?:\/\//.test(r.url) && r.outlet && !r.outlet.startsWith('www.') && /^https:\/\/www\.ransomware\.live\/id\//.test(r.link)), 'article and record links kept');
ok(doc.rows.find((r) => r.victim === 'Astrana').claimed_by === 'chaos' && doc.rows.find((r) => r.victim === 'Zdrowit S.A.').claimed_by === '', 'leak-site claim kept as the group name');

// Hostile input.
const bad = M.normalizeCyberattacks([null, 7, 'x', { url: 'javascript:alert(1)', link: 'https://evil.example/id/x', victim: ' A\n B ', country: 'de', domain: 'a.de', date: 'garbage', added: '2026-10-18T10:00:00' }]);
ok(bad.length === 1 && bad[0].url === '' && bad[0].outlet === '' && bad[0].link === '' && bad[0].victim === 'A B' && bad[0].cc === 'DE' && bad[0].date === '' && bad[0].added === '2026-10-18', 'hostile row ' + JSON.stringify(bad[0]));
ok(M.normalizeCyberattacks({ not: 'an array' }).length === 0, 'non-array input gives no rows');
console.log(`PASS ${pass} checks`);
