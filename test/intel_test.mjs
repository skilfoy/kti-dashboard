// Offline tests for neon/parts/37-intel.mjs, 38-lists.mjs and 39-enrich.mjs and the new schedule and health rows.
// Run from the working root: node test/intel_test.mjs .
// Fixtures marked REAL are read from the cloned repositories under /home/claude/skilfoy when present (ThreatCluster
// victims.json from Jam0k/Ransomware-Intel, a Unit 42 note, the awesome_threat_intel_blogs README); the rest are
// synthetic in the shape each source served when probed on 22 October 2026 (FIRMS area CSV header, MARAD advisory table, Lanes CSV headers, OFAC action page entries,
// Spamhaus DROP NDJSON, IPsum, Ransomwhere export, Lanes CSVs, RSS and Atom).
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const SCR = path.resolve(process.argv[2] || '.');
const M = await import(pathToFileURL(path.join(SCR, 'neon', 'collector.mjs')).href);
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };
const CLONES = process.env.TI_CLONES || path.join(SCR, '.clones');  // optional real-data checks run when the source repositories are cloned here
const has = (p) => fs.existsSync(path.join(CLONES, p));

// ---------------------------------------------------------------- FIRMS
const CSV = ['latitude,longitude,bright_ti4,scan,track,acq_date,acq_time,satellite,instrument,confidence,version,bright_ti5,frp,daynight',
  '48.512,37.991,355.1,0.4,0.4,2026-10-21,0112,N20,VIIRS,h,2.0NRT,290.1,41.2,N',
  '48.513,37.995,331.0,0.4,0.4,2026-10-21,0112,N20,VIIRS,n,2.0NRT,288.0,5.5,N',
  '50.001,36.201,330.2,0.4,0.4,2026-10-21,1048,N20,VIIRS,l,2.0NRT,289.0,2.1,D',
  'bad,row'].join(String.fromCharCode(13) + '\n');
const f = M.parseFirmsCsv(CSV);
ok(f.ok && f.rows.length === 3, 'FIRMS CSV: three valid rows, CRLF tolerated');
ok(f.rows[0].conf === 'h' && f.rows[0].frp === 41.2 && f.rows[0].at === '2026-10-21T01:12:00Z', 'FIRMS row fields and time');
ok(!M.parseFirmsCsv('Invalid MAP_KEY.').ok, 'FIRMS error text is not a CSV');
ok(M.firmsCell(48.512, 37.991) === '485:379' && M.firmsCell(-0.05, -12.31) === '-1:-124', 'FIRMS 0.1-degree cells, negative coordinates floor');
const now = Date.parse('2026-10-22T03:00:00Z');
const aoi = M.FIRMS_AOI.find((a) => a.id === 'T-UKR');
const pts = f.rows.map((p) => ({ ...p, cc: 'UA', cell: M.firmsCell(p.lat, p.lon) }));
const doc = M.firmsDoc({ per: [{ aoi, ok: true, source: 'VIIRS_NOAA20_NRT', pts }, { aoi: M.FIRMS_AOI[1], ok: false, error: 'HTTP 500', pts: [] }],
  prior: [{ aoi: 'T-UKR', cell: '485:379' }], series: [{ aoi: 'T-UKR', d: '2026-10-10', n: 10 }, { aoi: 'T-UKR', d: '2026-10-11', n: 30 }, { aoi: 'T-UKR', d: '2026-10-21', n: 60 }],
  firstDay: { 'T-UKR': '2026-10-01' }, now });
const u = doc.aois.find((a) => a.id === 'T-UKR');
ok(u.detections === 3 && u.high === 1 && u.cells === 2, 'FIRMS AOI counts');
ok(u.novel_cells === 1 && u.novel_detections === 1, 'novel: the cell absent from the prior 30 days, not the one seen before');
ok(u.median_daily === 20 && u.yesterday === 60 && u.ratio === 3, 'yesterday against the median of earlier days');
ok(doc.aois[1].ok === false && doc.aois[1].error === 'HTTP 500', 'a failed area is reported, not dropped');
ok(doc.rows.filter((r) => r.novel).length === 1 && doc.rows.every((r) => r.kind === 'fire'), 'fire rows carry the novel flag');
const young = M.firmsDoc({ per: [{ aoi, ok: true, pts: pts.map((p) => ({ ...p })) }], prior: [], series: [], firstDay: { 'T-UKR': '2026-10-20' }, now });
ok(young.aois[0].novelty_judged === false && young.aois[0].novel_cells === 0, 'novelty withheld until 7 days of cells exist');
ok(/acknowledge/.test(doc.credit) && /many causes/.test(doc.method), 'FIRMS credit line and cause caveat');

// ---------------------------------------------------------------- maritime (MARAD table rows as listed 22 October 2026)
const MARAD = `<table><thead><tr><th>Title</th><th>Status</th><th>Effective Date</th><th>Expire Date</th></tr></thead><tbody>
<tr><td><a href="/msci/2026-013-red-sea-bab-el-mandeb-strait-gulf-aden-arabian-sea-and-somali-basin-houthi-attacks">2026-013-Red Sea, Bab el Mandeb Strait, Gulf of Aden, Arabian Sea, and Somali Basin-Houthi Attacks on Commercial Vessels</a></td><td>Active</td><td>09/23/2026</td><td>03/22/2027</td></tr>
<tr><td><a href="https://www.maritime.dot.gov/msci/2026-012-black-sea-and-sea-azov-military-combat-operations">2026-012-Black Sea and Sea of Azov-Military Combat Operations</a></td><td>Active</td><td>09/23/2026</td><td>03/22/2027</td></tr>
<tr><td><a href="/msci/2026-010-gulf-aden-arabian-sea-indian-ocean-piracyarmed-robberykidnapping-ransom">2026-010-Gulf of Aden, Arabian Sea, Indian Ocean-Piracy/Armed Robbery/Kidnapping for Ransom</a></td><td>Active</td><td>08/07/2026</td><td>02/04/2027</td></tr>
<tr><td><a href="/msci/2026-007-worldwide-worldwide-foreign-adversarial">2026-007-Worldwide-Worldwide-Foreign Adversarial Technological, Physical, and Cyber Influence</a></td><td>Active</td><td>04/24/2026</td><td>10/21/2026</td></tr>
<tr><td><a href="/msci/2026-006-red-sea">2026-006-Red Sea, Bab el Mandeb Strait-Houthi Attacks on Commercial Vessels</a></td><td>Cancelled</td><td>03/26/2026</td><td>09/22/2026</td></tr></tbody></table>`;
const mr = M.parseMarad(MARAD, Date.parse('2026-10-22T03:00:00Z'));
ok(mr.length === 5 && mr[0].id === '2026-013' && mr[0].theater === 'T-RSY' && mr[0].in_force && mr[0].url === 'https://www.maritime.dot.gov/msci/2026-013-red-sea-bab-el-mandeb-strait-gulf-aden-arabian-sea-and-somali-basin-houthi-attacks', 'MARAD advisory row, theater and absolute link');
ok(mr[0].region.startsWith('Red Sea, Bab el Mandeb') && mr[0].threat === 'Houthi Attacks on Commercial Vessels' && mr[0].effective === '2026-09-23' && mr[0].expires === '2027-03-22', 'MARAD region, threat and dates');
ok(mr[1].theater === 'T-UKR' && mr[2].theater === 'T-HOA' && mr[2].threat === 'Piracy/Armed Robbery/Kidnapping for Ransom', 'Black Sea and Gulf of Aden piracy theaters');
ok(mr[3].region === 'Worldwide' && /^Foreign Adversarial/.test(mr[3].threat) && mr[3].lapsed && !mr[3].in_force, 'repeated region stripped; active past expiry is lapsed');
ok(mr[4].status === 'cancelled' && !mr[4].in_force, 'cancelled advisory');
const as = M.parseAsam({ asam: [{ reference: '2026-155', date: '2026-10-12', latitude: 12.9, longitude: 43.4, navArea: 'IX', subreg: '62', hostility: 'Unknown', victim: 'Bulk carrier', description: 'Vessel reported a suspicious approach by a skiff.' },
  { reference: '2026-150', date: '2026-09-01', latitude: 3.1, longitude: 105.5, navArea: 'XI', subreg: '71', hostility: 'Robbers', victim: 'Tanker', description: 'Robbers boarded.' }] });
ok(as.length === 2 && as[0].theater === 'T-RSY' && as[1].theater === 'T-SCS' && as[0].lat === 12.9, 'ASAM records placed in theaters by position');
const nw = M.parseNavwarn({ 'broadcast-warn': [{ msgYear: 2026, msgNumber: 812, navArea: '4', text: 'EASTERN MEDITERRANEAN. GPS SIGNALS UNRELIABLE DUE TO INTERFERENCE.', issueDate: '211200Z OCT 2026' },
  { msgYear: 2026, msgNumber: 813, navArea: '4', text: 'HAZARDOUS OPERATIONS, ROCKET LAUNCHING.' }] });
ok(nw.total === 2 && nw.gnss === 1 && nw.by_area['4'] === 1 && nw.rows[0].id === '812/2026', 'NGA warnings: GNSS interference counted');
ok(nw.by_category.gnss === 1 && nw.by_category.military === 1 && nw.rows[1].category === 'military' && nw.rows[0].kind === 'navwarn', 'NGA warnings sorted into categories');
// Positions as NGA writes them (HYDROPAC and NAVAREA IV texts of October 2026 use this form).
const pos = M.navPositions('AREA BOUNDED BY 24-30.0N 118-10.0E, 24-30.0N 119-00.0E, 23-50.0N 119-00.0E. ALSO 35-10-30N 129-05-00E.');
ok(pos.length === 4 && pos[0][0] === 24.5 && Math.abs(pos[0][1] - 118.167) < 0.001 && Math.abs(pos[3][0] - 35.175) < 0.001, 'NGA positions parsed, with seconds');
const np = M.navPoint(pos.slice(0, 3)), sp = M.navPoint(pos);
ok(Math.abs(np.lat - 24.278) < 0.002 && np.spread === false && sp.spread === true && sp.lat === 24.5, 'a compact area is averaged; scattered places keep the first');
const nw2 = M.parseNavwarn({ 'broadcast-warn': [
  { msgYear: 2026, msgNumber: 1101, navArea: 'P', text: 'TAIWAN STRAIT. LIVE FIRING EXERCISES 220000Z TO 232359Z OCT IN AREA BOUNDED BY 24-30.0N 118-10.0E, 24-30.0N 119-00.0E, 23-50.0N 119-00.0E, 23-50.0N 118-10.0E.' },
  { msgYear: 2026, msgNumber: 1102, navArea: 'P', text: 'RED SEA. VESSEL REPORTED ATTACKED BY PROJECTILE IN 13-30.0N 042-50.0E.' },
  { msgYear: 2026, msgNumber: 1103, navArea: 'A', text: 'BALTIC SEA. GNSS JAMMING REPORTED IN VICINITY 55-30.0N 019-00.0E.' },
  { msgYear: 2026, msgNumber: 1104, navArea: '4', text: 'GULF OF MEXICO. DRILLING RIG POSITIONS 27-10.4N 090-22.1W.' }] });
ok(nw2.by_category.military === 1 && nw2.by_category.hostile === 1 && nw2.by_category.gnss === 1 && nw2.by_category.other === 1 && nw2.rows.length === 3, 'other notices counted, not listed');
ok(nw2.rows[0].theater === 'T-TWN' && nw2.rows[1].theater === 'T-RSY' && nw2.rows[2].theater === 'T-EUH' && nw2.rows[0].area_label === 'HYDROPAC', 'warnings placed in theaters by their positions');
ok(nw2.by_theater['T-RSY'].hostile === 1 && nw2.by_theater['T-TWN'].military === 1, 'warning counts by theater');
ok(M.ngaDtg('101515Z MAY 2024') === '2024-05-10T15:15:00Z' && M.ngaDtg('nonsense') === null, 'NGA date-time groups read');
ok(M.ngaDtg('181530Z NOV 26') === '2026-11-18T15:30:00Z' && M.ngaDtg('181530Z NOV 2026.') === '2026-11-18T15:30:00Z', 'two-digit years of the daily memoranda read');
// The daily memorandum as plain text (NGA's layout: date-time group, then area, number and year, then the warning).
const dm = M.parseDailyMem('181530Z NOV 26\nHYDROPAC 3456/26(11).\nRED SEA.\n1. VESSEL REPORTED ATTACKED BY PROJECTILE IN 13-30.0N 042-50.0E.\n\n'
  + 'NAVAREA IV 1201/2026(GEN).\nGULF OF MEXICO.\n1. DRILLING RIG IN 27-10.4N 090-22.1W.\n(171200Z NOV 26)\n', 'P');
ok(dm.length === 2 && dm[0].navArea === 'P' && dm[0].msgNumber === 3456 && dm[0].msgYear === 2026 && dm[0].issueDate === '181530Z NOV 26' && dm[1].navArea === '4' && dm[1].issueDate === '171200Z NOV 26', 'daily memorandum split into warnings ' + JSON.stringify(dm));
const dmn = M.parseNavwarn(dm);
ok(dmn.total === 2 && dmn.rows.length === 1 && dmn.rows[0].theater === 'T-RSY' && dmn.rows[0].id === '3456/2026' && dmn.newest === '2026-11-18T15:30:00Z', 'memorandum warnings read like the API\'s');
ok(M.parseDailyMem('<!DOCTYPE html><html><body>MSI IS CURRENTLY UNDER MAINTENANCE</body></html>') === null && M.parseDailyMem('') === null && M.parseDailyMem('NO WARNINGS IN FORCE.').length === 0, 'a maintenance page is not a memorandum');
ok(M.parseNavwarn({ 'broadcast-warn': [{ msgYear: 2024, msgNumber: 1, text: 'GNSS JAMMING.', issueDate: '101515Z MAY 2024' }, { msgYear: 2024, msgNumber: 2, text: 'X', issueDate: '021141Z JUN 2024' }] }).newest === '2024-06-02T11:41:00Z', 'newest warning found for the staleness check');
ok(M.seaBox(26.5, 50.5) === 'T-HRM' && M.seaBox(12.6, 43.3) === 'T-RSY', 'the Gulf is Hormuz; Bab el Mandeb is the Red Sea');
const md = M.maritimeDoc({ marad: mr, asam: as, navwarn: nw, ukmto: [], status: [], now: Date.parse('2026-10-22T03:00:00Z') });
ok(md.advisories_in_force === 3 && md.by_theater['T-RSY'].advisories === 1 && md.by_theater['T-RSY'].incidents_30d === 1 && md.gnss.gnss === 1, 'maritime document by theater');
const md2 = M.maritimeDoc({ marad: mr, asam: as, navwarn: nw2, ukmto: [], status: [], now: Date.parse('2026-10-22T03:00:00Z') });
ok(md2.by_theater['T-RSY'].warn_hostile === 1 && md2.by_theater['T-RSY'].advisories === 1 && md2.by_theater['T-TWN'].warnings === 1 && md2.navwarn.by_category.other === 1
  && md2.navwarn.positioned === 3 && md2.rows.filter((r) => r.kind === 'navwarn')[0].category === 'hostile', 'warnings in the maritime document, hostile first');
const uk = M.parseUkmto([{ incidentNumber: '042-26', title: 'Suspicious approach', type: 'Suspicious Activity', incidentDate: '2026-10-20T08:00:00Z', locationLatitude: 13.1, locationLongitude: 43.2, slug: '042-26' }]);
ok(uk.length === 1 && uk[0].lat === 13.1 && uk[0].id === '042-26' && /recent-incidents\/042-26$/.test(uk[0].url), 'UKMTO array shape');
ok(M.parseUkmto({ nothing: true }).length === 0, 'UKMTO unknown shape parses to nothing');

// ---------------------------------------------------------------- abuse.ch: retired exports, authenticated API shapes
// Parsers drop documentation ranges, so these use addresses from ThreatCluster's public IOC feed of 22 October 2026.
const tfApi = M.parseThreatFox({ query_status: 'ok', data: [{ id: '1600001', ioc: '96.62.218.59:8443', ioc_type: 'ip:port', threat_type: 'botnet_cc', malware_printable: 'Cobalt Strike', confidence_level: 100, first_seen: '2026-10-21 10:00:00 UTC', tags: ['cs'] },
  { id: '1600002', ioc: 'evil.example', ioc_type: 'domain' }] });
ok(tfApi.length === 1 && tfApi[0].port === 8443 && tfApi[0].first_seen === '2026-10-21T10:00:00.000Z' && /ioc\/1600001\//.test(tfApi[0].ref), 'ThreatFox API shape');
const uhApi = M.parseUrlhausApi({ query_status: 'ok', urls: [{ id: '3300001', url: 'http://2.27.248.127:8080/bin.sh', url_status: 'online', date_added: '2026-10-21 09:00:00 UTC', threat: 'malware_download', tags: ['mirai', 'elf'], urlhaus_reference: 'https://urlhaus.abuse.ch/url/3300001/' },
  { id: '3300002', url: 'http://79.130.26.202/x', url_status: 'offline', date_added: '2026-10-21 09:00:00 UTC' }, { id: '3300003', url: 'http://host.example/x', url_status: 'online' }] });
ok(uhApi.length === 1 && uhApi[0].ip === '2.27.248.127' && uhApi[0].family === 'Mirai' && uhApi[0].port === 8080, 'URLhaus API shape: online IPv4 hosts only');
ok(/21 October 2026/.test(M.ABUSE_GATE) && /Auth-Key/.test(M.ABUSE_GATE), 'abuse.ch gate explains the change');

// ---------------------------------------------------------------- ThreatCluster cross-check
ok(M.tcNormName('ACME Holdings, Inc.') === M.tcNormName('acme') && M.tcNormName('Brutra Logistiek B.V.') === 'brutralogistiek', 'organisation names drop legal suffixes');
ok(M.tcNormGroup('Lynx Ransomware') === 'lynx' && M.tcNormGroup('INC Ransom') === 'inc', 'group names normalized');
let tc = [
  { group: 'qilin', victim: 'Alpha Freight Ltd', discovered: '2026-10-20T09:00:00+00:00', status: 'listed', first_party: true, website: 'alphafreight.com' },
  { group: 'qilin', victim: 'Beta Clinic', discovered: '2026-10-20T10:00:00+00:00', status: 'delisted', first_party: true },
  { group: 'akira', victim: 'Gamma Tools GmbH', discovered: '2026-10-19T10:00:00+00:00', status: 'listed', first_party: false },
  { group: 'akira', victim: 'Old Claim', discovered: '2026-09-25T10:00:00+00:00', status: 'listed', first_party: true },
];
const rl = [
  { group_name: 'qilin', post_title: 'Alpha Freight', discovered: '2026-10-20 08:59:00', website: 'www.alphafreight.com' },
  { group_name: 'akira', post_title: 'Gamma Tools', discovered: '2026-10-19 11:00:00' },
  { group_name: 'play', post_title: 'Delta Co', discovered: '2026-10-21 01:00:00' },
];
const x = M.leakCrossCheck(tc, rl, [{ group: 'qilin', active: 'yes', mirrors_up: '1', last_seen: '2026-10-20' }]);
const q = x.rows.find((r) => r.group === 'qilin'), ak = x.rows.find((r) => r.group === 'akira'), pl = x.rows.find((r) => r.group === 'play');
ok(q.both === 1 && q.tc_only === 1 && q.tc_delisted_30d === 1 && q.active === true && q.mirrors_up === 1, 'qilin: one corroborated, one single-source and delisted');
ok(ak.both === 1 && ak.tc_30d === 2 && ak.tc_window === 1, 'akira: claim outside the window counts in 30 days only');
ok(pl.rl_only === 1 && pl.corroboration === 0, 'play: ransomware.live only');
ok(x.totals.both === 2 && !JSON.stringify(x).includes('Alpha Freight'), 'totals, and no victim names in the output');
ok(q.both_first_party === 1 && q.corroboration_first_party === 100 && ak.both_first_party === 0 && ak.corroboration === 100 && ak.corroboration_first_party === 0 && x.totals.both_first_party === 1,
  'only a first-party ThreatCluster row counts as independent corroboration');
// With two ThreatCluster rows for one claim, the first-party row is matched.
const x2 = M.leakCrossCheck([{ ...tc[2], victim: 'Gamma Tools', first_party: false }, { ...tc[2], first_party: true }], [rl[1]], []);
ok(x2.rows[0].both_first_party === 1, 'a first-party row is preferred when both match');
if (has('ransomware-intel/data/victims.json')) {
  const real = JSON.parse(fs.readFileSync(path.join(CLONES, 'ransomware-intel/data/victims.json'), 'utf8'));
  const rx = M.leakCrossCheck(real.victims, [], []);
  ok(rx.rows.length > 20 && rx.totals.tc_30d === real.victims.length, 'REAL ThreatCluster victims.json: every row counted by group');
}

// ---------------------------------------------------------------- Ransomwhere
const ra = M.ransomAgg([{ family: 'Netwalker (Mailto)', blockchain: 'bitcoin', transactions: [{ time: 1590166805, amountUSD: 609724.09 }, { time: 1590164903, amountUSD: 1.01 }] },
  { family: 'Qlocker', blockchain: 'bitcoin', transactions: [{ time: Math.floor(now / 1000) - 10 * 86400, amountUSD: 500 }] }, { family: '', transactions: [] }], now);
ok(ra.rows[0].family === 'Netwalker (Mailto)' && ra.rows[0].usd === 609725 && ra.rows[0].first === '2020-05-22', 'Ransomwhere family totals and first date');
ok(ra.rows.find((r) => r.family === 'Qlocker').usd_90d === 500 && ra.rows.find((r) => r.family === 'Unknown').addresses === 1, 'recent window, unknown family kept');
ok(!JSON.stringify(ra).includes('address":"'), 'no addresses in the aggregate');

// ---------------------------------------------------------------- Unit 42
const note = ['2026-10-16 (Friday): Coruna-like Exploit Kit Activity', '', 'NOTES:', '', '- text with example[.]com in a note', '', 'INDICATORS:', '',
  '- 8itk5k-3n302ot5eo[.]store', '- static.flyfun[.]cc', '- 203.0.113[.]10:443', '- hxxps[:]//bad[.]example/path', '- SHA256 hash: ' + 'a'.repeat(64), '',
  'REFERENCES:', '', '- https://example.com/report'].join('\n');
const pu = M.parseU42(note, '2026-10-16-Coruna.txt');
ok(pu.date === '2026-10-16' && pu.title === 'Coruna-like Exploit Kit Activity', 'Unit 42 date and title');
ok(pu.counts.domain === 2 && pu.counts.ip === 1 && pu.counts.url === 1 && pu.counts.sha256 === 1 && pu.references === 1, 'Unit 42 counts from the indicator section only');
if (has('unit42-timely-threat-intel')) {
  const dir = path.join(CLONES, 'unit42-timely-threat-intel');
  const name = fs.readdirSync(dir).filter((n) => /^2026-.*\.txt$/.test(n)).sort().pop();
  const r = M.parseU42(fs.readFileSync(path.join(dir, name), 'utf8'), name);
  ok(r.date === name.slice(0, 10) && r.title.length > 5 && Object.values(r.counts).reduce((a, b) => a + b, 0) > 0, 'REAL newest Unit 42 note parses with indicators');
}

// ---------------------------------------------------------------- Gen Threat Labs
const fams = M.genFamilies([{ path: 'Chaes', type: 'tree' }, { path: 'Chaes/samples.sha256', type: 'blob', size: 650 }, { path: 'Chaes/network.txt', type: 'blob', size: 80 },
  { path: 'CobaltStrike/yara_rules/cs.yar', type: 'blob', size: 900 }, { path: '.github/x', type: 'blob' }, { path: 'README.md', type: 'blob' }]);
const ch = fams.find((x) => x.family === 'Chaes');
ok(fams.length === 2 && ch.hash_files.length === 1 && ch.network_files.length === 1 && fams.find((x) => x.family === 'CobaltStrike').yara === 1, 'Gen families, files by kind');
ok(M.countLines('# c\nF20D0FFD1164026E1BE61D19459E7B17FF420676D4C8083DD41BA5D04B97A08C\nnot\n', 'sha256') === 1 && M.countLines('a[.]b\n\n# x\nc[.]d\n', 'any') === 2, 'hash and network line counts');
ok(M.genKey('Cobalt Strike') === M.genKey('CobaltStrike'), 'family keys ignore case and spacing');

// ---------------------------------------------------------------- Lanes registry (headers as served on 22 October 2026)
const CRLF = String.fromCharCode(13) + '\n';
const ld = M.lanesRegistryDoc(['id,name,country,country_name,language,funding,ownership_note,homepage,feed,lanes',
  'aljazeera,Al Jazeera English,QAT,Qatar,en,state,Funded by the Qatari state,https://www.aljazeera.com,https://www.aljazeera.com/xml/rss/all.xml,"russia-ukraine:n (Third-party press); israel-palestine:b (Palestinian, Arab & Muslim-world press)"', ''].join(CRLF),
  ['date,conflict,refers_to,wording_side_a,wording_side_b,lane,lane_label,uses_side_a_wording,uses_side_b_wording,english_words_counted,articles_not_counted_non_english',
    "2026-10-20,china-taiwan,Taiwan's status,Taiwan / the country / the nation,Taiwan region / China's Taiwan / the island,a,Taiwanese press,18,0,472,0",
    "2026-10-20,china-taiwan,Taiwan's status,Taiwan / the country / the nation,Taiwan region / China's Taiwan / the island,b,Chinese state-aligned press,4,1,364,0",
    "2026-10-21,china-taiwan,Taiwan's status,Taiwan / the country / the nation,Taiwan region / China's Taiwan / the island,b,Chinese state-aligned press,2,3,300,0",
    '2026-08-01,china-taiwan,old,x,y,a,Taiwanese press,1,1,1,0', ''].join(CRLF), now);
ok(ld.outlets === 1 && ld.rows[0].name === 'Al Jazeera English' && ld.rows[0].funding === 'state' && ld.rows[0].ownership === 'Funded by the Qatari state' && ld.rows[0].country_name === 'Qatar' && /israel-palestine:b/.test(ld.rows[0].lanes), 'Lanes outlets with real headers');
const nms = ld.rows.filter((r) => r.kind === 'naming'), nb = nms.find((r) => r.lane === 'b');
ok(nms.length === 2 && nb.days === 2 && nb.uses_a === 6 && nb.uses_b === 4 && nb.words === 664 && nb.lane_label === 'Chinese state-aligned press' && nb.side_b.startsWith('Taiwan region'), 'Lanes naming summed per lane over 14 days');

// ---------------------------------------------------------------- blogs
ok(JSON.stringify(M.discoverFeed('<html><link rel="alternate" type="application/rss+xml" href="/feed/"><link rel="alternate" type="application/rss+xml" href="/comments/feed/"></html>', 'https://blog.example.com/'))
  === JSON.stringify(['https://blog.example.com/feed/']), 'feed discovery from the home page, comment feeds skipped');
const rss = '<?xml version="1.0"?><rss><channel><item><title><![CDATA[New loader &amp; C2]]></title><link>https://blog.example.com/a</link><pubDate>Tue, 20 Oct 2026 10:00:00 GMT</pubDate></item></channel></rss>';
const atom = '<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Atom post</title><link rel="alternate" href="https://x.example/p"/><updated>2026-10-21T00:00:00Z</updated></entry></feed>';
const ri = M.parseFeedItems(rss), ai = M.parseFeedItems(atom);
ok(ri.length === 1 && ri[0].title === 'New loader & C2' && ri[0].published === '2026-10-20T10:00:00.000Z', 'RSS items');
ok(ai.length === 1 && ai[0].link === 'https://x.example/p', 'Atom items');
ok(M.parseFeedItems('<html>nope</html>') === null, 'HTML is not a feed');
ok(M.feedTag('<a><b x="1">in</b></a>', 'b') === 'in' && M.feedTag('<bb>no</bb>', 'b') === '', 'feedTag matches whole element names');
if (has('awesome_threat_intel_blogs/README.md')) {
  const bl = M.parseBlogsReadme(fs.readFileSync(path.join(CLONES, 'awesome_threat_intel_blogs/README.md'), 'utf8'));
  ok(bl.length > 150 && bl.every((b) => /^https?:/.test(b.url) && b.type), 'REAL blog list parses (' + bl.length + ' blogs)');
}

// ---------------------------------------------------------------- link health
ok(M.linkStatus({ status: 200, final: 'https://www.example.com/x' }, 'https://example.com/x').status === 'ok', 'same-site redirect is ok');
ok(M.linkStatus({ status: 200, final: 'https://parked.example.net/' }, 'https://example.com/x').status === 'review', 'off-site redirect needs review');
ok(M.linkStatus({ status: 403 }, 'https://example.com').status === 'blocked' && M.linkStatus({ status: 404 }, 'https://example.com').status === 'review'
  && M.linkStatus({ status: 0, error: 'timeout' }, 'https://example.com').why === 'timeout', 'blocked, missing and timeout');

// ---------------------------------------------------------------- OFAC action pages
const page = `<h2>Specially Designated Nationals List</h2><p>The following individuals have been added to OFAC's SDN List:</p>
<p>ABDOLALIPUR, Azadeh, Iran; DOB 11 Sep 1988; POB Shiraz, Iran; nationality Iran; Gender Female (individual) [IRAN-EO13902] (Linked To: FARAB SOROUSH AFAGH QESHM COMPANY).</p>
<p>The following entities have been added to OFAC's SDN List:</p>
<p>ADRIAN SEA (a.k.a. ADRIAN) Crude Oil Tanker 159,000 DWT 81,000 GRT Panama flag; Vessel Year of Build 2004; Vessel Flag Panama; Vessel Registration Identification IMO 9283760; MMSI 352001162 (vessel) [IRAN-EO13846] (Linked To: X TRADING LTD).</p>
<p>SHADOW NET LLC, Moscow, Russia; Organization Type: Computer programming [CYBER2] [RUSSIA-EO14024].</p>
<p>The following individuals have been removed from OFAC's SDN List:</p>
<p>OLD, Person (individual) [SDGT].</p>
<p>Unrelated Administrative List Changes:</p><p>SOMEONE (individual) [IRAQ2].</p>`;
const ent = M.parseOfacAction(page);
const sum = M.ofacSummary(ent);
ok(ent.length === 4 && ent[0].name === 'ABDOLALIPUR, Azadeh' && ent[0].kind === 'individual', 'OFAC entries: administrative changes skipped, individual names kept whole');
ok(sum.added === 3 && sum.removed === 1 && sum.vessels.length === 1 && sum.vessels[0].imo === '9283760' && sum.vessels[0].flag === 'Panama' && sum.vessels[0].type === 'Crude Oil Tanker'
  && sum.vessels[0].name === 'ADRIAN SEA' && sum.vessels[0].aliases[0] === 'ADRIAN' && sum.vessels[0].mmsi === '352001162', 'vessel name, alias, IMO, MMSI, flag and type (tonnage dropped)');
ok(sum.cyber.length === 1 && sum.cyber[0].name === 'SHADOW NET LLC' && sum.cyber[0].action === 'added' && sum.programs.CYBER2 === 1, 'CYBER-tagged designation');
// Formats seen on the live pages of 21 and 30 September/October 2026: call sign in parentheses, no call sign, and the
// "deletions have been made" heading for removals (a vessel listed under both its names).
const page2 = `<h4>The following vessels have been added to OFAC's SDN List:</h4>
<p>ANEMOS (3E2064) General Cargo Panama flag; Vessel Year of Build 1999; Vessel Registration Identification IMO 9205952; MMSI 352002345 (vessel) [IRAN-EO13902] (Linked To: ROXETTE MARITIME SHIPPING AND TRADING S.A.).</p>
<p>WHALES PEARL Crew/Supply Vessel United Arab Emirates flag; Vessel Year of Build 2008; Vessel Registration Identification IMO 9483114; MMSI 470123456 (vessel) [IRAN-EO13902] (Linked To: WHALES SHIPPING LINE LLC).</p>
<p>GAS LUCKY LPG Tanker Comoros flag; Vessel Registration Identification IMO 9177557 (vessel) [IRAN-EO13902].</p>
<h4>The following deletions have been made to OFAC's SDN List:</h4>
<p>MARAYA (f.k.a. MED PATRON) Palletized Cargo Ship Samoa flag; Vessel Registration Identification IMO 7514517 (vessel) [LIBYA3].</p>
<p>MED PATRON (a.k.a. MARAYA) Palletized Cargo Ship Samoa flag; Vessel Registration Identification IMO 7514517 (vessel) [LIBYA3].</p>
<p>BELTRADE CO, Minsk, Belarus [BELARUS-EO14038].</p>
<h4>The following entities have been added to the Non-SDN Menu-Based Sanctions List:</h4>
<p>NOT SDN LTD, Moscow, Russia [MBS].</p>`;
const e2 = M.parseOfacAction(page2), os2 = M.ofacSummary(e2);
const vv = Object.fromEntries(os2.vessels.map((v) => [v.action + ':' + v.name, v]));
ok(os2.added === 3 && os2.removed === 3 && !e2.some((e) => e.name === 'NOT SDN LTD'), 'deletions heading counts as removals; an unrecognized list heading is skipped');
ok(vv['added:ANEMOS'].call_sign === '3E2064' && vv['added:ANEMOS'].type === 'General Cargo' && vv['added:ANEMOS'].flag === 'Panama', 'call sign, type and flag');
ok(vv['added:WHALES PEARL'] && vv['added:WHALES PEARL'].type === 'Crew/Supply Vessel' && vv['added:WHALES PEARL'].flag === 'United Arab Emirates', 'name without call sign stops at the type');
ok(vv['added:GAS LUCKY'] && vv['added:GAS LUCKY'].type === 'LPG Tanker' && vv['added:GAS LUCKY'].flag === 'Comoros', 'LPG stays in the type');
ok(os2.vessels.filter((v) => v.action === 'removed').length === 1 && vv['removed:MARAYA'].aliases.includes('MED PATRON') && vv['removed:MARAYA'].type === 'Palletized Cargo Ship'
  && os2.removed_by_kind.vessel === 2 && os2.removed_by_kind.entity === 1 && !os2.programs.LIBYA3, 'one removed vessel per IMO with both names; removals stay out of added programs');
ok(M.ofacHead('X (a.k.a. Y; a.k.a. Z) Tanker Panama flag; IMO 1234567') === 'X (a.k.a. Y; a.k.a. Z) Tanker Panama flag' && M.ofacVessel('X (a.k.a. Y; a.k.a. Z) Tanker Panama flag; IMO 1234567 (vessel) [T]').aliases.length === 2, 'aliases holding semicolons');
ok(M.ofacTags('Democratic Republic of the Congo-related Designations Removals').programs.includes('DR Congo'), 'DR Congo program recognized');

// ---------------------------------------------------------------- lists, credibility, RSIT
const ndjson = '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n{"cidr":"203.0.113.0/24","sblid":"SBL1","rir":"arin"}\n{"type":"metadata","timestamp":1}';
const dr = M.parseList(ndjson, 'cidr');
ok(dr.entries === 2 && M.inNets(dr.nets, M.ip2n('203.0.113.77')) && M.inNets(dr.nets, M.ip2n('1.10.31.255')) && !M.inNets(dr.nets, M.ip2n('1.10.32.0')), 'DROP NDJSON ranges');
const txt = M.parseList('; Spamhaus DROP\n1.10.16.0/20 ; SBL256894\n', 'ip');
ok(txt.nets.length === 1 && txt.entries === 1, 'DROP text fallback keeps networks');
const ips = M.parseList('#ip,ioc\n198.51.100.7,Possible Cobaltstrike C2 IP\n192.0.2.1\n', 'csv');
ok(ips.ips.has('198.51.100.7') && ips.ips.has('192.0.2.1') && ips.entries === 2, 'CSV and plain IP lists');
const ipsum = M.parseList('# IPsum\n77.90.185.20\t11\n152.32.225.117\t10\n', 'ipsum');
ok(ipsum.ipsum.get('77.90.185.20') === 11, 'IPsum list counts');
const c1 = M.credibility({ layers: ['ioc'], lists: [] }), c2 = M.credibility({ layers: ['ioc'], lists: ['tview'] }), c3 = M.credibility({ layers: ['ioc', 'src'], lists: ['cins', 'tor', 'ipsum'] });
ok(c1.cred === 3 && c1.rel === 'A' && c1.score === 0.6, 'single origin: possibly true');
ok(c2.cred === 3 && !M.CORRO_LISTS.some((l) => l.id === 'sslbl'), 'a derived list (ThreatView) adds no origin; deprecated SSLBL list dropped');
ok(c3.cred === 1 && c3.origins === 3, 'three operators confirm; Tor and IPsum are not origins');
ok(M.rsitOf('c2') === 'malicious-code/c2-server' && M.rsitOf('ioc', 'payload_delivery') === 'malicious-code/malware-distribution' && M.rsitOf('src') === 'information-gathering/scanner', 'RSIT mapping');

// ---------------------------------------------------------------- threat map carries the new fields
const tm = M.buildThreatmap({ nodes: [{ layer: 'ioc', ip: '198.51.100.7', port: 443, family: 'Cobalt Strike', lat: 1, lon: 2, cc: 'NL', first_seen: '2026-10-21T00:00:00Z', first_obs: '2026-10-21T01:00:00Z', lists: ['c2if', 'cins'], ipsum: 3, threat: 'botnet_cc' },
  { layer: 'src', ip: '198.51.100.7', port: 0, family: '', lat: 1, lon: 2, cc: 'NL', lists: ['c2if', 'cins'], ipsum: 3 }],
  fetched: { c2: { ok: true, rows: [] }, ioc: { ok: true, rows: [1] }, src: { ok: true, rows: [1] }, url: { ok: true, rows: [] } }, trend: [], geoStats: {} });
const node = tm.rows.find((r) => r.kind === 'node' && r.layer === 'ioc');
ok(node.lb === 'c2if,cins' && node.ipsum === 3 && node.cred === 1 && node.rsit === 'malicious-code/c2-server' && node.obs === '2026-10-21T01:00:00Z', 'node: lists, IPsum, credibility, RSIT and observation time');
ok(tm.credibility[1] === 2 && /RSIT/.test(tm.taxonomy), 'map-level credibility counts and taxonomy note');

// ---------------------------------------------------------------- enrichment inputs
ok(M.enrichInput('asn', 'AS13335') === '13335' && M.enrichInput('ip', '10.0.0.1') === null && M.enrichInput('ip', '8.8.8.8') === '8.8.8.8', 'ASN and public IP inputs; private refused');
ok(M.enrichInput('domain', 'Example.COM.') === 'example.com' && M.enrichInput('domain', 'not a domain') === null && M.enrichInput('hash', 'A'.repeat(64)) === 'a'.repeat(64), 'domain and hash inputs');
ok(M.enrichInput('actor', 'APT28') === 'APT28' && M.enrichInput('actor', '<script>') === null && M.enrichInput('nope', 'x') === null, 'actor input and unknown type');
ok(Object.values(M.ANALYZERS).every((a) => a.types.length && a.label && typeof a.run === 'function'), 'every analyzer declares its types');
ok(M.ANALYZERS.mbazaar.types[0] === 'hash' && M.ANALYZERS.yaraify.types[0] === 'hash' && !/key|auth/i.test(M.ANALYZERS.mbazaar.page('a'.repeat(64)) + M.ANALYZERS.yaraify.page('a'.repeat(64))), 'abuse.ch hash analyzers; no key in their links');
const mb = M.parseBazaar({ query_status: 'ok', data: [{ sha256_hash: 'a'.repeat(64), file_type: 'exe', signature: 'StrelaStealer', tags: ['exe', 'StrelaStealer'], first_seen: '2026-10-24 05:00:00', intelligence: { downloads: '12' },
  yara_rules: [{ rule_name: 'win_strela', author: 'example' }], vendor_intel: { ReversingLabs: {}, Triage: {} } }] });
ok(mb.found && mb.signature === 'StrelaStealer' && mb.downloads === 12 && mb.yara_rules[0].rule === 'win_strela' && mb.vendors.length === 2, 'MalwareBazaar get_info parsed');
ok(M.parseBazaar({ query_status: 'hash_not_found' }).found === false && (() => { try { M.parseBazaar({ query_status: 'illegal_hash' }); return false; } catch { return true; } })(), 'MalwareBazaar not found and refusals');
const yf = M.parseYaraify({ query_status: 'ok', data: { metadata: { sha256_hash: 'b'.repeat(64), file_type_mime: 'application/x-dosexec', sightings: 3 },
  tasks: [{ static_results: [{ rule_name: 'DetectsLoader', author: 'x' }, { rule_name: 'xxx', author: 'xxx' }, { rule_name: 'DetectsLoader', author: 'x' }], clamav_results: ['Win.Trojan.Example'] }, { static_results: null, clamav_results: null }] } });
ok(yf.found && yf.sightings === 3 && yf.tasks === 2 && yf.yara_rules.length === 1 && yf.clamav[0] === 'Win.Trojan.Example', 'YARAify lookup parsed; non-public rules dropped');

// ---------------------------------------------------------------- volume baseline and schedule
const vf = (n, med, days) => M.volumeFlag({ feed: 'x', n, median_30d: med, runs: 10, first_at: new Date(now - days * 864e5).toISOString() }, now);
ok(vf(500, 100, 10).flag === 'spike' && vf(10, 100, 10).flag === 'silence' && vf(0, 100, 10).flag === 'silence' && vf(110, 100, 10).flag === 'normal' && vf(500, 100, 3).flag === 'baseline building', 'volume flags');
const at = (s) => M.plan(new Date(s));
ok(JSON.stringify(at('2026-10-22T06:19:00Z')) === JSON.stringify(['gdelt', 'health', 'ioda', 'sources', 'translate', 'triage', 'lists', 'leaksites', 'links', 'unit42', 'triageeval', 'score', 'entities', 'watch', 'reports']), ':19 at 06 UTC adds Unit 42');
ok(at('2026-10-26T08:19:00Z').includes('ransompay') && !at('2026-10-27T08:19:00Z').includes('ransompay'), 'Ransomwhere Mondays only');
ok(at('2026-10-22T10:49:00Z').join() === 'gdelt,health,ioda,retention,fires,maritime,sources,triage,cyphys,entities,watch,reports' && at('2026-10-22T10:04:00Z').join() === 'gdelt,infra,snap,sources,translate,entities,watch,foresight,reports', ':49 and :04 plans');
ok(at('2026-10-22T12:19:00Z').includes('sec8k') && at('2026-10-22T22:19:00Z').includes('sec8k') && !at('2026-10-22T13:19:00Z').includes('sec8k'), 'SEC 8-K at 12 and 22 UTC');

// ---------------------------------------------------------------- SEC 8-K (EDGAR full-text search hits as served 22 October 2026)
const H = (adsh, file, name, cik, sic, date, items, form = '8-K') => ({ _id: adsh + ':' + file, _source: { ciks: [cik], display_names: [name], sics: [sic], file_date: date, form, file_type: form, adsh, items, biz_states: ['CA'], period_ending: date } });
const s1 = H('0001104659-26-109813', 'asth-20260922x8k.htm', 'Astrana Health, Inc.  (ASTH)  (CIK 0001083446)', '0001083446', '8742', '2026-09-23', ['1.05']);
const s2 = H('0000000001-26-000001', 'bank8k.htm', 'Example Bancorp  (EXBK)  (CIK 0000000001)', '0000000001', '6022', '2026-10-01', ['8.01', '9.01']);
const s3 = H('0000000002-26-000002', 'misc.htm', 'Other Co  (CIK 0000000002)', '0000000002', '3674', '2026-10-02', ['2.02']);
const s4 = H('0001104659-26-200000', 'asth8ka.htm', 'Astrana Health, Inc.  (ASTH)  (CIK 0001083446)', '0001083446', '8742', '2026-10-15', ['1.05'], '8-K/A');
const sr = M.secRows({ item105: [s1, s4], ransomware: [s1, s2, s3], cyberattack: [], incident: [s2] });
const a1 = sr.find((r) => r.adsh === s1._source.adsh), b1 = sr.find((r) => r.cik === '1');
ok(sr.length === 3 && !sr.some((r) => r.cik === '2'), 'Item 1.05 and incident-term 8.01 filings kept; other items dropped');
ok(a1.company === 'Astrana Health, Inc.' && a1.ticker === 'ASTH' && a1.cik === '1083446' && a1.score === 7 && a1.url === 'https://www.sec.gov/Archives/edgar/data/1083446/000110465926109813/0001104659-26-109813-index.htm', 'filing row, score and index link');
ok(b1.item_801 && b1.financial && b1.vertical === 'financial' && b1.score === 3 && b1.terms.join() === 'ransomware,incident', '8.01 filing by a bank: financial vertical, terms listed');
ok(sr.find((r) => r.amendment).amends === s1._source.adsh, 'amendment linked to its original');
// Exhibit-only matches are boilerplate: an 8.01 filing whose term appears only in EX-10.1 is left out; one whose 8-K text
// carries the term is kept and links to that text.
const ex = (h, file, type) => ({ _id: h._source.adsh + ':' + file, _source: { ...h._source, file_type: type } });
const s5 = H('0000000005-26-000005', 'credit8k.htm', 'Lender Co  (LNDR)  (CIK 0000000005)', '0000000005', '6022', '2026-10-03', ['1.01', '8.01', '9.01']);
const s6 = H('0000000006-26-000006', 'retail8k.htm', 'Retail Co  (RTL)  (CIK 0000000006)', '0000000006', '5500', '2026-10-04', ['8.01', '9.01']);
const sx = M.secRows({ item105: [], ransomware: [ex(s5, 'ex10-1.htm', 'EX-10.1'), ex(s6, 'ex99-1.htm', 'EX-99.1'), s6], cyberattack: [], incident: [] });
ok(sx.length === 1 && sx[0].cik === '6' && /retail8k\.htm$/.test(sx[0].doc_url) && sx[0].in_8k_text.join() === 'ransomware', 'exhibit-only 8.01 matches dropped; the 8-K text match kept and linked');
ok(M.secVertical('4941').vertical === 'water' && M.secVertical('4911').vertical === 'energy' && M.secVertical('8062').vertical === 'healthcare' && M.secVertical('7372').sector === 'Software and IT services', 'SIC to verticals');
ok(M.secUrl('"Item 1.05"', '8-K', '2026-07-24', '2026-10-22', 1) === 'https://efts.sec.gov/LATEST/search-index?q=%22Item%201.05%22&forms=8-K&dateRange=custom&startdt=2026-07-24&enddt=2026-10-22&from=100', 'EDGAR query on the root form');

console.log(`intel tests: ${pass} checks passed`);
