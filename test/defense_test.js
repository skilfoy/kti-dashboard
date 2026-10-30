// The Defense, weaponization and warning calculations against the built datasets in out/, run in node with a minimal
// dash stand-in. Run: node test/defense_test.js <scratch dir>
const fs = require('fs'), path = require('path'), assert = require('assert');
const S = process.argv[2];
const calcs = {};
global.window = global;
global.d3 = {};
global.dash = { calc: (id, def) => { calcs[id] = def; }, loader() {}, onData() {}, params: () => ({}), data: () => ({ status: 'missing' }), colors: [] };
global.TI = { root: { addEventListener() {} }, page() {}, h() {}, v() {}, f: {}, rows: () => null, ready: () => false };
global.document = { getElementById: () => null };
for (const f of ['calcs.js', 'defense.js', 'weapon.js', 'warning.js']) eval(fs.readFileSync(path.join(S, 'public', 'js', f), 'utf8'));  // eslint-disable-line no-eval
const file = (n) => { const x = JSON.parse(fs.readFileSync(path.join(S, 'public', 'data', n + '.json'), 'utf8')); return Array.isArray(x) ? x : x.rows; };
// The runtime hands list and record cells over as JSON text; mimic that for the inputs these calcs read.
const norm = (rows) => { const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))]; return rows.map((r) => Object.fromEntries(cols.map((c) => [c, r[c] == null ? null : typeof r[c] === 'object' ? JSON.stringify(r[c]) : r[c]]))); };
const data = {};
const get = (id) => {
  if (data[id]) return data[id];
  if (calcs[id]) return (data[id] = norm(calcs[id].fn(...calcs[id].inputs.map(get))));
  return (data[id] = norm(file(id)));
};
let checks = 0;
const ok = (c, m) => { assert(c, m); checks += 1; };

const verticals = get('verticals').map((v) => v.vertical_id);
const tech = get('defense_techniques');
const gw = get('defense_group_weight');
ok(gw.length === verticals.length * get('attack_groups').length, 'one weight per group and vertical');
ok(gw.every((g) => g.weight >= 0.2 && g.weight <= 1), 'weights within 0.2 to 1');
// A state group whose description names none of the vertical's sectors is halved: China at Taiwan Strait 3 gives 0.6, halved 0.3.
const sectors = new Set(get('defense_group_sectors').map((r) => r.group_id + '|' + r.vertical_id));
const cn = gw.filter((g) => g.vertical_id === 'financial' && g.nexus === 'China' && !/Financial/.test(g.motivation || ''));
ok(cn.every((g) => (sectors.has(g.group_id + '|financial') ? g.weight >= 0.6 : g.weight <= 0.3 + 1e-9)), 'sector halving for state groups');
const pr = get('defense_priority');
ok(pr.length === verticals.length * tech.length, 'one priority per technique and vertical');
for (const v of verticals) {
  const rows = pr.filter((r) => r.vertical_id === v);
  ok(new Set(rows.map((r) => r.rank)).size === rows.length && Math.min(...rows.map((r) => r.rank)) === 1, `${v}: ranks unique from 1`);
  ok(rows.every((r) => Math.abs(r.priority - (r.prevalence + r.choke + r.actionability)) < 0.003 && r.priority >= 0 && r.priority <= 3), `${v}: priority is the sum of its parts`);
  ok(rows.every((r) => r.shift === r.base_rank - r.rank), `${v}: shift is baseline rank minus rank`);
  ok(Math.max(...rows.map((r) => r.p_threat)) === 1 && Math.max(...rows.map((r) => r.breadth)) === 1, `${v}: threat use and breadth scaled to 1`);
  ok(rows.every((r) => (r.gap === '') === (r.community > 0 && r.atomic > 0)), `${v}: gap flags match content counts`);
}
const fin = pr.filter((r) => r.vertical_id === 'financial');
ok(fin[0].technique_id === 'T1059', 'financial rank 1 is T1059: ' + fin[0].technique_id);
const t1190 = fin.find((r) => r.technique_id === 'T1190');
ok(t1190.community === 329 && t1190.atomic === 0 && t1190.gap === 'No Atomic test', 'T1190 counts: ' + JSON.stringify([t1190.community, t1190.atomic, t1190.gap]));
const tac = get('defense_tactic_cov');
ok(tac.every((r) => r.detected_share == null || (r.detected_share >= 0 && r.detected_share <= 1)), 'tactic shares in 0..1');
ok(tac.filter((r) => r.vertical_id === 'financial').length === 15, 'all 15 v20 tactics present');
const tele = get('defense_telemetry_rank').filter((r) => r.vertical_id === 'financial');
ok(tele[0].rank === 1 && tele.every((r, i) => i === 0 || tele[i - 1].weighted >= r.weighted), 'telemetry ranked by summed priority');
ok(tele.every((r) => r.top_served <= 100), 'served counts within the top 100');
const cri = get('defense_cri_rank').filter((r) => r.vertical_id === 'financial');
ok(cri.length === 60 && cri.every((r) => r.weighted_share >= 0 && r.weighted_share <= 1), 'CRI shares in 0..1');
const ac = get('defense_actor_cov');
ok(ac.every((r) => r.detected <= r.techniques && r.tested <= r.techniques), 'actor coverage counts bounded');
ok(new Set(get('kev_attack_cve').map((r) => r.cve)).size === 419, 'KEV mapping covers 419 CVEs');
const kx = get('defense_kev_exploit');
ok(kx[0].technique_id === 'T1190' && kx[0].cves === 154, 'T1190 leads exploitation techniques');
const sm = get('defense_summary');
ok(sm.length === verticals.length, 'one summary per vertical');

const wl = get('weapon_lags');
ok(wl.length >= 4 && wl.every((r) => +r.year >= 2022), 'weaponization years from 2022');
const ws = get('weapon_summary')[0];
const w = get('weaponization');
const cohort = w.filter((r) => r.in_kev === 'Yes' && r.cohort === 'Since KEV launch' && r.weapon_before_kev);
ok(ws.kev_both === cohort.length && ws.kev_first === cohort.filter((r) => r.weapon_before_kev === 'Yes').length, 'summary counts match the rows');
ok(w.every((r) => !r.weapon_before_kev || (r.weapon_before_kev === 'Yes') === (r.weaponized < r.kev_added)), 'weaponized-first flag matches the dates');
ok(w.every((r) => !r.weaponized || r.weaponized === [r.nuclei_added, r.msf_added].filter(Boolean).sort()[0]), 'weaponized is the earlier tool date');

const rules = get('indicator_rules');
const ind = new Set(get('theater_indicators').map((r) => r.ind_id));
ok(rules.every((r) => ind.has(r.ind_id)), 'every rule names a known indicator');
ok(new Set(rules.map((r) => r.rule_id)).size === rules.length, 'rule ids unique');
console.log(JSON.stringify({ checks, financial_top5: fin.slice(0, 5).map((r) => r.technique_id), in_scope: Object.fromEntries(verticals.map((v) => [v, gw.filter((g) => g.vertical_id === v && g.in_scope === 'Yes').length])),
  weapon: { kev_both: ws.kev_both, kev_first: ws.kev_first, median_lead_first: ws.median_lead_first, ew_weaponized: ws.ew_weaponized } }));
console.log('PASS defense');
