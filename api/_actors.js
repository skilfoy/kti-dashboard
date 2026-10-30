const { handle, sendJson, upstream } = require('./_lib');

// Reported state-nexus targeting, for the map's attribution layer. Source: the MISP galaxy threat-actor cluster
// (dual-licensed, CC0 1.0 option), which carries each actor's attributed country and, for actors also listed in the
// Council on Foreign Relations Cyber Operations Tracker, the CFR fields: suspected state sponsor, suspected victims,
// target categories and incident type. Arcs run from the attributed country to each suspected victim country.
// This is historical attribution compiled from public reporting, with the cluster's own confidence values; none of
// it describes live traffic. Victims that are regions, organisations or sectors stay in the actor row as text.
const SOURCES = [
  'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json',
  'https://cdn.jsdelivr.net/gh/MISP/misp-galaxy@main/clusters/threat-actor.json',
];
const ISO = { Afghanistan: 'AF', Albania: 'AL', Algeria: 'DZ', Argentina: 'AR', Armenia: 'AM', Australia: 'AU', Austria: 'AT', Azerbaijan: 'AZ', Bahamas: 'BS',
  Bahrain: 'BH', Bangladesh: 'BD', Belarus: 'BY', Belgium: 'BE', Brazil: 'BR', Brunei: 'BN', Cambodia: 'KH', Cameroon: 'CM', Canada: 'CA', 'Central African Republic': 'CF',
  Chile: 'CL', China: 'CN', Colombia: 'CO', 'Costa Rica': 'CR', Croatia: 'HR', Cuba: 'CU', 'Czech Republic': 'CZ', Czechia: 'CZ', Denmark: 'DK', Djibouti: 'DJ',
  Ecuador: 'EC', Egypt: 'EG', Estonia: 'EE', Finland: 'FI', France: 'FR', Gaza: 'PS', Georgia: 'GE', Germany: 'DE', Greece: 'GR', Guatemala: 'GT', 'Hong Kong': 'HK',
  Hungary: 'HU', India: 'IN', Indonesia: 'ID', Iran: 'IR', 'Iran (Islamic Republic of)': 'IR', Iraq: 'IQ', Ireland: 'IE', Israel: 'IL', Italy: 'IT', 'Ivory Coast': 'CI',
  Japan: 'JP', Jordan: 'JO', Kazakhstan: 'KZ', Kenya: 'KE', "Korea (Democratic People's Republic of)": 'KP', 'Korea (Republic of)': 'KR', Kuwait: 'KW', Kyrgyzstan: 'KG',
  Laos: 'LA', Latvia: 'LV', Lebanon: 'LB', Lebonon: 'LB', Libya: 'LY', Lithuania: 'LT', Luxembourg: 'LU', Macao: 'MO', Malaysia: 'MY', Mali: 'ML', Mexico: 'MX',
  Moldova: 'MD', Mongolia: 'MN', Morocco: 'MA', Myanmar: 'MM', Namibia: 'NA', Nepal: 'NP', Netherlands: 'NL', 'New Zealand': 'NZ', Nigeria: 'NG', 'North Korea': 'KP',
  Norway: 'NO', Oman: 'OM', Pakistan: 'PK', Palestine: 'PS', Panama: 'PA', "People's Republic of China": 'CN', Peru: 'PE', Philippines: 'PH', 'The Philippines': 'PH',
  Poland: 'PL', Portugal: 'PT', Qatar: 'QA', Romania: 'RO', Russia: 'RU', 'Russian Federation': 'RU', Rwanda: 'RW', 'Saudi Arabia': 'SA', Senegal: 'SN', Serbia: 'RS',
  Singapore: 'SG', Slovakia: 'SK', 'Solomon Islands': 'SB', Somalia: 'SO', 'South Africa': 'ZA', 'South Korea': 'KR', 'South Sudan': 'SS', Spain: 'ES', 'Sri Lanka': 'LK',
  Sudan: 'SD', Suriname: 'SR', Sweden: 'SE', Switzerland: 'CH', Syria: 'SY', Taiwan: 'TW', Tajikistan: 'TJ', Thailand: 'TH', Togo: 'TG', Tunisia: 'TN', Turkey: 'TR',
  'Türkiye': 'TR', Turkmenistan: 'TM', US: 'US', 'United States': 'US', 'United States of America': 'US', Ukraine: 'UA', 'United Arab Emirates': 'AE',
  'United Kingdom': 'GB', Uzbekistan: 'UZ', Venezuela: 'VE', Vietnam: 'VN', 'Viet Nam': 'VN', Yemen: 'YE' };
const list = (x) => (Array.isArray(x) ? x : typeof x === 'string' ? x.split(',') : []).map((s) => String(s).trim()).filter(Boolean);
const iso2 = (s) => { const t = String(s || '').trim(); return /^[A-Z]{2}$/.test(t) ? t : ISO[t] || ''; };
function clip(s, n) {
  const t = String(s || '').replace(/\s+/g, ' ').trim();
  if (t.length <= n) return t;
  const cut = t.slice(0, n), dot = cut.lastIndexOf('. ');
  return (dot > n * 0.5 ? cut.slice(0, dot + 1) : cut.replace(/\s+\S*$/, '') + ' ...');
}

function build(cluster) {
  const actors = [], pairs = new Map(), origins = new Map();
  for (const v of cluster.values || []) {
    const m = v.meta || {};
    const origin = iso2(m.country) || iso2(m['cfr-suspected-state-sponsor']);
    if (origin) { const o = origins.get(origin) || { kind: 'origin', cc: origin, actors: 0, with_victims: 0 }; o.actors++; origins.set(origin, o); }
    const named = list(m['cfr-suspected-victims']).concat(list(m['suspected-victims']));
    const victims = [...new Set(named.map(iso2).filter((c) => c && c !== origin))];
    if (!victims.length) continue;
    if (origin) origins.get(origin).with_victims++;
    const refs = list(m.refs);
    actors.push({ kind: 'actor', name: v.value, origin, sponsor: m['cfr-suspected-state-sponsor'] || '', confidence: m['attribution-confidence'] == null ? null : +m['attribution-confidence'],
      incident: list(m['cfr-type-of-incident']).join(', '), targets: list(m['cfr-target-category']).slice(0, 6), victims,
      other: [...new Set(named.filter((n) => !iso2(n)))].filter((n) => n.length > 2).slice(0, 6), aka: list(m.synonyms).slice(0, 6),
      ref: refs.find((r) => /cfr\.org/.test(r)) || refs[0] || '', refs: refs.length, desc: clip(v.description, 260), uuid: v.uuid });
    if (!origin) continue;
    for (const t of victims) {
      const k = origin + '>' + t;
      const p = pairs.get(k) || { kind: 'pair', o: origin, t, n: 0, actors: [] };
      p.n++; if (p.actors.length < 12) p.actors.push(v.value);
      pairs.set(k, p);
    }
  }
  actors.sort((a, b) => b.victims.length - a.victims.length || a.name.localeCompare(b.name));
  const rows = [...actors, ...[...pairs.values()].sort((a, b) => b.n - a.n), ...[...origins.values()].sort((a, b) => b.actors - a.actors)];
  return { actors_total: (cluster.values || []).length, actors_with_victims: actors.length, pairs: pairs.size, rows };
}

module.exports = handle(async (req, res) => {
  const tried = [];
  for (const url of SOURCES) {
    let r;
    try { r = await upstream(url, { timeout: 20000 }); } catch (e) { tried.push({ url, error: String(e.message || e) }); continue; }
    if (!r.ok || !r.json || !Array.isArray(r.json.values)) { tried.push({ url, status: r.status }); continue; }
    const b = build(r.json);
    return sendJson(res, 200, { source: 'MISP galaxy threat-actor cluster (CFR Cyber Operations Tracker fields where present)', source_url: url,
      cluster_version: r.json.version, license: 'CC0 1.0 (dual-licensed)', generated: new Date().toISOString(),
      note: 'Historical attribution compiled from public reporting; arcs are attributed origin to suspected victim country, not observed traffic.',
      ...b, count: b.rows.length }, 43200, 604800);
  }
  return sendJson(res, 502, { error: 'threat-actor cluster unavailable', tried }, 0);
});
module.exports.build = build;
