// ---------------------------------------------------------------- corroboration lists and credibility for mapped hosts (G58, G51)
// Free IPv4 lists from the Open-Source-Threat-Intel-Feeds catalogue (Bert-JanP, BSD-3-Clause), each with its operator and
// the terms found on 22 October 2026. A mapped host gains a list when the list names its address (or, for network lists,
// a range holding it). An address no list carries is unknown: absence is never read as benign.
// Independence is judged by operator: a list run by the operator of the feed that put the host on the map adds no new
// origin, and aggregates (IPsum counts how many lists carry an address; FireHOL level 1 bundles DShield and Feodo, two of
// the map's own sources) are shown beside the count and never added to it. Tor exit relays are flagged, since an exit
// relays other people's traffic. ThreatView names no sources for this feed, and a sample on 22 October 2026 showed its
// addresses largely repeating blocklist.de and CINS Army, so it is shown beside the count as derived; each run measures
// every list's overlap with the other operators' lists and publishes it, so the call can be checked. abuse.ch SSLBL's IP
// list was deprecated on 3 January 2025 and is left out.
export const CORRO_LISTS = [
  { id: 'blde', name: 'blocklist.de attackers, last 48 hours', op: 'blocklist.de', url: 'https://lists.blocklist.de/lists/all.txt', fmt: 'ip', terms: 'Free download; terms page not machine-readable; personal use, confirm before client use' },
  { id: 'cins', name: 'CINS Army bad actors', op: 'Sentinel IPS', url: 'https://cinsscore.com/list/ci-badguys.txt', fmt: 'ip', terms: 'Provided to parse and use in any way you see fit' },
  { id: 'drop', name: 'Spamhaus DROP (do not route or peer)', op: 'Spamhaus', url: 'https://www.spamhaus.org/drop/drop_v4.json', alt: 'https://www.spamhaus.org/drop/drop.txt', fmt: 'cidr', terms: 'Free of charge under the DROP Terms of Use; no Spamhaus name in marketing' },
  { id: 'c2if', name: 'C2IntelFeeds C2 IPs, last 30 days', op: 'drb-ra', url: 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv', fmt: 'csv', terms: 'CC BY-NC-SA 4.0: non-commercial use only; excluded from client products', nc: true },
  { id: 'tview', name: 'ThreatView IP high confidence', op: 'ThreatView', url: 'https://threatview.io/Downloads/IP-High-Confidence-Feed.txt', fmt: 'ip', derived: true, terms: 'Open-access community feed; no licence stated; confirm before client use' },
  { id: 'etc', name: 'Proofpoint Emerging Threats compromised IPs', op: 'Proofpoint', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', fmt: 'ip', terms: 'Emerging Threats Open blocklist, free' },
  { id: 'gsnow', name: 'GreenSnow attackers', op: 'GreenSnow', url: 'https://blocklist.greensnow.co/greensnow.txt', fmt: 'ip', terms: 'Free blocklist; no licence stated; confirm before client use' },
  { id: 'tcioc', name: 'ThreatCluster IOC blocklist, last 30 days', op: 'ThreatCluster', url: 'https://threatcluster.io/api/iocs/public/feed.txt', fmt: 'ip', terms: 'Public feed, no key; ThreatCluster invites SIEM and cron use' },
  { id: 'tor', name: 'Tor exit relays', op: 'Tor Project', url: 'https://check.torproject.org/torbulkexitlist', fmt: 'ip', flag: true, terms: 'Public list' },
  { id: 'ipsum', name: 'IPsum (count of lists naming the address)', op: 'aggregate', url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt', fmt: 'ipsum', aggregate: true, terms: 'Public domain (Unlicense)' },
];
// The operator behind each map layer, for the independence rule.
export const LAYER_OP = { c2: 'abuse.ch', ioc: 'abuse.ch', url: 'abuse.ch', src: 'SANS ISC' };
const IX_CR2 = String.fromCharCode(13);
const V4 = /\b(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(\d{1,2}))?\b/;
export const ip2n = (ip) => { const p = ip.split('.'); return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + +p[3]; };
// Parses one list into { ips: Set, nets: [[lo, hi], ...] sorted, ipsum: Map } and its entry count.
export function parseList(text, fmt) {
  const ips = new Set(), nets = [], ipsum = new Map();
  let entries = 0;
  const s = String(text || '');
  if (fmt === 'cidr' && /^\s*[{[]/.test(s)) {
    for (const line of s.split(IX_CR2).join('').split('\n')) {
      let o = null;
      try { o = JSON.parse(line); } catch { continue; }
      const c = o && (o.cidr || o.prefix);
      const m = c && String(c).match(V4);
      if (m && m[5] != null) { const lo = ip2n(m[0].split('/')[0]) & ~((2 ** (32 - +m[5])) - 1); nets.push([lo >>> 0, (lo >>> 0) + 2 ** (32 - +m[5]) - 1]); entries++; }
    }
  } else {
    for (const raw of s.split(IX_CR2).join('').split('\n')) {
      const line = raw.trim();
      if (!line || line[0] === '#' || line[0] === ';') continue;
      const m = line.match(V4);
      if (!m) continue;
      const ip = [m[1], m[2], m[3], m[4]].map(Number).join('.');
      if (m[5] != null && +m[5] < 32) { const bits = +m[5], lo = (ip2n(ip) & (bits ? ~((2 ** (32 - bits)) - 1) : 0)) >>> 0; nets.push([lo, lo + 2 ** (32 - bits) - 1]); entries++; continue; }
      if (fmt === 'ipsum') { const n = +(line.split(/\s+/)[1] || 0); if (n) ipsum.set(ip, n); }
      ips.add(ip); entries++;
    }
  }
  nets.sort((a, b) => a[0] - b[0]);
  return { ips, nets, ipsum, entries };
}
export function inNets(nets, n) {
  let lo = 0, hi = nets.length - 1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (nets[mid][0] <= n) lo = mid + 1; else hi = mid - 1; }
  for (let k = hi; k >= 0 && k > hi - 64; k--) if (nets[k][0] <= n && n <= nets[k][1]) return true;
  return false;
}
// Admiralty credibility for a mapped host from the operators naming it: 1 confirmed by three or more independent
// origins, 2 probably true with two, 3 possibly true with one (the map's own source). Reliability is the map source's
// registry grade; the item score is reliability x credibility weight (Tiepolo and Sorensen p525).
export const REL_W = { A: 1.0, B: 0.8, C: 0.6, D: 0.4, E: 0.2, F: 0.3 };
export const CRED_W = { 1: 1.0, 2: 0.8, 3: 0.6, 4: 0.4, 5: 0.2, 6: 0.3 };
// Registry grades: abuse.ch A (S-ABUSE); SANS ISC DShield B (long-running community sensor data with known scanner noise).
export const LAYER_REL = { c2: 'A', ioc: 'A', url: 'A', src: 'B' };
export function credibility({ layers, lists }) {
  const ops = new Set((layers || []).map((l) => LAYER_OP[l]).filter(Boolean));
  for (const id of lists || []) { const L = CORRO_LISTS.find((x) => x.id === id); if (L && !L.flag && !L.aggregate && !L.derived) ops.add(L.op); }
  const origins = ops.size;
  const cred = origins >= 3 ? 1 : origins === 2 ? 2 : 3;
  const rel = (layers || []).map((l) => LAYER_REL[l]).filter(Boolean).sort()[0] || 'C';
  return { origins, cred, rel, score: Math.round(REL_W[rel] * CRED_W[cred] * 100) / 100 };
}
export async function jobLists() {
  const t0 = Date.now();
  const hosts = await sql(`SELECT DISTINCT host(ip) AS ip FROM ti.infra WHERE last_obs > now() - interval '6 hours' AND family(ip) = 4`);
  const fetched = await pool(CORRO_LISTS, 4, async (L) => {
    let r = await get(L.url, { timeout: 30000 });
    let used = L.url;
    if ((!r.ok || !r.text) && L.alt) { r = await get(L.alt, { timeout: 30000 }); used = L.alt; }
    if (!r.ok) return { L, ok: false, status: r.status, error: r.error || 'HTTP ' + r.status, used };
    const p = parseList(r.text, L.alt && used === L.alt ? 'ip' : L.fmt);
    if (!p.entries) return { L, ok: false, status: r.status, error: 'no entries parsed: ' + String(r.text || '').slice(0, 80).replace(/\s+/g, ' '), used };
    return { L, ok: true, status: r.status, used, ...p };
  });
  const rows = [];
  const per = new Map(fetched.map((f) => [f.L.id, { matched: 0, only: 0 }]));
  for (const { ip } of hosts) {
    const n = ip2n(ip), lists = [];
    let ipsum = null, tor = false;
    for (const f of fetched) {
      if (!f.ok) continue;
      const hit = f.ips.has(ip) || (f.nets.length && inNets(f.nets, n));
      if (f.L.id === 'ipsum') { if (f.ipsum.has(ip)) { ipsum = f.ipsum.get(ip); per.get('ipsum').matched++; } continue; }
      if (!hit) continue;
      per.get(f.L.id).matched++;
      if (f.L.flag) { tor = true; continue; }
      lists.push(f.L.id);
    }
    if (lists.length === 1) per.get(lists[0]).only++;
    if (lists.length || ipsum || tor) rows.push({ ip, lists, ipsum, tor });
  }
  await sqlTx([
    [`INSERT INTO ti.ip_list (ip, lists, ipsum, tor, checked_at) SELECT ip::inet, ARRAY(SELECT jsonb_array_elements_text(lists)), ipsum, tor, now()
      FROM jsonb_to_recordset($1::jsonb) AS x(ip text, lists jsonb, ipsum int, tor boolean)
      ON CONFLICT (ip) DO UPDATE SET lists = EXCLUDED.lists, ipsum = EXCLUDED.ipsum, tor = EXCLUDED.tor, checked_at = now()`, [rows]],
    // Hosts checked this run that no list carries any more lose their old memberships.
    [`DELETE FROM ti.ip_list WHERE ip IN (SELECT ip::inet FROM jsonb_array_elements_text($1::jsonb) AS t(ip)) AND checked_at < now() - interval '1 minute'`, [hosts.map((h) => h.ip)]],
  ]);
  // Measured independence: the share of each list's single addresses that a list from another operator also carries.
  const peers = fetched.filter((f) => f.ok && !f.L.flag && !f.L.aggregate);
  for (const f of peers) {
    if (!f.ips.size) { f.overlap = null; continue; }
    let shared = 0;
    for (const ip of f.ips) { const n = ip2n(ip); if (peers.some((g) => g !== f && g.L.op !== f.L.op && (g.ips.has(ip) || (g.nets.length && inNets(g.nets, n))))) shared++; }
    f.overlap = Math.round((shared / f.ips.size) * 1000) / 1000;
  }
  const lists = fetched.map((f) => ({ kind: 'list', id: f.L.id, name: f.L.name, operator: f.L.op, url: f.used || f.L.url, terms: f.L.terms, noncommercial: !!f.L.nc,
    role: f.L.flag ? 'flag' : f.L.aggregate ? 'aggregate' : f.L.derived ? 'derived' : 'corroboration', ok: f.ok, status: f.status, error: f.ok ? null : f.error, entries: f.ok ? f.entries : null,
    overlap_other_operators: f.overlap == null ? null : f.overlap, matched: per.get(f.L.id).matched, only_list: per.get(f.L.id).only }));
  const doc = { source: 'Free IPv4 blocklists from the Open-Source-Threat-Intel-Feeds catalogue (Bert-JanP), checked against the hosts on the threat map',
    method: 'Each mapped IPv4 host is looked up in every list hourly. Corroboration counts distinct operators: the map source\'s operator plus each list operator that names the host; a list run by the same operator adds nothing. IPsum (a count of lists), lists judged derived from others (ThreatView) and Tor exits are shown beside the count, never in it; overlap_other_operators is the measured share of a list\'s addresses that another operator\'s list also carries. Credibility: 3 or more operators 1 (confirmed), 2 operators 2 (probably true), the map source alone 3 (possibly true). An address no list carries is unknown, never clean.',
    hosts: hosts.length, listed_hosts: rows.filter((r) => r.lists.length).length, generated: new Date().toISOString(), served_from: 'store', count: lists.length, rows: lists };
  await recordVolume(fetched.filter((f) => f.ok).map((f) => ['list_' + f.L.id, f.entries]));
  return { hosts: hosts.length, listed: doc.listed_hosts, lists: lists.map((l) => l.id + ':' + (l.ok ? l.entries + '/' + l.matched : 'fail')), published: await putDoc('lists', doc), ms: Date.now() - t0 };
}
// ENISA Reference Security Incident Taxonomy (RSIT) classification.taxonomy/type for each map layer (G52), so rows and
// exports carry one shared vocabulary; ThreatFox rows follow the feed's own threat type.
export function rsitOf(layer, threat) {
  if (layer === 'c2') return 'malicious-code/c2-server';
  if (layer === 'url') return 'malicious-code/malware-distribution';
  if (layer === 'src') return 'information-gathering/scanner';
  const t = String(threat || '').toLowerCase();
  if (/botnet|_cc\b|c2/.test(t)) return 'malicious-code/c2-server';
  if (/payload|delivery|download/.test(t)) return 'malicious-code/malware-distribution';
  return 'other/undetermined';
}
