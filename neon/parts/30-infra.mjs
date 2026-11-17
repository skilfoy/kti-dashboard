// ---------------------------------------------------------------- malicious infrastructure
const LAYERS = ['c2', 'ioc', 'src', 'url'];
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
export const normIp = (s) => { const p = String(s || '').trim().split('.'); if (p.length !== 4) return ''; const ip = p.map((x) => String(parseInt(x, 10))).join('.'); return IPV4.test(ip) ? ip : ''; };
export function publicV4(ip) {
  if (!IPV4.test(ip)) return false;
  const [a, b, c] = ip.split('.').map(Number);
  // RFC 6890 special-purpose IPv4 blocks, exactly (documentation ranges are /24s, not their /16s).
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 192 && b === 88 && c === 99) || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113));
}
const ts = (v) => { if (!v) return null; const d = new Date(String(v).replace(' UTC', 'Z').replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(String(v)) || /UTC/.test(String(v)) ? '' : 'Z')); return isNaN(d) ? null : d.toISOString(); };
// URLhaus tags mix family names with file types, architectures, hosting and delivery labels; only family names
// colour the map. Known families are written the way abuse.ch's ThreatFox writes them, so layers agree.
const GENERIC = new Set(['32-bit', '64-bit', 'elf', 'mips', 'mipsel', 'arm', 'arm7', 'arm5', 'arm6', 'aarch64', 'arm64', 'x86', 'x86-64', 'x86_64', 'amd64', 'i686', 'sh4', 'm68k', 'ppc',
  'powerpc', 'spc', 'sparc', 'mpsl', 'exe', 'dll', 'zip', 'rar', '7z', 'doc', 'docx', 'xls', 'xlsx', 'pdf', 'js', 'vbs', 'ps1', 'bat', 'cmd', 'hta', 'lnk', 'iso', 'img', 'msi', 'apk',
  'jar', 'java', 'python', 'golang', 'rust', 'upx', 'packed', 'signed', 'ascii', 'sh', 'bash', 'shellscript', 'opendir', 'payload', 'dropper', 'loader', 'downloader', 'backdoor',
  'trojan', 'rat', 'stealer', 'infostealer', 'miner', 'coinminer', 'ddos', 'malware', 'botnet', 'c2', 'cc', 'ioc', 'censys', 'shodan', 'unknown', 'none', 'encrypted', 'base64',
  'powershell', 'script', 'gitlab', 'github', 'bitbucket', 'discord', 'telegram', 'dropbox', 'mediafire', 'google-drive', 'onedrive', 'pastebin', 'cdn', 'cheatsheet', 'fakeupdates',
  'clickfix', 'phishing', 'exploit', 'cve']);
const FAMILY = { mirai: 'Mirai', mozi: 'Mozi', gafgyt: 'Gafgyt', bashlite: 'Gafgyt', tsunami: 'Tsunami', asyncrat: 'AsyncRAT', remcos: 'Remcos', remcosrat: 'Remcos',
  quasarrat: 'Quasar RAT', quasar: 'Quasar RAT', njrat: 'njRAT', xworm: 'XWorm', dcrat: 'DCRat', lumma: 'Lumma Stealer', lummastealer: 'Lumma Stealer', vidar: 'Vidar',
  redline: 'RedLine Stealer', stealc: 'Stealc', amadey: 'Amadey', smokeloader: 'SmokeLoader', cobaltstrike: 'Cobalt Strike', sliver: 'Sliver', havoc: 'Havoc',
  netsupport: 'NetSupportManager RAT', screenconnect: 'ScreenConnect', connectwise: 'ScreenConnect', aisuru: 'Aisuru', kaiten: 'Kaiten', hajime: 'Hajime' };
export function familyOf(tags) {
  for (const raw of String(tags || '').split(',').map((x) => x.trim()).filter(Boolean)) {
    const t = raw.toLowerCase();
    if (GENERIC.has(t) || /^\d/.test(t) || t.length < 3 || /^(dropped-by-|ua-|cve-|exploit-)/.test(t)) continue;
    const key = t.replace(/[^a-z0-9]/g, '');
    return FAMILY[key] || (raw === t ? raw.charAt(0).toUpperCase() + raw.slice(1) : raw);
  }
  return 'unattributed';
}

export function parseFeodo(j) {
  if (!Array.isArray(j)) return [];
  return j.map((d) => ({ layer: 'c2', ip: normIp(d.ip_address), port: +d.port || 0, family: d.malware || 'unattributed', threat: 'botnet_cc', status: d.status || '',
    confidence: null, count: 1, tags: '', cc_feed: d.country || '', as_feed: d.as_name || '', first_seen: ts(d.first_seen), last_seen: ts(d.last_online),
    ref: `https://feodotracker.abuse.ch/browse/host/${normIp(d.ip_address)}/` })).filter((x) => x.ip && publicV4(x.ip));
}
export function parseThreatFox(j) {
  if (!j || typeof j !== 'object') return [];
  // The authenticated API (get_iocs) answers {query_status, data: [...]}; the retired export was keyed by IOC id.
  const items = Array.isArray(j.data) ? j.data.map((d) => [d && d.id, d]) : Object.entries(j).map(([id, arr]) => [id, Array.isArray(arr) ? arr[0] : arr]);
  const out = [];
  for (const [id, d] of items) {
    if (!d || d.ioc_type !== 'ip:port') continue;
    const [h, p] = String(d.ioc_value || d.ioc || '').split(':');
    const ip = normIp(h);
    if (!ip || !publicV4(ip)) continue;
    out.push({ layer: 'ioc', ip, port: +p || 0, family: d.malware_printable || d.malware || 'unattributed', threat: d.threat_type || '', status: '',
      confidence: d.confidence_level == null ? null : +d.confidence_level, count: 1, tags: Array.isArray(d.tags) ? d.tags.join(', ') : String(d.tags || ''),
      cc_feed: '', as_feed: '', first_seen: ts(d.first_seen_utc || d.first_seen), last_seen: ts(d.last_seen_utc || d.last_seen), ref: `https://threatfox.abuse.ch/ioc/${id}/` });
  }
  return out;
}
// DShield: /api/topips/records (rank, source, reports, targets) or /api/sources/attacks (ip, attacks, count, firstseen, lastseen).
export function parseDShield(j) {
  const arr = Array.isArray(j) ? j : j && typeof j === 'object' ? Object.values(j).find(Array.isArray) || [] : [];
  return arr.map((d) => {
    const ip = normIp(d.source || d.ip || d.ipaddress);
    const reports = +(d.reports ?? d.count ?? 0), targets = +(d.targets ?? d.attacks ?? 0);
    return { layer: 'src', ip, port: 0, family: 'scanning', threat: 'attack_source', status: '', confidence: null, count: reports || null, tags: targets ? `${targets} targets` : '',
      cc_feed: '', as_feed: '', first_seen: ts(d.firstseen), last_seen: ts(d.lastseen || d.updated), ref: `https://isc.sans.edu/ipinfo/${ip}` };
  }).filter((x) => x.ip && publicV4(x.ip));
}
export function csvLine(line) {
  const out = []; let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) { if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += ch; }
    else if (ch === '"') q = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}
// URLhaus online URLs whose host is an IPv4 literal, folded to one row per IP. Records come from the retired CSV export
// or the authenticated API (urls/recent): { id, added, url, status, threat, tags, link }.
// stats (optional) receives what the answer held before the fold: records, online, ip_literal (online with a public
// IPv4 host) and the newest and oldest date_added, so a shrinking layer can be traced to the answer itself.
export function foldUrlhaus(records, max = 600, stats = null) {
  const by = new Map();
  const st = stats || {};
  Object.assign(st, { records: 0, online: 0, ip_literal: 0, newest_added: null, oldest_added: null });
  for (const { id, added, url, status, threat, tags, link } of records) {
    st.records++;
    const at = ts(added);
    if (at && (!st.newest_added || at > st.newest_added)) st.newest_added = at;
    if (at && (!st.oldest_added || at < st.oldest_added)) st.oldest_added = at;
    if (status && status !== 'online') continue;
    st.online++;
    let host = '', port = 0;
    try { const u = new URL(url); host = u.hostname; port = +u.port || (u.protocol === 'https:' ? 443 : 80); } catch { continue; }
    const ip = normIp(host);
    if (!ip || !publicV4(ip) || ip !== host) continue;
    st.ip_literal++;
    const r = by.get(ip) || { layer: 'url', ip, port: 0, ports: new Map(), family: 'unattributed', threat: threat || 'malware_download', status: status || 'online', confidence: null,
      count: 0, tagc: new Map(), cc_feed: '', as_feed: '', first_seen: null, last_seen: null, ref: link || `https://urlhaus.abuse.ch/url/${id}/` };
    r.count++;
    r.ports.set(port, (r.ports.get(port) || 0) + 1);
    for (const t of String(tags || '').split(',').map((x) => x.trim()).filter(Boolean)) r.tagc.set(t, (r.tagc.get(t) || 0) + 1);
    const a = ts(added);
    if (a && (!r.last_seen || a > r.last_seen)) { r.last_seen = a; r.ref = link || r.ref; }
    if (a && (!r.first_seen || a < r.first_seen)) r.first_seen = a;
    by.set(ip, r);
  }
  return [...by.values()].sort((a, b) => b.count - a.count || String(b.last_seen).localeCompare(String(a.last_seen))).slice(0, max).map((r) => {
    const tags = [...r.tagc.entries()].sort((a, b) => b[1] - a[1]).map((x) => x[0]);
    const { ports, tagc, ...rest } = r;
    return { ...rest, port: [...ports.entries()].sort((a, b) => b[1] - a[1])[0][0], tags: tags.slice(0, 6).join(', '), family: familyOf(tags.join(',')) };
  });
}
export function parseUrlhaus(text, max = 600) {
  const recs = [];
  for (const line of String(text || '').split('\n')) {
    if (!line || line[0] === '#') continue;
    const f = csvLine(line.trim());
    if (f.length < 8) continue;
    const [id, added, url, status, , threat, tags, link] = f;
    recs.push({ id, added, url, status: status || 'online', threat, tags, link });
  }
  return foldUrlhaus(recs, max);
}
export function parseUrlhausApi(j, max = 600, stats = null) {
  const arr = j && Array.isArray(j.urls) ? j.urls : [];
  return foldUrlhaus(arr.map((u) => ({ id: u.id, added: u.date_added, url: u.url, status: u.url_status, threat: u.threat, tags: Array.isArray(u.tags) ? u.tags.join(',') : String(u.tags || ''),
    link: u.urlhaus_reference })), max, stats);
}

// abuse.ch closed its keyless ThreatFox and URLhaus exports: both answer HTTP 410 Gone from 21 October 2026, the day
// abuse.ch revised its terms of use. ThreatFox, URLhaus and MalwareBazaar are now free for not-for-profit use through an
// Auth-Key from auth.abuse.ch, and commercial use may need a Spamhaus subscription; Feodo Tracker, SSL Blacklist and
// YARAify stay free for any use (CC0). With ABUSECH_AUTH_KEY in the function environment the two layers read the
// authenticated APIs (ThreatFox get_iocs for one day; URLhaus urls/recent); without it they report the gate and draw nothing.
export const ABUSE_GATE = 'abuse.ch closed the keyless ThreatFox and URLhaus exports on 21 October 2026 (HTTP 410) and limited free use to not-for-profit purposes through an Auth-Key from auth.abuse.ch; this layer stays dark until a key is set';
export const ABUSE_API = { ioc: 'https://threatfox-api.abuse.ch/api/v1/', url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/' };
export function abuseFetch(layer) {
  const key = ENV().ABUSECH_AUTH_KEY || '';
  if (!key) return Promise.resolve({ ok: false, status: 410, ms: 0, error: ABUSE_GATE, gated: true });
  if (layer === 'ioc') return cachedGet(ABUSE_API.ioc, { method: 'POST', as: 'json', timeout: 25000, body: JSON.stringify({ query: 'get_iocs', days: 1 }),
    headers: { 'Auth-Key': key, 'content-type': 'application/json' } });
  return cachedGet(ABUSE_API.url, { as: 'json', timeout: 25000, headers: { 'Auth-Key': key } });
}
// A light request for the health job: ThreatFox's IOC-type list and URLhaus's single newest URL.
export function abuseProbe(layer) {
  const key = ENV().ABUSECH_AUTH_KEY || '';
  if (!key) return Promise.resolve({ ok: false, status: 410, ms: 0, error: ABUSE_GATE, gated: true });
  if (layer === 'ioc') return get(ABUSE_API.ioc, { method: 'POST', as: 'json', timeout: 12000, body: JSON.stringify({ query: 'types' }), headers: { 'Auth-Key': key, 'content-type': 'application/json' } });
  return get(ABUSE_API.url + 'limit/1/', { as: 'json', timeout: 12000, headers: { 'Auth-Key': key } });
}

const FEEDS = {
  c2: { url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', as: 'json', parse: (r) => parseFeodo(r.json), name: 'abuse.ch Feodo Tracker' },
  ioc: { url: ABUSE_API.ioc, fetch: () => abuseFetch('ioc'), parse: (r) => parseThreatFox(r.json), name: 'abuse.ch ThreatFox' },
  src: { url: 'https://isc.sans.edu/api/topips/records/100?json', as: 'json', parse: (r) => parseDShield(r.json), name: 'SANS ISC DShield' },
  url: { url: ABUSE_API.url, fetch: () => abuseFetch('url'), parse: (r) => parseUrlhausApi(r.json, 600, (r.answer = {})), name: 'abuse.ch URLhaus' },
};

// Geolocation: ip-api.com batch (100 per request; the free tier allows 15 batch requests a minute and reports the
// remainder in X-Rl and the reset in X-Ttl), then GeoJS for anything ip-api did not answer.
export async function geolocate(ips, { maxIpApi = 7 } = {}) {
  const out = new Map();
  let calls = 0, limited = false;
  for (let i = 0; i < ips.length && calls < maxIpApi && !limited; i += 100) {
    const chunk = ips.slice(i, i + 100);
    calls++;
    const r = await get('http://ip-api.com/batch?fields=status,message,query,country,countryCode,regionName,city,lat,lon,isp,as,asname', {
      method: 'POST', body: JSON.stringify(chunk), headers: { 'content-type': 'application/json' }, as: 'json', timeout: 15000 });
    if (r.status === 429) { limited = true; break; }
    if (!r.ok || !Array.isArray(r.json)) break;
    for (const g of r.json) {
      if (!g || !g.query) continue;
      if (g.status === 'success' && isFinite(g.lat) && isFinite(g.lon)) {
        out.set(g.query, { ok: true, lat: g.lat, lon: g.lon, cc: g.countryCode || '', country: g.country || '', region: g.regionName || '', city: g.city || '',
          asn: String(g.as || '').split(' ')[0] || '', as_name: g.asname || String(g.as || '').split(' ').slice(1).join(' '), isp: g.isp || '', provider: 'ip-api.com' });
      } else out.set(g.query, { ok: false, provider: 'ip-api.com' });
    }
    const rl = r.headers && +r.headers.get('x-rl');
    if (r.headers && r.headers.get('x-rl') != null && rl <= 0) limited = true;
  }
  const rest = ips.filter((ip) => !out.has(ip) || !out.get(ip).ok).slice(0, 300);
  for (let i = 0; i < rest.length; i += 25) {
    const r = await get('https://get.geojs.io/v1/ip/geo.json?ip=' + rest.slice(i, i + 25).join(','), { as: 'json', timeout: 15000 });
    if (!r.ok) break;
    for (const g of [].concat(r.json || [])) {
      const lat = parseFloat(g.latitude), lon = parseFloat(g.longitude);
      if (g && g.ip && isFinite(lat) && isFinite(lon) && !(lat === 0 && lon === 0)) {
        out.set(g.ip, { ok: true, lat, lon, cc: g.country_code || '', country: g.country || '', region: g.region || '', city: g.city || '',
          asn: g.asn ? 'AS' + g.asn : '', as_name: g.organization_name || g.organization || '', isp: g.organization_name || '', provider: 'geojs.io' });
      } else if (g && g.ip && !out.has(g.ip)) out.set(g.ip, { ok: false, provider: 'geojs.io' });
    }
  }
  return { geo: out, ipapi_calls: calls, limited };
}

export async function jobInfra() {
  const t0 = Date.now();
  const fetched = {};
  await Promise.all(LAYERS.map(async (layer) => {
    const f = FEEDS[layer];
    const r = { ...(await (f.fetch ? f.fetch() : cachedGet(f.url, { as: f.as, timeout: 25000 }))) };
    let rows = [];
    // The abuse.ch APIs answer 200 with query_status set when the key is refused or nothing matched.
    if (r.ok && r.json && r.json.query_status && !['ok', 'no_results'].includes(r.json.query_status)) { r.ok = false; r.error = 'abuse.ch query_status ' + String(r.json.query_status).slice(0, 60); }
    try { rows = r.ok ? f.parse(r) : []; } catch (e) { r.ok = false; r.error = String(e.message || e); }
    fetched[layer] = { ok: r.ok && rows.length > 0, status: r.status, ms: r.ms, error: r.error || (r.ok && !rows.length ? 'no rows' : undefined), gated: !!r.gated, rows, answer: r.answer };
  }));
  const collapsed = await infraCollapse(fetched);
  // Geolocate what the cache does not hold (failures retried after a day), C2 first.
  const all = LAYERS.flatMap((l) => fetched[l].rows);
  const uniq = [...new Set(all.map((x) => x.ip))];
  const cached = new Set();
  for (let i = 0; i < uniq.length; i += 2000) {
    const part = uniq.slice(i, i + 2000);
    for (const r of await sql(`SELECT host(ip) AS ip FROM ti.ip_geo WHERE ip = ANY($1::inet[]) AND ((ok AND fetched_at > now() - interval '30 days') OR fetched_at > now() - interval '1 day')`,
      [`{${part.join(',')}}`])) cached.add(r.ip);
  }
  const prio = { c2: 0, ioc: 1, src: 2, url: 3 };
  const need = [...new Set(all.slice().sort((a, b) => prio[a.layer] - prio[b.layer]).map((x) => x.ip).filter((ip) => !cached.has(ip)))];
  const g = need.length ? await geolocate(need) : { geo: new Map(), ipapi_calls: 0, limited: false };
  const geoRows = [...g.geo.entries()].map(([ip, v]) => ({ ip, ...v }));
  const seenAt = new Date().toISOString();
  const okLayers = LAYERS.filter((l) => fetched[l].ok);
  const infraRows = okLayers.flatMap((l) => fetched[l].rows.map(({ as_feed, ...x }) => x));
  // One row per key: a feed can list an address twice, or in two spellings of one inet (17 November 2026: four runs
  // failed with "ON CONFLICT DO UPDATE command cannot affect row a second time").
  await sqlTx([
    [`INSERT INTO ti.ip_geo (ip, ok, lat, lon, cc, country, region, city, asn, as_name, isp, provider, fetched_at)
      SELECT DISTINCT ON (ip::inet) ip::inet, ok, lat, lon, cc, country, region, city, asn, as_name, isp, provider, now()
      FROM jsonb_to_recordset($1::jsonb) AS x(ip text, ok boolean, lat real, lon real, cc text, country text, region text, city text, asn text, as_name text, isp text, provider text)
      ORDER BY ip::inet, ok DESC
      ON CONFLICT (ip) DO UPDATE SET ok = EXCLUDED.ok OR ti.ip_geo.ok,
        lat = CASE WHEN EXCLUDED.ok THEN EXCLUDED.lat ELSE ti.ip_geo.lat END, lon = CASE WHEN EXCLUDED.ok THEN EXCLUDED.lon ELSE ti.ip_geo.lon END,
        cc = CASE WHEN EXCLUDED.ok THEN EXCLUDED.cc ELSE ti.ip_geo.cc END, country = CASE WHEN EXCLUDED.ok THEN EXCLUDED.country ELSE ti.ip_geo.country END,
        region = CASE WHEN EXCLUDED.ok THEN EXCLUDED.region ELSE ti.ip_geo.region END, city = CASE WHEN EXCLUDED.ok THEN EXCLUDED.city ELSE ti.ip_geo.city END,
        asn = CASE WHEN EXCLUDED.ok THEN EXCLUDED.asn ELSE ti.ip_geo.asn END, as_name = CASE WHEN EXCLUDED.ok THEN EXCLUDED.as_name ELSE ti.ip_geo.as_name END,
        isp = CASE WHEN EXCLUDED.ok THEN EXCLUDED.isp ELSE ti.ip_geo.isp END, provider = CASE WHEN EXCLUDED.ok THEN EXCLUDED.provider ELSE ti.ip_geo.provider END,
        fetched_at = now()`, [geoRows]],
    [`INSERT INTO ti.infra (layer, ip, port, family, threat, status, confidence, count, tags, ref, cc_feed, first_seen, last_seen, first_obs, last_obs)
      SELECT DISTINCT ON (layer, ip::inet, port) layer, ip::inet, port, family, threat, status, confidence, count, tags, ref, cc_feed, first_seen, last_seen, $2::timestamptz, $2::timestamptz
      FROM jsonb_to_recordset($1::jsonb) AS x(layer text, ip text, port int, family text, threat text, status text, confidence int, count int, tags text, ref text, cc_feed text,
        first_seen timestamptz, last_seen timestamptz)
      ORDER BY layer, ip::inet, port, last_seen DESC NULLS LAST
      ON CONFLICT (layer, ip, port) DO UPDATE SET family = EXCLUDED.family, threat = EXCLUDED.threat, status = EXCLUDED.status, confidence = EXCLUDED.confidence,
        count = EXCLUDED.count, tags = EXCLUDED.tags, ref = EXCLUDED.ref, cc_feed = EXCLUDED.cc_feed, first_seen = coalesce(EXCLUDED.first_seen, ti.infra.first_seen),
        last_seen = coalesce(EXCLUDED.last_seen, ti.infra.last_seen), last_obs = $2::timestamptz`, [infraRows, seenAt]],
  ]);
  // Current set: what each feed listed this run; a feed that failed keeps its last 3 hours of rows, flagged stale.
  // A collapsed layer (below a fifth of its baseline) keeps the same 3 hours of earlier rows, flagged stale, beside what it
  // listed now: one thin answer does not empty the layer, and a lasting drop shows once those rows age out.
  const failed = LAYERS.filter((l) => !fetched[l].ok || collapsed[l]);
  const nodes = await sql(`SELECT i.layer, host(i.ip) AS ip, i.port, i.family, i.threat, i.status, i.confidence, i.count, i.tags, i.ref, i.first_seen, i.last_seen, i.first_obs,
      coalesce(nullif(g.cc, ''), nullif(i.cc_feed, '')) AS cc, g.lat, g.lon, g.city, g.asn, g.as_name, (i.last_obs < $1::timestamptz) AS stale,
      l.lists, l.ipsum, l.tor
    FROM ti.infra i LEFT JOIN ti.ip_geo g ON g.ip = i.ip AND g.ok LEFT JOIN ti.ip_list l ON l.ip = i.ip
    WHERE i.last_obs = $1::timestamptz OR (i.layer = ANY($2::text[]) AND i.last_obs > now() - interval '3 hours')`, [seenAt, `{${failed.join(',')}}`]);
  // Daily rollup for trends (today's row is rewritten each run).
  const roll = new Map();
  for (const n of nodes) { const k = n.layer + '|' + (n.cc || '??') + '|' + n.family; roll.set(k, (roll.get(k) || 0) + 1); }
  const rollRows = [...roll.entries()].map(([k, n]) => { const [layer, cc, family] = k.split('|'); return { layer, cc, family, n }; });
  const tr = await sqlTx([
    [`DELETE FROM ti.infra_daily WHERE day = (now() AT TIME ZONE 'UTC')::date`],
    [`INSERT INTO ti.infra_daily (day, layer, cc, family, n) SELECT (now() AT TIME ZONE 'UTC')::date, layer, cc, family, n FROM jsonb_to_recordset($1::jsonb) AS x(layer text, cc text, family text, n int)`, [rollRows]],
    [`SELECT to_char(day, 'YYYY-MM-DD') AS d, layer, sum(n)::int AS n FROM ti.infra_daily WHERE day > (now() AT TIME ZONE 'UTC')::date - 30 GROUP BY 1, 2 ORDER BY 1, 2`],
    // Earliest first observation still held (rows go after 30 days unseen): how long the collector has been watching.
    [`SELECT min(first_obs) AS since FROM ti.infra`],
  ]);
  const trend = tr[2];
  const obsSince = tr[3] && tr[3][0] ? tr[3][0].since : null;
  const doc = buildThreatmap({ nodes, fetched, trend, obsSince, collapsed, geoStats: { cached: cached.size, looked_up: g.geo.size, ipapi_calls: g.ipapi_calls, rate_limited: g.limited, pending: need.length - g.geo.size } });
  const published = await putDoc('threatmap', doc);
  await recordVolume(LAYERS.filter((l) => fetched[l].ok).map((l) => ['infra_' + l, fetched[l].rows.length]));
  return { layers: Object.fromEntries(LAYERS.map((l) => [l, { ok: fetched[l].ok, status: fetched[l].status, rows: fetched[l].rows.length, error: fetched[l].error,
      ...(fetched[l].answer ? { answer: fetched[l].answer } : {}), ...(collapsed[l] ? { collapsed: collapsed[l] } : {}) }])),
    collapsed: Object.keys(collapsed).length ? Object.keys(collapsed) : undefined, nodes: nodes.length, geolocated: doc.geolocated, geo: doc.geo, published, ms: Date.now() - t0 };
}

// Collapse guard (in the spirit of the blogs job's): a layer that answered with rows but fewer than a fifth of its volume
// baseline for this UTC hour (volumeFlag silence, judged after seven days of runs). Returns { layer: { n, baseline,
// basis } }. The run stays ok, since the drop may be real upstream (URLhaus, 2 November 2026); the layer and the run
// detail name it.
export async function infraCollapse(fetched, hour = new Date().getUTCHours()) {
  const out = {};
  let base = [];
  try { base = await sql(VOLUME_BASELINE_SQL, [`{${LAYERS.map((l) => 'infra_' + l).join(',')}}`, hour]); } catch { return out; }
  for (const b of base) {
    const l = b.feed.slice(6), f = fetched[l];
    if (!f || !f.ok) continue;
    const v = volumeFlag({ ...b, n: f.rows.length });
    if (v.flag === 'silence') out[l] = { n: v.n, baseline: v.baseline, basis: v.basis };
  }
  return out;
}

// The map draws at most MAP_CAP nodes per layer (ThreatFox newest first, URLhaus by URL count); the layer, country and
// family counts cover every listed host. Empty fields are left out to keep the document small.
const MAP_CAP = { c2: 1000, ioc: 1200, src: 100, url: 500 };
const compact = (o) => { for (const k of Object.keys(o)) if (o[k] == null || o[k] === '' || o[k] === false) delete o[k]; return o; };
// New in the last 24 hours: listed by the source in that window (its own first-seen time), or first observed by the
// collector in it once the collector has watched for a full day. Before then a first observation only marks when the
// collector started, so it does not count; the live fallback has no observations and uses source times alone.
const DAY_MS = 86400000;
const msOf = (v) => (v ? new Date(v).getTime() : NaN);
export function buildThreatmap({ nodes, fetched, trend, geoStats, obsSince = null, collapsed = {} }) {
  const now = Date.now();
  const since = msOf(obsSince), baseline = isFinite(since) && now - since >= DAY_MS;
  const within = (v) => { const t = msOf(v); return isFinite(t) && now - t < DAY_MS; };
  const rows = [], byCc = new Map(), fam = new Map(), stats = {}, drawn = { c2: 0, ioc: 0, src: 0, url: 0 };
  nodes = nodes.slice().sort((a, b) => (a.layer === 'url' && b.layer === 'url' ? (b.count || 0) - (a.count || 0) : String(b.first_seen || '').localeCompare(String(a.first_seen || ''))));
  for (const l of LAYERS) {
    const c = collapsed[l];
    stats[l] = { name: FEEDS[l].name, url: FEEDS[l].url, ok: fetched[l].ok, status: fetched[l].status, listed: fetched[l].rows.length, nodes: 0, geolocated: 0, new_24h: 0,
      ...(fetched[l].gated ? { gated: true, note: ABUSE_GATE } : !fetched[l].ok ? { note: String(fetched[l].error || 'HTTP ' + fetched[l].status).slice(0, 200) }
        : c ? { collapsed: c, note: `listed ${c.n} against a baseline of ${c.baseline} (${c.basis === 'hour' ? 'same UTC hour' : 'all hours'}); hosts seen in the last 3 hours are kept, flagged stale` } : {}) };
  }
  // Layers naming each address, for the independence count behind credibility (38-lists.mjs).
  const ipLayers = new Map();
  for (const n of nodes) { const s = ipLayers.get(n.ip) || new Set(); s.add(n.layer); ipLayers.set(n.ip, s); }
  const credCount = { 1: 0, 2: 0, 3: 0 };
  for (const n of nodes) {
    const s = stats[n.layer];
    s.nodes++;
    const fresh = within(n.first_seen) || (baseline && within(n.first_obs));
    if (fresh) s.new_24h++;
    if (n.cc) { const c = byCc.get(n.cc) || { kind: 'country', cc: n.cc, c2: 0, ioc: 0, src: 0, url: 0, total: 0 }; c[n.layer]++; c.total++; byCc.set(n.cc, c); }
    const fk = n.layer + '|' + n.family;
    fam.set(fk, (fam.get(fk) || 0) + 1);
    if (n.lat == null || n.lon == null) continue;
    s.geolocated++;
    const lists = Array.isArray(n.lists) ? n.lists : [];
    const cr = credibility({ layers: [...(ipLayers.get(n.ip) || [n.layer])], lists });
    credCount[cr.cred]++;
    if (++drawn[n.layer] > MAP_CAP[n.layer]) continue;
    rows.push(compact({ kind: 'node', layer: n.layer, ip: n.ip, port: n.port || null, lat: r2(n.lat), lon: r2(n.lon), cc: n.cc, city: n.city, asn: n.asn || null, as_name: n.as_name,
      family: n.family || 'unattributed', threat: n.threat, status: n.status, confidence: n.confidence, count: n.layer === 'src' || n.layer === 'url' ? n.count : null,
      tags: n.layer === 'url' ? n.tags : null, first_seen: n.first_seen, last_seen: n.last_seen, obs: n.first_obs || null, new: !!fresh, stale: !!n.stale, ref: n.ref,
      lb: lists.length ? lists.join(',') : null, ipsum: n.ipsum || null, tor: !!n.tor, cred: cr.cred, rel: cr.rel, sc: cr.score, rsit: rsitOf(n.layer, n.threat) }));
  }
  for (const l of LAYERS) stats[l].drawn = Math.min(drawn[l], MAP_CAP[l]);
  for (const [k, n] of fam) { const [layer, family] = k.split('|'); rows.push({ kind: 'family', layer, family, n }); }
  rows.push(...byCc.values());
  for (const t of trend || []) rows.push({ kind: 'trend', d: t.d, layer: t.layer, n: t.n });
  const geolocated = rows.filter((r) => r.kind === 'node').length;
  return { source: 'abuse.ch Feodo Tracker, ThreatFox and URLhaus; SANS ISC DShield; geolocation by ip-api.com and GeoJS', generated: new Date().toISOString(), served_from: 'store',
    layers: stats, nodes: nodes.length, geolocated, geo: geoStats, new_basis: baseline ? 'source+collector' : 'source', credibility: credCount,
    time_fields: { source: ['first_seen', 'last_seen'], observation: ['obs'] }, taxonomy: 'ENISA Reference Security Incident Taxonomy (RSIT): classification.taxonomy/type in rsit',
    observing_since: isFinite(since) ? new Date(since).toISOString() : null, count: rows.length, rows };
}

