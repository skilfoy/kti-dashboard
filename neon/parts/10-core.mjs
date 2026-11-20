// threat-feeds collector. Runs as a Neon Function (Node 24) on branch main of Neon project threat-intel, loaded by
// neon/loader.mjs from the private ti-docs bucket after a SHA-256 check. A schedule trigger POSTs / every 15 minutes;
// the jobs keep state in Postgres (schema ti, role ti_app, SQL over HTTP) and publish gzipped JSON documents to the
// bucket under docs/. The threat-feeds Vercel service reads those documents through GET /doc/<name>, authenticating
// with its Vercel OIDC token. No npm dependencies: node:crypto, node:zlib and fetch only.
//
//   gdelt      GDELT 2.0 15-minute exports, incremental: armed-actor CAMEO material conflict per slot (country, 1-degree
//              cell, top events, actor-to-action flows); publishes the 24h window with a 48h baseline and a 30-day
//              per-country baseline (gdelt-w24b48) and 30 days of daily country totals (gdelt-series30).
//   infra      reported malicious infrastructure: abuse.ch Feodo Tracker C2, ThreatFox ip:port IOCs, DShield top
//              attacking sources, URLhaus online malware hosts (ThreatFox and URLhaus through abuse.ch's authenticated
//              APIs since 21 October 2026, dark without ABUSECH_AUTH_KEY); IP geolocation cached in Postgres (ip-api.com
//              batch, GeoJS fallback); publishes threatmap.
//   health     reachability of every upstream; uptime over 24h and 7d; DShield Infocon; collector run state (health).
//   snap       last-good copies of the live endpoints the dashboard reads (snap-ransomware, snap-cyberattacks,
//              snap-epss, snap-threatfox); press-reported attacks are normalized by the cyber part (35-cyber.mjs);
//              hourly, the context feeds of 36-context.mjs (snap-lanes: Lanes relationship temperatures and daily
//              pages; snap-ofac: OFAC Recent Actions).
//   ioda       IODA internet-outage events by country (ioda).
//   retention  prunes rows past their windows.
//   lists      free IPv4 blocklists checked against the mapped hosts, for corroboration and credibility (38-lists.mjs).
//   fires, maritime, leaksites, ransompay, unit42, genioc, lanesreg, blogs, links, sec8k
//              public collection added 22 October 2026 (37-intel, 37b-sea, 37c-reg, 37d-sec); on-demand enrichment behind GET /enrich
//              (39-enrich.mjs). FIRMS_MAP_KEY, CLOQ_API_KEY, SEC_USER_AGENT and ABUSECH_AUTH_KEY (when set) live only in
//              this function's environment.
import { createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, sign, timingSafeEqual, verify } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { gzipSync, gunzipSync, inflateRawSync } from 'node:zlib';

export const VERSION = '2026-11-20.4';
const UA = 'threat-feeds-collector/1.0 (+https://github.com/skilfoy; OSINT dashboard collector)';
const ENV = () => process.env;
const BUCKET = () => ENV().TI_BUCKET || 'ti-docs';

// ---------------------------------------------------------------- utilities
const r2 = (x) => Math.round(x * 100) / 100;
export function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
}

export async function fetchT(url, { timeout = 15000, headers = {}, ...opts } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    return await fetch(url, { ...opts, headers: { 'user-agent': UA, ...headers }, signal: ctrl.signal });
  } finally { clearTimeout(t); }
}

// GET returning {ok, status, ms, text|json|buf, error}. Never throws.
export async function get(url, { as = 'text', timeout = 15000, headers = {}, method = 'GET', body } = {}) {
  const t0 = Date.now();
  try {
    const r = await fetchT(url, { method, headers, body, timeout });
    const out = { ok: r.ok, status: r.status, ms: 0, headers: r.headers };
    if (as === 'buf') out.buf = Buffer.from(await r.arrayBuffer());
    else {
      out.text = await r.text();
      if (as === 'json') { try { out.json = JSON.parse(out.text); } catch { out.json = null; if (out.ok) { out.ok = false; out.error = 'invalid JSON'; } } }
    }
    out.ms = Date.now() - t0;
    return out;
  } catch (e) {
    return { ok: false, status: 0, ms: Date.now() - t0, error: String((e && e.name === 'AbortError') ? 'timeout' : (e && e.message) || e) };
  }
}

// Upstream responses shared by the jobs of one scheduled run (ThreatFox feeds both infra and snap).
const RUN_CACHE = new Map();
export function cachedGet(url, opts = {}) {
  const hit = RUN_CACHE.get(url);
  if (hit && Date.now() - hit.at < 120000) return hit.p;
  const p = get(url, opts);
  RUN_CACHE.set(url, { at: Date.now(), p });
  if (RUN_CACHE.size > 50) RUN_CACHE.delete(RUN_CACHE.keys().next().value);
  return p;
}

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}

// ---------------------------------------------------------------- Postgres over HTTP (Neon SQL endpoint)
// Same wire protocol as @neondatabase/serverless: POST https://api.<region host>/sql with the connection string in a
// header; rows come back as raw text in array mode and are parsed here by type OID.
// TI_SQL_URL and TI_SQL_TOKEN (3.1.0) point the collector at the KTI SQL gateway on the Oracle server, which answers the
// same contract with a bearer token; without them the collector uses Neon's endpoint for DATABASE_URL.
let sqlConf = null;
function sqlTarget() {
  const E = ENV(), key = (E.TI_SQL_URL || '') + '|' + (E.DATABASE_URL || '');
  if (sqlConf && sqlConf.key === key) return sqlConf;
  if (E.TI_SQL_URL) {
    if (!E.TI_SQL_TOKEN) throw new Error('TI_SQL_TOKEN is not set');
    sqlConf = { key, url: E.TI_SQL_URL, headers: { authorization: 'Bearer ' + E.TI_SQL_TOKEN }, via: 'gateway' };
    return sqlConf;
  }
  const cs = E.DATABASE_URL;
  if (!cs) throw new Error('DATABASE_URL is not set');
  const u = new URL(cs);
  sqlConf = { key, url: 'https://' + u.hostname.replace(/^[^.]+\./, 'api.') + '/sql', headers: { 'Neon-Connection-String': cs }, via: 'neon' };
  return sqlConf;
}
const isoTs = (v) => { const d = new Date(String(v).replace(' ', 'T').replace(/([+-]\d\d)$/, '$1:00')); return isNaN(d) ? v : d.toISOString(); };
const PARSE = { 16: (v) => v === 't' || v === 'true', 20: Number, 21: Number, 23: Number, 26: Number, 700: Number, 701: Number, 1700: Number, 114: JSON.parse, 3802: JSON.parse, 1184: isoTs, 1114: isoTs };
// Bytes of query results read this instance (response text), for the transfer budget; runJob records a job's share.
export const DB_IO = { calls: 0, bytes: 0, sent: 0 };
function rowsOf(res) {
  const names = res.fields.map((f) => f.name);
  const ps = res.fields.map((f) => PARSE[f.dataTypeID] || ((v) => v));
  return res.rows.map((r) => { const o = {}; for (let i = 0; i < names.length; i++) o[names[i]] = r[i] == null ? null : ps[i](r[i]); return o; });
}
const prep = (p) => (p == null ? null : p instanceof Date ? p.toISOString() : typeof p === 'object' ? JSON.stringify(p) : String(p));
async function sqlPost(body) {
  const { url, headers } = sqlTarget();
  const payload = JSON.stringify(body);
  DB_IO.sent += payload.length;
  const r = await fetchT(url, { method: 'POST', timeout: 40000, body: payload,
    headers: { ...headers, 'Neon-Raw-Text-Output': 'true', 'Neon-Array-Mode': 'true', 'content-type': 'application/json' } });
  const text = await r.text();
  DB_IO.calls++; DB_IO.bytes += text.length;
  let j = null;
  try { j = JSON.parse(text); } catch { /* handled below */ }
  if (!r.ok || !j) throw new Error(`sql ${r.status}: ${(j && j.message) || text.slice(0, 300)}${j && j.code ? ' [' + j.code + ']' : ''}`);
  return j;
}
export async function sql(query, params = []) { return rowsOf(await sqlPost({ query, params: params.map(prep) })); }
// Several statements in one transaction (one HTTP round trip). Each item is [query, params].
export async function sqlTx(list) {
  if (!list.length) return [];
  const j = await sqlPost({ queries: list.map(([query, params = []]) => ({ query, params: params.map(prep) })) });
  if (!Array.isArray(j.results)) throw new Error('sql batch: unexpected response');
  return j.results.map(rowsOf);
}

// ---------------------------------------------------------------- object storage (S3 SigV4, path style)
const sha256hex = (b) => createHash('sha256').update(b).digest('hex');
const hmac = (k, s) => createHmac('sha256', k).update(s).digest();
const encKey = (k) => k.split('/').map((s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())).join('/');
// AWS Signature Version 4 headers for one S3 request (exported for the test vector).
export function sigv4({ method, host, path, query = '', headers = {}, payloadHash, amzDate, region, keyId, secret }) {
  const day = amzDate.slice(0, 8);
  const h = { host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = String(v).trim();
  const names = Object.keys(h).sort();
  const signed = names.join(';');
  const creq = [method, path, query, names.map((n) => n + ':' + h[n] + '\n').join(''), signed, payloadHash].join('\n');
  const scope = `${day}/${region}/s3/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(creq)].join('\n');
  let k = hmac('AWS4' + secret, day); k = hmac(k, region); k = hmac(k, 's3'); k = hmac(k, 'aws4_request');
  const sig = createHmac('sha256', k).update(sts).digest('hex');
  const out = { ...h, authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signed}, Signature=${sig}` };
  delete out.host;
  return out;
}
async function s3(method, key, { body, contentType } = {}) {
  const e = ENV();
  if (!e.AWS_ENDPOINT_URL_S3 || !e.AWS_ACCESS_KEY_ID) throw new Error('object storage credentials are not set');
  const ep = new URL(e.AWS_ENDPOINT_URL_S3);
  const path = '/' + BUCKET() + '/' + encKey(key);
  const buf = body == null ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body : Buffer.from(body);
  const amzDate = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const headers = sigv4({ method, host: ep.host, path, headers: contentType ? { 'content-type': contentType } : {}, payloadHash: sha256hex(buf), amzDate,
    region: e.AWS_REGION || 'us-east-1', keyId: e.AWS_ACCESS_KEY_ID, secret: e.AWS_SECRET_ACCESS_KEY });
  return fetchT(ep.origin + path, { method, headers, body: method === 'PUT' ? buf : undefined, timeout: 30000 });
}
export async function s3Get(key) {
  const r = await s3('GET', key);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`storage GET ${key}: HTTP ${r.status}`);
  return { buf: Buffer.from(await r.arrayBuffer()), modified: r.headers.get('last-modified'), type: r.headers.get('content-type') };
}
export async function s3Put(key, buf, contentType) {
  const r = await s3('PUT', key, { body: buf, contentType });
  if (!r.ok) throw new Error(`storage PUT ${key}: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
}
// Reference files (ref/*): the gzipped copy <key>.gz (pushed with op=push&gz=1) first, the plain object when it is missing.
// Bucket reads count against the Neon plan's monthly transfer; the world atlas alone was a third of it (756 KB a read).
export async function refGet(key) {
  const z = await s3Get(key + '.gz');
  if (z) return { ...z, buf: gunzipSync(z.buf), gz: true };
  return s3Get(key);
}
// Documents: gzipped JSON at docs/<name>.json.gz.
export async function putDoc(name, obj) {
  const raw = Buffer.from(JSON.stringify(obj));
  const gz = gzipSync(raw, { level: 9 });
  await s3Put(`docs/${name}.json.gz`, gz, 'application/gzip');
  return { name, bytes: raw.length, gz: gz.length };
}
export async function getDoc(name) {
  const o = await s3Get(`docs/${name}.json.gz`);
  if (!o) return null;
  return JSON.parse(gunzipSync(o.buf).toString('utf8'));
}

// ---------------------------------------------------------------- geography: ISO-2 country at a point
// world-atlas 50m (Natural Earth, quantized TopoJSON) and the ISO numeric map are read once from ref/ in the bucket.
let GEO = null;
export function decodeTopo(topo, objectName) {
  const { scale: [sx, sy], translate: [tx, ty] } = topo.transform;
  const arcs = topo.arcs.map((a) => { let x = 0, y = 0; return a.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; }); });
  const ring = (idx) => {
    const out = [];
    for (const i of idx) {
      const a = i < 0 ? arcs[~i].slice().reverse() : arcs[i];
      for (let k = out.length ? 1 : 0; k < a.length; k++) out.push(a[k]);
    }
    return out;
  };
  return topo.objects[objectName].geometries.map((g) => ({ id: g.id, name: g.properties && g.properties.name,
    polys: g.type === 'Polygon' ? [g.arcs.map(ring)] : g.type === 'MultiPolygon' ? g.arcs.map((p) => p.map(ring)) : [] }));
}
const NAMED = { Kosovo: 'XK', Somaliland: 'SO', 'N. Cyprus': 'CY' };
export function buildGeo(topo, num2iso) {
  const index = [];
  for (const f of decodeTopo(topo, 'countries')) {
    const iso = f.id != null ? num2iso[String(+f.id)] : NAMED[f.name];
    if (!iso) continue;
    for (const rings of f.polys) {
      if (!rings.length || !rings[0].length) continue;
      let x0 = 180, x1 = -180, y0 = 90, y1 = -90;
      for (const [x, y] of rings[0]) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
      index.push({ iso, rings, x0, x1, y0, y1 });
    }
  }
  return { index, memo: new Map() };
}
// One read per instance however many callers ask at once (the GDELT pool parses files concurrently); a failed read is
// forgotten so the next caller tries again.
let GEO_P = null;
async function geo() {
  if (GEO) return GEO;
  return GEO_P || (GEO_P = (async () => {
    const [a, n] = await Promise.all([refGet('ref/countries-50m.json'), refGet('ref/num2iso.json')]);
    if (!a || !n) throw new Error('reference geography missing from the bucket (ref/countries-50m.json, ref/num2iso.json)');
    GEO = buildGeo(JSON.parse(a.buf.toString('utf8')), JSON.parse(n.buf.toString('utf8')));
    return GEO;
  })().catch((e) => { GEO_P = null; throw e; }));
}
export function setGeo(g) { GEO = g; GEO_P = null; }
function inRing(x, y, ring) {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0], yi = ring[i][1], xj = ring[j][0], yj = ring[j][1];
    if (((yi > y) !== (yj > y)) && (x < ((xj - xi) * (y - yi)) / (yj - yi) + xi)) inside = !inside;
  }
  return inside;
}
function ringDist2(x, y, ring, kx) {
  let best = Infinity;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const ax = ring[j][0] * kx, ay = ring[j][1], bx = ring[i][0] * kx, by = ring[i][1], px = x * kx;
    const dx = bx - ax, dy = by - ay, l2 = dx * dx + dy * dy;
    let t = l2 ? ((px - ax) * dx + (y - ay) * dy) / l2 : 0;
    t = t < 0 ? 0 : t > 1 ? 1 : t;
    const ex = ax + t * dx - px, ey = ay + t * dy - y, d2 = ex * ex + ey * ey;
    if (d2 < best) best = d2;
  }
  return best;
}
const NEAR = 0.36; // about 40 km: coastal geocodes that a generalized boundary leaves offshore
export function isoAt(G, lon, lat) {
  if (!isFinite(lon) || !isFinite(lat)) return '';
  const key = Math.round(lon * 100) + ',' + Math.round(lat * 100);
  const hit = G.memo.get(key);
  if (hit !== undefined) return hit;
  let v = '';
  for (const p of G.index) {
    if (lon < p.x0 || lon > p.x1 || lat < p.y0 || lat > p.y1) continue;
    if (!inRing(lon, lat, p.rings[0])) continue;
    let hole = false;
    for (let k = 1; k < p.rings.length; k++) if (inRing(lon, lat, p.rings[k])) { hole = true; break; }
    if (!hole) { v = p.iso; break; }
  }
  if (!v) {
    const kx = Math.cos((lat * Math.PI) / 180), pad = NEAR / Math.max(kx, 0.2);
    let bd = NEAR * NEAR;
    for (const p of G.index) {
      if (lon < p.x0 - pad || lon > p.x1 + pad || lat < p.y0 - NEAR || lat > p.y1 + NEAR) continue;
      const d = ringDist2(lon, lat, p.rings[0], kx);
      if (d < bd) { bd = d; v = p.iso; }
    }
  }
  if (G.memo.size > 300000) G.memo.clear();
  G.memo.set(key, v);
  return v;
}
export function gcKm(la1, lo1, la2, lo2) {
  const r = Math.PI / 180, dLa = (la2 - la1) * r, dLo = (lo2 - lo1) * r;
  const a = Math.sin(dLa / 2) ** 2 + Math.cos(la1 * r) * Math.cos(la2 * r) * Math.sin(dLo / 2) ** 2;
  return 12742 * Math.asin(Math.min(1, Math.sqrt(a)));
}

