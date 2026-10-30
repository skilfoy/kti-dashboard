// Read side of the collector's document store. The Neon Function "ti" (project threat-intel) serves the gzipped JSON
// documents it publishes to its private bucket at GET /doc/<name>. Callers authenticate with this deployment's Vercel
// OIDC token, which Vercel puts on every function request as x-vercel-oidc-token and the collector verifies against
// Vercel's published keys; no shared secret exists on either side. Documents are cached per warm instance (60 s on
// success, 15 s on failure). Failures come back as {ok:false, reason}; nothing here throws.
const zlib = require('zlib');

const DEFAULT_URL = 'https://br-summer-scene-b8t048y2-ti.compute.c-14.us-east-1.aws.neon.tech';
const collectorUrl = () => String(process.env.TI_COLLECTOR_URL || DEFAULT_URL).replace(/\/+$/, '');
const tokenOf = (req) => (req && req.headers && (req.headers['x-vercel-oidc-token'] || req.headers['X-Vercel-Oidc-Token'])) || process.env.VERCEL_OIDC_TOKEN || '';

async function call(req, path, { method = 'GET', body, timeout = 8000 } = {}) {
  const token = tokenOf(req);
  if (!token) return { ok: false, status: 0, reason: 'no_oidc_token' };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(collectorUrl() + path, { method, body, signal: ctrl.signal,
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json', 'user-agent': 'threat-feeds/1.0 (+https://github.com/skilfoy)' } });
    return { ok: r.ok, status: r.status, buf: Buffer.from(await r.arrayBuffer()), headers: r.headers };
  } catch (e) {
    return { ok: false, status: 0, reason: e && e.name === 'AbortError' ? 'timeout' : String((e && e.message) || e) };
  } finally { clearTimeout(t); }
}

const cache = new Map();
async function getDoc(req, name, { ttlMs = 60000, timeout = 8000 } = {}) {
  const hit = cache.get(name);
  if (hit && Date.now() - hit.at < (hit.v.ok ? ttlMs : Math.min(ttlMs, 15000))) return hit.v;
  const r = await call(req, '/doc/' + encodeURIComponent(name), { timeout });
  let v;
  if (!r.ok) {
    let detail = '';
    try { detail = JSON.parse(r.buf.toString('utf8')).error || ''; } catch { /* not JSON */ }
    v = { ok: false, status: r.status, reason: r.reason || (r.status === 404 ? 'missing' : 'http_' + r.status + (detail ? ': ' + detail : '')) };
  } else {
    try {
      const raw = r.buf[0] === 0x1f && r.buf[1] === 0x8b ? zlib.gunzipSync(r.buf) : r.buf;
      v = { ok: true, doc: JSON.parse(raw.toString('utf8')), modified: r.headers.get('x-doc-modified') || '' };
    } catch (e) { v = { ok: false, reason: 'unreadable document: ' + e.message }; }
  }
  cache.set(name, { at: Date.now(), v });
  return v;
}

// Minutes since an ISO time; Infinity when absent.
const ageMin = (iso) => { const t = Date.parse(iso); return isFinite(t) ? (Date.now() - t) / 60000 : Infinity; };

module.exports = { call, getDoc, ageMin, collectorUrl, hasToken: (req) => !!tokenOf(req) };
