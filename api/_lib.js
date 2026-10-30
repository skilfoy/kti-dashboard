// Shared helpers for the threat-feeds service. No external dependencies; Node 24 global fetch.
const UA = 'threat-feeds/1.0 (+https://github.com/skilfoy; OSINT dashboard proxy)';

// Open to any origin: the data is public and any page or tool may read it.
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// The collector's control plane (/api/admin: run jobs, push code, read raw documents) answers only on the project's
// generated *.vercel.app addresses, which Vercel Authentication (Standard Protection) keeps to the owner and the tools
// he authorizes. Every data route answers the same on every host. Vercel routes a request by its Host header, so a
// request that claims a *.vercel.app host is served, and protected, as that host.
function isOperator(req) {
  const host = String((req && req.headers && req.headers.host) || '').toLowerCase().split(':')[0];
  return host.endsWith('.vercel.app') || (process.env.TI_LOCAL_OPERATOR === '1' && (host === 'localhost' || host === '127.0.0.1'));
}

// ?enc=deflate64 on any endpoint: a 200 body travels as raw-deflate JSON in base64 with its decoded length, plus the
// header fields a reader shows before decoding. The dashboard reads its larger datasets this way, which keeps each
// connector answer to a fraction of the JSON size.
const zlib = require('zlib');
const HEAD = ['source', 'generated', 'served_from', 'age_min', 'stale', 'latest', 'count'];
function pack(body) {
  const raw = Buffer.from(JSON.stringify(body));
  const out = {};
  for (const k of HEAD) if (body[k] !== undefined) out[k] = body[k];
  return { ...out, enc: 'deflate-raw+base64', bytes: raw.length, data: zlib.deflateRawSync(raw, { level: 9 }).toString('base64') };
}

// Send JSON with edge caching: served from Vercel's CDN for `sMaxage` seconds,
// then revalidated in the background for `swr` seconds (stale-while-revalidate).
function sendJson(res, status, body, sMaxage = 900, swr = 3600) {
  if (status === 200 && body && typeof body === 'object' && res.__req && q(res.__req, 'enc', '') === 'deflate64') body = pack(body);
  cors(res);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (status === 200 && sMaxage > 0) res.setHeader('Cache-Control', `public, s-maxage=${sMaxage}, stale-while-revalidate=${swr}`);
  else res.setHeader('Cache-Control', 'no-store');
  res.status(status).send(JSON.stringify(body));
}

async function upstream(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || 20000);
  const started = Date.now();
  try {
    const r = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': UA, Accept: opts.accept || 'application/json', ...(opts.headers || {}) },
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* caller handles text */ }
    return { ok: r.ok, status: r.status, json, text, ms: Date.now() - started };
  } finally {
    clearTimeout(timer);
  }
}

function handle(fn) {
  return async (req, res) => {
    res.__req = req;
    if (req.method === 'OPTIONS') { cors(res); res.status(204).end(); return; }
    if (req.method !== 'GET') { sendJson(res, 405, { error: 'method_not_allowed' }, 0); return; }
    try {
      await fn(req, res);
    } catch (e) {
      sendJson(res, 502, { error: 'proxy_error', message: String(e && e.message || e) }, 0);
    }
  };
}

// Vercel passes query already parsed on req.query, but support raw URL too.
function q(req, key, def) {
  const v = (req.query && req.query[key]) ?? new URL(req.url, 'http://x').searchParams.get(key);
  return v == null || v === '' ? def : v;
}

module.exports = { cors, sendJson, upstream, handle, q, UA, pack, isOperator };
