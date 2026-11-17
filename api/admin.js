const { handle, sendJson, q, isOperator } = require('./_lib');
const store = require('../lib/store');
const crypto = require('crypto');

// Operator endpoint for the collector. It answers only on the project's *.vercel.app hosts, which Vercel
// Authentication protects; on the public domain it does not exist (404). It reaches the Neon Function with this
// deployment's OIDC token. Responses are never cached.
// Vercel Authentication (Standard Protection) must stay on for this project: it is what keeps these hosts private.
//   op=sha                          SHA-256 and size of each collector asset in this deployment
//   op=push&asset=code|atlas|num2iso|links|gold|feeds&u=<presigned upload URL for that object in the ti-docs bucket>
//   op=run&job=gdelt|infra|health|snap|ioda|retention|lists|fires|maritime|leaksites|ransompay|unit42|genioc|lanesreg|blogs|links|sec8k[&backfill=1][&rebuild=1][&reprocess=1][&history=<days>][&budget=<ms>]
//        run collector jobs now; reprocess re-reads the 72-hour GDELT window, history fills country counts back <days>
//   op=status | op=probe&target=<name>[&find=<text>|&from=<offset>] | op=doc&name=<document> | op=whoami
const ASSETS = {
  code: { key: 'code/collector.mjs', type: 'text/javascript', bytes: () => require('../lib/collector').source() },
  atlas: { key: 'ref/countries-50m.json', type: 'application/json', bytes: () => Buffer.from(JSON.stringify(require('world-atlas/countries-50m.json'))) },
  num2iso: { key: 'ref/num2iso.json', type: 'application/json', bytes: () => Buffer.from(JSON.stringify(require('../lib/num2iso.json'))) },
  links: { key: 'ref/links.json', type: 'application/json', bytes: () => Buffer.from(JSON.stringify(require('../lib/links.json'))) },
  gold: { key: 'ref/triage-gold.json', type: 'application/json', bytes: () => Buffer.from(JSON.stringify(require('../lib/triage-gold.json'))) },
  // The source network registry (pipeline/feeds_build.py); the sources job reads it from the bucket.
  feeds: { key: 'ref/feeds.json', type: 'application/json', bytes: () => Buffer.from(JSON.stringify(require('../data/feeds.json'))) },
};
const STORAGE_HOST = /^br-[a-z0-9-]+\.storage\.c-\d+\.[a-z0-9-]+\.aws\.neon\.tech$/;
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

function relay(res, r) {
  let body;
  try { body = JSON.parse(r.buf.toString('utf8')); } catch { body = { raw: r.buf ? r.buf.toString('utf8').slice(0, 2000) : null, reason: r.reason }; }
  return sendJson(res, r.ok ? 200 : r.status || 502, body, 0);
}

module.exports = handle(async (req, res) => {
  if (!isOperator(req)) return sendJson(res, 404, { error: 'not_found' }, 0);
  const op = q(req, 'op', 'whoami');
  if (op === 'whoami') {
    // Whether this deployment carries an OIDC token, and its non-secret claims.
    const tok = req.headers['x-vercel-oidc-token'] || '';
    let claims = null;
    try { claims = tok ? JSON.parse(Buffer.from(tok.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')) : null; } catch { /* malformed */ }
    const pick = claims && { iss: claims.iss, aud: claims.aud, sub: claims.sub, owner_id: claims.owner_id, project_id: claims.project_id, environment: claims.environment, exp: claims.exp };
    return sendJson(res, 200, { oidc: !!tok, claims: pick, collector: store.collectorUrl() }, 0);
  }
  if (op === 'sha') {
    const out = {};
    for (const [name, a] of Object.entries(ASSETS)) { const b = a.bytes(); out[name] = { key: a.key, bytes: b.length, sha256: sha(b) }; }
    return sendJson(res, 200, { collector: store.collectorUrl(), assets: out }, 0);
  }
  if (op === 'push') {
    const name = q(req, 'asset', '');
    const a = ASSETS[name];
    if (!a) return sendJson(res, 400, { error: 'asset must be one of ' + Object.keys(ASSETS).join(', ') }, 0);
    let u;
    try { u = new URL(q(req, 'u', '')); } catch { return sendJson(res, 400, { error: 'u must be a URL' }, 0); }
    if (u.protocol !== 'https:' || !STORAGE_HOST.test(u.hostname) || u.pathname !== '/ti-docs/' + a.key) {
      return sendJson(res, 400, { error: 'u must be a presigned upload URL for ti-docs/' + a.key }, 0);
    }
    const body = a.bytes();
    const r = await fetch(u, { method: 'PUT', body, headers: { 'content-type': a.type } });
    return sendJson(res, r.ok ? 200 : 502, { asset: name, key: a.key, status: r.status, bytes: body.length, sha256: sha(body), detail: r.ok ? undefined : (await r.text()).slice(0, 400) }, 0);
  }
  if (op === 'run') {
    const job = q(req, 'job', '');
    if (!/^[a-z0-9,]{2,80}$/.test(job)) return sendJson(res, 400, { error: 'job required' }, 0);
    return relay(res, await store.call(req, '/run', { method: 'POST', timeout: 58000,
      body: JSON.stringify({ job, backfill: q(req, 'backfill', '') === '1', rebuild: q(req, 'rebuild', '') === '1', reprocess: q(req, 'reprocess', '') === '1',
        historyDays: Math.max(0, Math.min(35, +q(req, 'history', '0') || 0)), budgetMs: Math.min(+q(req, 'budget', '45000') || 45000, 50000) }) }));
  }
  if (op === 'status') return relay(res, await store.call(req, '/status', { timeout: 25000 }));
  if (op === 'probe') return relay(res, await store.call(req, '/probe?target=' + encodeURIComponent(q(req, 'target', '')) + (q(req, 'find', '') ? '&find=' + encodeURIComponent(q(req, 'find', '')) : '')
    + (q(req, 'from', '') ? '&from=' + encodeURIComponent(q(req, 'from', '')) : ''), { timeout: 25000 }));
  if (op === 'doc') {
    const d = await store.getDoc(req, q(req, 'name', ''), { ttlMs: 0 });
    if (!d.ok) return sendJson(res, 502, d, 0);
    const rows = Array.isArray(d.doc.rows) ? d.doc.rows : [];
    const kinds = {};
    for (const r of rows) kinds[r.kind || '-'] = (kinds[r.kind || '-'] || 0) + 1;
    const { rows: _omit, ...head } = d.doc;
    const n = Math.min(+q(req, 'n', '3') || 3, 50);
    const kind = q(req, 'kind', '');
    return sendJson(res, 200, { ...head, kinds, sample: rows.filter((r) => !kind || r.kind === kind).slice(0, n), age_min: Math.round(store.ageMin(d.doc.generated)) }, 0);
  }
  return sendJson(res, 400, { error: 'unknown op' }, 0);
});
