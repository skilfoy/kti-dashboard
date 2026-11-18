// Neon Function "ti" entry point. Loads the collector module from the private ti-docs bucket (code/collector.mjs)
// with the branch's injected storage credentials, refuses it unless its SHA-256 equals TI_CODE_SHA256, and hands
// every request to it. Updating the collector is an upload plus a config-only redeploy that sets the new hash.
//
// Fallback to the previous bundle: TI_CODE_SHA256_PREV (optional) pins the bundle that ran before. After a bundle's
// first good run the loader keeps a copy of it at code/by-sha/<sha256>.mjs. When the current bundle cannot be read,
// fails its hash check or its import, or fails its first run (a 5xx answer, a thrown error, or a scheduled run in
// which every job failed), the loader loads code/by-sha/<TI_CODE_SHA256_PREV>.mjs, checks that hash too, and serves
// it; the failed request is answered by the previous bundle. Each answer carries x-ti-bundle (the first 12 hex digits
// of the bundle that answered, with ";fallback" when it is the previous one). The pinned hashes in the function
// environment stay the only authority: a bundle in the bucket runs only when its SHA-256 matches one of them.
//
// Transfer (3.2.0): bucket reads count against the Neon plan's monthly transfer, and a cold start used to read the
// 400 KB bundle and then the 400 KB kept copy. Each bundle is read from its gzipped copy (<key>.gz, about a third of the
// size) when one is there and its source matches the pinned hash, from the plain object otherwise; the kept copy is
// written gzipped, and whether it is already there is asked with HEAD, so a cold start reads one gzipped bundle.
import { createHash, createHmac } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const hm = (k, s) => createHmac('sha256', k).update(s).digest();
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

// One SigV4-signed request to the branch bucket (path style). GET and HEAD return the Response; PUT sends body, as
// application/gzip for a .gz key and text/javascript otherwise.
export function s3request(E, method, key, body) {
  const ep = new URL(E.AWS_ENDPOINT_URL_S3), region = E.AWS_REGION || 'us-east-1';
  const path = '/' + (E.TI_BUCKET || 'ti-docs') + '/' + key;
  const d = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, ''), day = d.slice(0, 8);
  const buf = body == null ? Buffer.alloc(0) : Buffer.from(body);
  const payload = sha256(buf);
  const ct = method === 'PUT' ? (key.endsWith('.gz') ? 'application/gzip' : 'text/javascript') : null;
  const signed = ct ? 'content-type;host;x-amz-content-sha256;x-amz-date' : 'host;x-amz-content-sha256;x-amz-date';
  const creq = [method, path, '', ...(ct ? ['content-type:' + ct] : []), 'host:' + ep.host, 'x-amz-content-sha256:' + payload, 'x-amz-date:' + d, '', signed, payload].join('\n');
  const scope = day + '/' + region + '/s3/aws4_request';
  const sts = ['AWS4-HMAC-SHA256', d, scope, createHash('sha256').update(creq).digest('hex')].join('\n');
  let k = hm('AWS4' + E.AWS_SECRET_ACCESS_KEY, day); k = hm(k, region); k = hm(k, 's3'); k = hm(k, 'aws4_request');
  const sig = createHmac('sha256', k).update(sts).digest('hex');
  return fetch(ep.origin + path, { method, body: method === 'PUT' ? buf : undefined, headers: { ...(ct ? { 'content-type': ct } : {}), 'x-amz-date': d, 'x-amz-content-sha256': payload,
    authorization: 'AWS4-HMAC-SHA256 Credential=' + E.AWS_ACCESS_KEY_ID + '/' + scope + ', SignedHeaders=' + signed + ', Signature=' + sig } });
}

async function importSource(src, h) {
  try {
    return await import('data:text/javascript;base64,' + Buffer.from(src).toString('base64'));
  } catch {
    // Runtimes that refuse data: imports load the same source from a file named by its hash.
    const file = '/tmp/collector-' + h.slice(0, 16) + '.mjs';
    writeFileSync(file, src);
    return import(pathToFileURL(file).href);
  }
}

// Whether a bundle's answer to a run (POST / from the schedule trigger, or POST /run) counts as failed: a 5xx, or every
// job that ran failed (a job skipped for a held lease does not count either way). Reads (GET) are never judged here.
export async function failedRun(req, res) {
  const p = new URL(req.url).pathname.replace(/\/+$/, '');
  if (req.method !== 'POST' || (p !== '' && p !== '/run')) return null;
  if (res.status >= 500) return 'HTTP ' + res.status;
  try {
    const j = await res.clone().json();
    const ran = (j && Array.isArray(j.jobs) ? j.jobs : []).filter((x) => !x.skipped);
    if (ran.length && ran.every((x) => !x.ok)) return 'every job failed: ' + ran.map((x) => x.job + ' ' + String(x.error || '').slice(0, 80)).join('; ');
  } catch { /* not JSON: judged by status alone */ }
  return null;
}

export function makeLoader({ env = process.env, s3 = (m, k, b) => s3request(env, m, k, b), log = console } = {}) {
  const E = env;
  const state = { cur: null, prev: null, pending: null, using: null, verified: false, reason: null, events: [] };
  const note = (msg) => { state.events.push({ at: new Date().toISOString(), msg }); if (state.events.length > 20) state.events.shift(); log.error('loader: ' + msg); };

  // The gzipped copy first; a missing, unreadable or stale one (its source not the pinned hash) falls through to the
  // plain object, which alone decides a refusal.
  async function fetchBundle(key, want) {
    try {
      const z = await s3('GET', key + '.gz');
      if (z.ok) {
        const src = gunzipSync(Buffer.from(await z.arrayBuffer())).toString('utf8');
        if (sha256(src) === want) return { src, sha: want, via: key + '.gz', mod: await importSource(src, want) };
        note(key + '.gz does not hold the pinned bundle; reading ' + key);
      }
    } catch (e) { note(key + '.gz unreadable (' + String((e && e.message) || e) + '); reading ' + key); }
    const r = await s3('GET', key);
    if (!r.ok) throw new Error(key + ': storage HTTP ' + r.status);
    const src = await r.text();
    const h = sha256(src);
    if (h !== want) throw new Error(key + ' hash ' + h + ' does not match the pinned ' + want);
    return { src, sha: h, via: key, mod: await importSource(src, h) };
  }
  async function loadPrev(why) {
    const want = E.TI_CODE_SHA256_PREV;
    if (!want || want === E.TI_CODE_SHA256) throw new Error(why + '; no previous bundle pinned (TI_CODE_SHA256_PREV)');
    if (!state.prev) state.prev = await fetchBundle('code/by-sha/' + want + '.mjs', want);
    state.using = 'prev'; state.reason = why;
    note('serving the previous bundle ' + want.slice(0, 12) + ': ' + why);
    return state.prev;
  }
  async function load() {
    if (!E.TI_CODE_SHA256) throw new Error('TI_CODE_SHA256 is not set');
    try { state.cur = await fetchBundle('code/collector.mjs', E.TI_CODE_SHA256); state.using = 'cur'; return state.cur; }
    catch (e) { return loadPrev('current bundle refused: ' + String((e && e.message) || e)); }
  }
  // After the current bundle's first good run, keep a gzipped copy under its hash for the next deploy's fallback. A
  // copy already there is found with HEAD (no body read); fetchBundle checks its hash whenever it is used.
  async function keep(b) {
    try {
      const key = 'code/by-sha/' + b.sha + '.mjs.gz';
      const have = await s3('HEAD', key);
      if (have.ok) return;
      const put = await s3('PUT', key, gzipSync(Buffer.from(b.src), { level: 9 }));
      if (!put.ok) note('could not keep ' + key + ': storage HTTP ' + put.status);
    } catch (e) { note('could not keep the bundle copy: ' + String((e && e.message) || e)); }
  }
  const tag = (res, b) => {
    try { res.headers.set('x-ti-bundle', b.sha.slice(0, 12) + (state.using === 'prev' ? ';fallback' : '')); return res; }
    catch { const h = new Headers(res.headers); h.set('x-ti-bundle', b.sha.slice(0, 12) + (state.using === 'prev' ? ';fallback' : '')); return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h }); }
  };

  async function handle(request) {
    if (!state.using) await (state.pending || (state.pending = load().finally(() => { state.pending = null; })));
    const b = state.using === 'prev' ? state.prev : state.cur;
    // Until its first good run the current bundle is on probation: a failed run switches to the previous bundle and
    // the same request is answered again by it (the jobs hold leases and write idempotently, so a rerun is safe).
    if (state.using === 'cur' && !state.verified) {
      const replay = request.clone();
      let res, why;
      try { res = await b.mod.default.fetch(request); why = await failedRun(request, res); }
      catch (e) { why = 'threw ' + String((e && e.message) || e); }
      if (!why) {
        const p = new URL(request.url).pathname.replace(/\/+$/, '');
        if (request.method === 'POST' && (p === '' || p === '/run')) { state.verified = true; await keep(b); }
        return tag(res, b);
      }
      const prev = await loadPrev('current bundle failed its first run: ' + why);
      return tag(await prev.mod.default.fetch(replay), prev);
    }
    return tag(await b.mod.default.fetch(request), b);
  }

  return {
    state,
    async fetch(request) {
      try {
        return await handle(request);
      } catch (e) {
        log.error('loader:', (e && e.stack) || e);
        return new Response(JSON.stringify({ error: String((e && e.message) || e), stage: state.using ? 'handler' : 'load', fallback: state.using === 'prev' || undefined }),
          { status: 503, headers: { 'content-type': 'application/json' } });
      }
    },
  };
}

export default makeLoader();
