// Offline test of neon/loader.mjs: hash pinning, the copy kept after a bundle's first good run, and the fallback to the
// previous bundle when the new one fails its hash check, its import or its first run. The bucket is an in-memory map.
// node test/loader_test.mjs <repository root>
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';

const ROOT = path.resolve(process.argv[2] || '.');
const L = await import(path.join(ROOT, 'neon', 'loader.mjs'));
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };
const sha = (s) => createHash('sha256').update(s).digest('hex');

// A bundle answering every request with its own name; POST / reports the jobs given.
const bundle = (name, jobs = [{ job: 'gdelt', ok: true }], extra = '') => `${extra}
export default { async fetch(req) {
  const p = new URL(req.url).pathname;
  if (req.method === 'POST') return new Response(JSON.stringify({ bundle: ${JSON.stringify(name)}, jobs: ${JSON.stringify(jobs)} }), { headers: { 'content-type': 'application/json' } });
  return new Response(JSON.stringify({ bundle: ${JSON.stringify(name)}, path: p }), { headers: { 'content-type': 'application/json' } });
} };`;
const OLD = bundle('old'), NEW = bundle('new');

// Objects are kept as the bytes written: strings for plain keys, Buffers for .gz keys. reads lists every GET and HEAD.
function rig({ cur, prev, env = {}, curGz = null, prevGz = null }) {
  const bucket = new Map(), puts = [], reads = [], quiet = { error: () => {} };
  if (cur != null) bucket.set('code/collector.mjs', cur);
  if (curGz != null) bucket.set('code/collector.mjs.gz', gzipSync(Buffer.from(curGz)));
  if (prev != null) bucket.set('code/by-sha/' + sha(prev) + '.mjs', prev);
  if (prevGz != null) bucket.set('code/by-sha/' + sha(prevGz) + '.mjs.gz', gzipSync(Buffer.from(prevGz)));
  const s3 = async (method, key, body) => {
    if (method === 'PUT') { puts.push(key); bucket.set(key, key.endsWith('.gz') ? Buffer.from(body) : Buffer.from(body).toString()); return new Response('', { status: 200 }); }
    reads.push(method + ' ' + key);
    if (!bucket.has(key)) return new Response(method === 'HEAD' ? null : 'NoSuchKey', { status: 404 });
    return new Response(method === 'HEAD' ? null : bucket.get(key), { status: 200 });
  };
  const E = { TI_CODE_SHA256: cur != null ? sha(cur) : curGz != null ? sha(curGz) : 'f'.repeat(64),
    ...(prev != null ? { TI_CODE_SHA256_PREV: sha(prev) } : prevGz != null ? { TI_CODE_SHA256_PREV: sha(prevGz) } : {}), ...env };
  return { loader: L.makeLoader({ env: E, s3, log: quiet }), bucket, puts, reads, E };
}
const unz = (b) => gunzipSync(b).toString('utf8');
const trigger = () => new Request('https://fn.example/', { method: 'POST', headers: { 'x-neon-trigger-invocation-id': 't', 'content-type': 'application/json' }, body: '{}' });
const get = (p = '/status') => new Request('https://fn.example' + p);
const body = async (r) => JSON.parse(await r.text());

// 1. The current bundle loads, serves, and after its first good run is kept under its hash.
{
  const { loader, bucket, puts } = rig({ cur: NEW, prev: OLD });
  let r = await loader.fetch(get('/doc/health'));
  ok(r.status === 200 && (await body(r)).bundle === 'new' && r.headers.get('x-ti-bundle') === sha(NEW).slice(0, 12), 'current bundle serves');
  ok(!loader.state.verified && !puts.length, 'a read does not end probation');
  r = await loader.fetch(trigger());
  ok((await body(r)).bundle === 'new' && loader.state.verified, 'first good scheduled run ends probation');
  ok(unz(bucket.get('code/by-sha/' + sha(NEW) + '.mjs.gz')) === NEW && puts.length === 1, 'bundle kept gzipped under its hash after its first good run');
  await loader.fetch(trigger());
  ok(puts.length === 1, 'kept once');
}

// 2. Hash mismatch: the bucket holds code the pinned hash does not name; the previous bundle serves.
{
  const { loader } = rig({ cur: NEW, prev: OLD, env: { TI_CODE_SHA256: 'a'.repeat(64) } });
  const r = await loader.fetch(get());
  ok(r.status === 200 && (await body(r)).bundle === 'old' && r.headers.get('x-ti-bundle') === sha(OLD).slice(0, 12) + ';fallback', 'hash mismatch falls back');
  ok(/does not match the pinned/.test(loader.state.reason), 'reason recorded: ' + loader.state.reason);
}

// 3. The new bundle does not import (syntax error).
{
  const bad = 'export default {{ broken';
  const { loader } = rig({ cur: bad, prev: OLD });
  const r = await loader.fetch(trigger());
  ok(r.status === 200 && (await body(r)).bundle === 'old' && /current bundle refused/.test(loader.state.reason), 'import failure falls back');
}

// 4. The new bundle's first scheduled run fails every job: the same run is answered by the previous bundle, which
//    keeps serving; nothing is kept for the failed bundle.
{
  const failing = bundle('new-broken', [{ job: 'gdelt', ok: false, error: 'boom' }, { job: 'infra', ok: false, error: 'boom' }, { job: 'snap', ok: false, skipped: true }]);
  const { loader, puts } = rig({ cur: failing, prev: OLD });
  let r = await loader.fetch(trigger());
  ok((await body(r)).bundle === 'old' && /first run: every job failed: gdelt boom; infra boom/.test(loader.state.reason), 'failed first run falls back ' + loader.state.reason);
  r = await loader.fetch(get());
  ok((await body(r)).bundle === 'old' && r.headers.get('x-ti-bundle').endsWith(';fallback'), 'previous bundle keeps serving');
  ok(!puts.length, 'a failed bundle is not kept');
}

// 5. One failed job among several good ones is not a failed run.
{
  const mixed = bundle('new-mixed', [{ job: 'gdelt', ok: true }, { job: 'blogs', ok: false, error: 'held' }]);
  const { loader } = rig({ cur: mixed, prev: OLD });
  const r = await loader.fetch(trigger());
  ok((await body(r)).bundle === 'new-mixed' && loader.state.verified && loader.state.using === 'cur', 'a partial failure keeps the new bundle');
}

// 6. The new bundle throws on its first run (a 5xx answer counts the same).
{
  const thrower = `export default { async fetch() { throw new Error('kaput'); } };`;
  const { loader } = rig({ cur: thrower, prev: OLD });
  const r = await loader.fetch(trigger());
  ok((await body(r)).bundle === 'old' && /threw kaput/.test(loader.state.reason), 'a throwing first run falls back');
  const five = `export default { async fetch(req) { return new Response('{"error":"x"}', { status: 500 }); } };`;
  const g = rig({ cur: five, prev: OLD });
  const r2 = await g.loader.fetch(get('/status'));
  ok(r2.status === 500 && g.loader.state.using === 'cur', 'a read answering 500 is passed through, not judged');
  const r3 = await g.loader.fetch(trigger());
  ok((await body(r3)).bundle === 'old', 'a 5xx run falls back');
}

// 7. Without a pinned previous bundle, or with a previous copy that fails its own hash, the loader answers 503.
{
  const { loader } = rig({ cur: NEW, env: { TI_CODE_SHA256: 'b'.repeat(64) } });
  const r = await loader.fetch(get());
  const j = await body(r);
  ok(r.status === 503 && j.stage === 'load' && /no previous bundle pinned/.test(j.error), 'no previous pinned: 503 ' + j.error);
  const t = rig({ cur: NEW, prev: OLD, env: { TI_CODE_SHA256: 'c'.repeat(64) } });
  t.bucket.set('code/by-sha/' + sha(OLD) + '.mjs', OLD + '\n// altered');
  const r2 = await t.loader.fetch(get());
  ok(r2.status === 503 && /does not match the pinned/.test((await body(r2)).error), 'an altered previous copy is refused');
  const u = rig({ cur: null, prev: null, env: { TI_CODE_SHA256: '' } });
  ok((await u.loader.fetch(get())).status === 503, 'no hash set: 503');
}

// 7b. Transfer (3.2.0): the gzipped bundle is read when it holds the pinned source, a stale one falls through to the
//     plain object, a kept copy already there is found with HEAD, and the previous bundle is read from its gzipped copy.
{
  const a = rig({ cur: NEW, curGz: NEW, prev: OLD });
  let r = await a.loader.fetch(trigger());
  ok((await body(r)).bundle === 'new' && a.loader.state.cur.via === 'code/collector.mjs.gz', 'gzipped bundle served');
  ok(!a.reads.includes('GET code/collector.mjs') && a.reads.includes('HEAD code/by-sha/' + sha(NEW) + '.mjs.gz') && a.puts.length === 1, 'one gzipped GET, a HEAD, one PUT: ' + a.reads.join(', '));
  const b = rig({ cur: NEW, curGz: OLD, prev: OLD });
  r = await b.loader.fetch(get());
  ok((await body(r)).bundle === 'new' && b.loader.state.cur.via === 'code/collector.mjs' && b.loader.state.using === 'cur', 'a stale gzipped copy falls through to the plain bundle');
  ok(b.loader.state.events.some((e) => /does not hold the pinned bundle/.test(e.msg)), 'the stale copy is noted');
  const c = rig({ cur: NEW, curGz: NEW, prev: OLD });
  c.bucket.set('code/by-sha/' + sha(NEW) + '.mjs.gz', gzipSync(Buffer.from(NEW)));
  await c.loader.fetch(trigger());
  ok(!c.puts.length && !c.reads.some((x) => x.startsWith('GET code/by-sha/')), 'a kept copy already there costs one HEAD and no read');
  const d = rig({ curGz: NEW, prevGz: OLD, env: { TI_CODE_SHA256: 'd'.repeat(64) } });
  r = await d.loader.fetch(get());
  ok((await body(r)).bundle === 'old' && d.loader.state.prev.via === 'code/by-sha/' + sha(OLD) + '.mjs.gz', 'previous bundle read from its gzipped copy');
  const e = rig({ cur: NEW, prev: OLD });
  e.bucket.set('code/collector.mjs.gz', Buffer.from('not gzip'));
  r = await e.loader.fetch(get());
  ok((await body(r)).bundle === 'new' && e.loader.state.events.some((x) => /unreadable/.test(x.msg)), 'an unreadable gzipped copy falls through');
}

// 8. failedRun on its own.
{
  const res = (status, j) => new Response(JSON.stringify(j), { status });
  ok(await L.failedRun(trigger(), res(200, { jobs: [] })) === null, 'no jobs: not a failure');
  ok(await L.failedRun(trigger(), res(200, { jobs: [{ job: 'x', ok: false, skipped: true }] })) === null, 'only skipped jobs: not a failure');
  ok(/HTTP 502/.test(await L.failedRun(new Request('https://fn.example/run', { method: 'POST', body: '{}' }), res(502, {}))), 'POST /run 5xx is a failure');
  ok(await L.failedRun(get('/doc/x'), res(500, {})) === null, 'reads are not judged');
}

// 9. The storage request is signed (SigV4 header shape) for GET and PUT.
{
  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u, o) => { seen.push({ u: String(u), o }); return new Response('x'); };
  const E = { AWS_ENDPOINT_URL_S3: 'https://br-x.storage.c-1.us-east-1.aws.neon.tech', AWS_ACCESS_KEY_ID: 'nak', AWS_SECRET_ACCESS_KEY: 'nsk', TI_BUCKET: 'ti-docs' };
  await L.s3request(E, 'GET', 'code/collector.mjs');
  await L.s3request(E, 'PUT', 'code/by-sha/abc.mjs', 'src');
  globalThis.fetch = realFetch;
  ok(seen[0].u === 'https://br-x.storage.c-1.us-east-1.aws.neon.tech/ti-docs/code/collector.mjs' && /SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/.test(seen[0].o.headers.authorization), 'GET signed');
  // Same signatures as the collector's own SigV4 (checked there against the AWS test vector), for the same date.
  const C = await import(path.join(ROOT, 'neon', 'collector.mjs'));
  for (const [i, method, key, payload, headers] of [[0, 'GET', 'code/collector.mjs', '', {}], [1, 'PUT', 'code/by-sha/abc.mjs', 'src', { 'content-type': 'text/javascript' }]]) {
    const want = C.sigv4({ method, host: 'br-x.storage.c-1.us-east-1.aws.neon.tech', path: '/ti-docs/' + key, headers, payloadHash: sha(payload), amzDate: seen[i].o.headers['x-amz-date'],
      region: 'us-east-1', keyId: 'nak', secret: 'nsk' });
    ok(want.authorization === seen[i].o.headers.authorization, method + ' signature matches the collector SigV4');
  }
  ok(seen[1].o.method === 'PUT' && /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/.test(seen[1].o.headers.authorization) && seen[1].o.headers['x-amz-content-sha256'] === sha('src'), 'PUT signed with its payload hash');
}

// 10. The deploy plan and workflow: the plan names the build and both hashes; the workflow reads no secret, deploys
//     nothing, and gates its production job on the protected environment.
{
  const fs = await import('node:fs');
  const P = await import(path.join(ROOT, 'neon', 'deploy_plan.mjs'));
  const plan = P.planFor(ROOT, 'abc1234');
  const built = sha(fs.readFileSync(path.join(ROOT, 'neon', 'collector.mjs')));
  ok(plan.includes(built) && plan.includes('"TI_CODE_SHA256": "' + built + '"') && plan.includes('TI_CODE_SHA256_PREV') && plan.includes('abc1234') && /presign_storage_object/.test(plan), 'plan names the build hash and the fallback pin');
  ok(!/\bactually\b/i.test(plan) && !/postgres(ql)?:\/\/|X-Amz-Signature|nsk_|nak_/i.test(plan), 'plan holds no secret and keeps the writing rules');
  let threw = false; try { P.deployPlan({ sha: 'xyz' }); } catch { threw = true; }
  ok(threw, 'plan refuses a malformed hash');
  const wf = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'collector-deploy.yml'), 'utf8');
  ok(!/secrets\./.test(wf) && !/deploy_function|presign|op=push|vercel deploy|aws s3|curl[^\n]*-X (PUT|POST)/.test(wf.replace(/^#.*$/gm, '')), 'deploy workflow reads no secret and runs no production write');
  ok(/prepare-production:[\s\S]*environment: collector-production/.test(wf) && /if: github.event_name != 'pull_request' && github.ref == 'refs\/heads\/main'/.test(wf) && /node test\/run_all\.mjs/.test(wf), 'production job gated on the protected environment, after the offline suite');
}

console.log(`PASS ${pass} checks (loader)`);
