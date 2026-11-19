// Offline test of the automated collector deploy (.github/scripts/collector_deploy.mjs and its workflow): the timing
// window, the skip without secrets, the presigned URL (AWS test vector), the loader zip, the switch judgement, and whole
// runs against fake Neon, storage, Vercel, operator and GitHub endpoints: success, fallback with rollback, dry run,
// unconfirmed OLD, unchanged bundle and a service serving another build.
// node test/auto_deploy_test.mjs <repository root>      (after python3 pipeline/collector_build.py .)
import zlib from 'node:zlib';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const ROOT = path.resolve(process.argv[2] || '.');
const D = await import(path.join(ROOT, '.github', 'scripts', 'collector_deploy.mjs'));
const C = await import(path.join(ROOT, 'neon', 'collector.mjs'));
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };
const sha = (b) => createHash('sha256').update(b).digest('hex');
const at = (hms) => Date.parse('2026-11-03T' + hms + 'Z');

// ---------------------------------------------------------------- timing window
ok(D.waitForWindow(at('10:11:00')) === 0 && D.waitForWindow(at('10:15:59')) === 0 && D.waitForWindow(at('10:56:00')) === 0, 'inside: 7 to 12 minutes after :04 and :49');
ok(D.waitForWindow(at('10:10:59')) === 1000, 'a second before the window opens');
ok(D.waitForWindow(at('10:16:00')) === 10 * 60000, 'window closed at 12 minutes: wait for 10:26');
ok(D.waitForWindow(at('10:01:00')) === 10 * 60000 && D.waitForWindow(at('10:04:30')) === 6.5 * 60000, 'before and during the trigger minute');
ok(D.waitForWindow(at('10:59:30')) === 0 && D.waitForWindow(at('11:00:30')) === 0 && D.waitForWindow(at('11:01:00')) === 10 * 60000, 'the :49 window runs across the hour to 11:01');
ok(JSON.stringify(D.leasesHeld({ leases: [{ job: 'gdelt', until: '2026-11-03T10:12:00Z' }, { job: 'infra', until: '1970-01-01T00:00:00Z' }] }, at('10:11:00'))) === '["gdelt"]'
  && !D.leasesHeld({ leases: [{ job: 'gdelt', until: '2026-11-03T10:10:00Z' }] }, at('10:11:00')).length && D.leasesHeld(null, at('10:11:00')).length === 1, 'leases held, and an unreadable status counts as held');
ok([4, 19, 34, 49].every((m) => !D.inWindow(Date.parse(`2026-11-03T10:${String(m).padStart(2, '0')}:30Z`))), 'never during a trigger minute');

// ---------------------------------------------------------------- small pieces
ok(D.collectorChanged(['neon/parts/20-gdelt.mjs']) && D.collectorChanged(['lib/collector.js']) && D.collectorChanged(['pipeline/collector_build.py']) && !D.collectorChanged(['data/authored/items.json', 'public/js/app.js']), 'collector paths');
ok(D.loaderChanged(['neon/loader.mjs']) && !D.loaderChanged(['neon/parts/10-core.mjs']), 'loader path');
ok(JSON.stringify(D.missingSecrets({ NEON_API_KEY: 'x' })) === JSON.stringify(['NEON_STORAGE_KEY_ID', 'NEON_STORAGE_SECRET', 'VERCEL_AUTOMATION_BYPASS_SECRET', 'VERCEL_TOKEN']), 'missing secrets named');
// AWS Signature Version 4 query-string example (GET examplebucket/test.txt, expires 86400).
{
  const u = D.presignUrl({ method: 'GET', endpoint: 'https://examplebucket.s3.amazonaws.com', path: '/test.txt', keyId: 'AKIAIOSFODNN7EXAMPLE', secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1', amzDate: '20130524T000000Z', expires: 86400 });
  ok(u.endsWith('X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404'), 'presigned URL matches the AWS test vector');
  const p = new URL(D.presignUrl({ method: 'PUT', endpoint: D.CONFIG.storage, path: '/ti-docs/code/collector.mjs', keyId: 'k', secret: 's', amzDate: '20261103T051159Z' }));
  ok(/^br-[a-z0-9-]+\.storage\.c-\d+\.[a-z0-9-]+\.aws\.neon\.tech$/.test(p.hostname) && p.pathname === '/ti-docs/code/collector.mjs', 'upload URL passes the operator endpoint host and path check');
}
{
  const src = 'export default { fetch() { return new Response("ok"); } };\n'.repeat(50);
  const z = D.zipOne('index.mjs', src);
  ok(C.firstEntry(z).toString() === src && z.includes(Buffer.from('index.mjs')), 'loader zip: one entry, index.mjs, round trip');
}
ok(D.versionOf("export const VERSION = '2026-11-03.1';") === '2026-11-03.1', 'version read from a bundle');

// ---------------------------------------------------------------- switch judgement (the rollback conditions)
{
  const good = { envDeploy: { status: 'completed', environment: ['A', 'TI_CODE_SHA256', 'TI_CODE_SHA256_PREV'] }, namesBefore: ['A', 'TI_CODE_SHA256'], newVersion: 'v2', newSha: 'f'.repeat(64),
    run: { http: 200, version: 'v2', ok: true }, status: { version: 'v2' }, probation: true };
  ok(D.judgeSwitch(good).length === 0, 'a clean switch passes');
  const bad = (o) => D.judgeSwitch({ ...good, ...o }).join(' | ');
  ok(/fell back/.test(bad({ run: { http: 200, version: 'v1', ok: true } })), 'old version on the run: fallback');
  ok(/op=status reports version v1/.test(bad({ status: { version: 'v1' } })), 'old version on status');
  ok(/did not pass probation/.test(bad({ probation: false })), 'no kept copy: probation failed');
  ok(/gdelt job failed/.test(bad({ run: { http: 200, version: 'v2', ok: false, error: 'boom' } })), 'failed job');
  ok(/HTTP 503/.test(bad({ run: { http: 503 } })), 'run refused');
  ok(/environment lost A/.test(bad({ envDeploy: { status: 'completed', environment: ['TI_CODE_SHA256', 'TI_CODE_SHA256_PREV'] } })), 'a lost variable');
  ok(/not completed/.test(bad({ envDeploy: { status: 'failed', environment: good.envDeploy.environment } })), 'deploy not completed');
}

// ---------------------------------------------------------------- whole runs against fake services
const OLD_SRC = "export const VERSION = '2026-11-02.1';\n// old\n", NEW_SRC = "export const VERSION = '2026-11-03.1';\n// new\n";
const OLD = sha(OLD_SRC), NEW = sha(NEW_SRC);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deploy-'));
const bundlePath = path.join(dir, 'collector.mjs'); fs.writeFileSync(bundlePath, NEW_SRC);
const loaderPath = path.join(dir, 'loader.mjs'); fs.writeFileSync(loaderPath, '// loader v2\n');
const SECRETS = { NEON_API_KEY: 'neon-key', NEON_STORAGE_KEY_ID: 'nak_x', NEON_STORAGE_SECRET: 'nsk_x', VERCEL_AUTOMATION_BYPASS_SECRET: 'bypass', VERCEL_TOKEN: 'vt',
  GITHUB_TOKEN: 'gh', GITHUB_REPOSITORY: 'o/r', GITHUB_SERVER_URL: 'https://github.com', GITHUB_RUN_ID: '1' };
const NAMES = ['ABUSECH_AUTH_KEY', 'CLOQ_API_KEY', 'DATABASE_URL', 'FIRMS_MAP_KEY', 'SEC_USER_AGENT', 'TI_BUCKET', 'TI_CODE_SHA256', 'TI_CODE_SHA256_PREV'];

// keptOld: 'gz' (the loader's copy since 3.2.0), true (a plain copy kept before 3.2.0) or false. leases: [{job, until}]
// for op=status, each released after `holdMs` of fake clock.
function world({ serveSha = NEW, fallback = false, keptOld = 'gz', start = at('10:02:00'), leases = [], staleStatus = 0, staleRun = 0 } = {}) {
  const w = { clock: start, bucket: new Map([['code/collector.mjs', OLD_SRC], ['code/collector.mjs.gz', zlib.gzipSync(OLD_SRC)]]), env: { TI_CODE_SHA256: OLD, TI_CODE_SHA256_PREV: 'e'.repeat(64) }, deploys: [], writes: [], issues: [], comments: [], logs: [], leases };
  if (keptOld === 'gz') w.bucket.set(`code/by-sha/${OLD}.mjs.gz`, zlib.gzipSync(OLD_SRC));
  else if (keptOld) w.bucket.set(`code/by-sha/${OLD}.mjs`, OLD_SRC);
  const running = () => (!fallback && w.env.TI_CODE_SHA256 === NEW && w.bucket.get('code/collector.mjs') === NEW_SRC ? 'new' : 'old');
  w.http = async (url, opts = {}) => {
    const u = new URL(String(url)), method = opts.method || 'GET', h = Object.fromEntries(Object.entries(opts.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
    if (u.hostname.endsWith('.storage.c-14.us-east-1.aws.neon.tech')) {
      assert.ok(u.searchParams.get('X-Amz-Credential').startsWith('nak_x/') && /^[0-9a-f]{64}$/.test(u.searchParams.get('X-Amz-Signature')), 'storage requests are presigned');
      const key = decodeURIComponent(u.pathname).replace(/^\/ti-docs\//, '');
      if (method === 'PUT') { w.writes.push('PUT ' + key); w.bucket.set(key, key.endsWith('.gz') ? Buffer.from(opts.body) : Buffer.from(opts.body).toString()); return new Response('', { status: 200 }); }
      return w.bucket.has(key) ? new Response(w.bucket.get(key)) : new Response('NoSuchKey', { status: 404 });
    }
    if (u.hostname === 'console.neon.tech') {
      assert.equal(h.authorization, 'Bearer neon-key');
      if (method === 'GET') return json({ function: { slug: 'ti', current_deployment: { id: 20 + w.deploys.length, status: 'completed', environment: Object.keys(w.env).length > 2 ? NAMES : NAMES.filter((n) => n !== 'TI_CODE_SHA256_PREV' || w.env.TI_CODE_SHA256_PREV) } } });
      const env = opts.body.get('environment'), zip = opts.body.get('zip');
      w.deploys.push({ environment: env ? JSON.parse(env) : null, zip: !!zip });
      w.writes.push(zip ? 'DEPLOY zip' : 'DEPLOY env ' + env);
      if (env) Object.assign(w.env, JSON.parse(env));
      return json({ id: 20 + w.deploys.length, status: 'completed', environment: NAMES });
    }
    if (u.hostname === 'api.vercel.com') { assert.equal(h.authorization, 'Bearer vt'); return json({ deployments: [{ url: 'threat-feeds-abc-skilfoys-projects.vercel.app', state: 'READY' }] }); }
    if (u.hostname === 'threat-feeds-abc-skilfoys-projects.vercel.app') {
      assert.equal(h['x-vercel-protection-bypass'], 'bypass');
      const op = u.searchParams.get('op');
      if (op === 'sha') return json({ assets: { code: { sha256: serveSha } } });
      if (op === 'push') {
        const up = new URL(u.searchParams.get('u')), gz = u.searchParams.get('gz') === '1';
        assert.equal(up.pathname, gz ? '/ti-docs/code/collector.mjs.gz' : '/ti-docs/code/collector.mjs');
        w.writes.push(gz ? 'PUSH gz' : 'PUSH'); w.bucket.set(gz ? 'code/collector.mjs.gz' : 'code/collector.mjs', gz ? zlib.gzipSync(NEW_SRC) : NEW_SRC);
        return json({ asset: 'code', status: 200, sha256: NEW });
      }
      if (op === 'run' && running() === 'new' && w.staleRun > 0) { w.staleRun--; w.writes.push('RUN'); return json({ version: '2026-11-02.1', jobs: [{ job: 'gdelt', ok: true }] }); }
      if (op === 'run') {
        w.writes.push('RUN');
        const v = running() === 'new' ? '2026-11-03.1' : '2026-11-02.1';
        if (v === '2026-11-03.1') w.bucket.set(`code/by-sha/${NEW}.mjs.gz`, zlib.gzipSync(NEW_SRC)); // the loader keeps the copy after a good run
        return json({ version: v, jobs: [{ job: 'gdelt', ok: true }] });
      }
      if (op === 'status' && running() === 'new' && w.stale > 0) { w.stale--; return json({ version: '2026-11-02.1', runs: [], leases: [] }); }
      if (op === 'status') return json({ version: running() === 'new' ? '2026-11-03.1' : '2026-11-02.1', runs: [{ job: 'gdelt', ok: true, started_at: new Date(w.clock).toISOString() }],
        leases: w.leases.map((l) => ({ job: l.job, holder: 'cron', until: new Date(l.until).toISOString() })) });
    }
    if (u.hostname === 'api.github.com') {
      if (u.pathname.endsWith('/pulls')) return json([{ number: 7, merged_at: '2026-11-03T10:00:00Z' }]);
      const b = JSON.parse(opts.body);
      if (u.pathname.endsWith('/issues')) { w.issues.push(b); return json({ number: 9 }, 201); }
      if (u.pathname.endsWith('/comments')) { w.comments.push({ path: u.pathname, ...b }); return json({}, 201); }
    }
    throw new Error('unexpected request ' + method + ' ' + u.href);
  };
  w.stale = staleStatus; w.staleRun = staleRun;
  w.run = (extra = {}) => D.deploy({ env: { ...SECRETS, ...extra.env }, http: w.http, wait: async (ms) => { w.clock += ms; }, now: () => w.clock, log: (l) => w.logs.push(l),
    bundlePath, loaderPath, sha: 'abc123', files: extra.files || ['neon/parts/20-gdelt.mjs'], prevLoader: extra.prevLoader || null });
  return w;
}

// A warm instance still on the old bundle answers op=status twice after the pin: the check asks again.
{
  const w = world({ staleStatus: 2 });
  const r = await w.run();
  ok(r.ok && w.env.TI_CODE_SHA256 === NEW && w.issues.length === 0, 'a stale op=status answer is asked again, not rolled back ' + r.error);
}
// An old warm instance takes the first two gdelt runs after the pin: the run is asked again.
{
  const w = world({ staleRun: 2 });
  const r = await w.run();
  ok(r.ok && w.env.TI_CODE_SHA256 === NEW && w.writes.filter((x) => x === 'RUN').length === 3, 'a stale run answer is run again, not rolled back ' + r.error);
}
// A month-long operator pause does not hold the deploy; a running job's lease does.
{
  const w = world({ leases: [{ job: 'ocia1', until: at('10:02:00') + 30 * 864e5 }] });
  const r = await w.run();
  ok(r.ok && !r.evidence.steps.some((s) => s.name === 'leases held') && r.evidence.steps.some((s) => s.name === 'quiet' && s.paused.includes('ocia1')), 'a paused job does not block the switch');
  ok(JSON.stringify(D.leasesHeld({ leases: [{ job: 'a', until: '2026-11-03T10:20:00Z' }, { job: 'b', until: '2026-12-03T10:20:00Z' }] }, at('10:11:00'))) === '["a"]', 'held: within 20 minutes only');
}
// Success: waits for the window, pushes, pins NEW with PREV = OLD, checks, comments on the merged pull request.
{
  const w = world();
  const r = await w.run();
  ok(r.ok && w.env.TI_CODE_SHA256 === NEW && w.env.TI_CODE_SHA256_PREV === OLD, 'pinned NEW with PREV = OLD');
  ok(JSON.stringify(w.writes.map((x) => x.replace(/^DEPLOY .*/, 'DEPLOY'))) === '["PUSH","PUSH gz","DEPLOY","RUN"]', 'writes in order: push, gzipped push, pin, run ' + w.writes);
  ok(zlib.gunzipSync(w.bucket.get('code/collector.mjs.gz')).toString() === NEW_SRC, 'the gzipped copy holds the new bundle');
  const pinAt = r.evidence.steps.find((s) => s.name === 'pinned').at;
  ok(D.inWindow(Date.parse(pinAt)) && pinAt === '2026-11-03T10:11:00.000Z', 'switch landed in the window ' + pinAt);
  ok(Object.keys(w.deploys[0].environment).join() === 'TI_CODE_SHA256,TI_CODE_SHA256_PREV' && !w.deploys[0].zip, 'environment-only deploy naming only the two hashes');
  ok(w.comments.length === 1 && w.comments[0].path.endsWith('/issues/7/comments') && /2026-11-03\.1/.test(w.comments[0].body) && w.issues.length === 0, 'comment on the merged pull request');
  ok(!w.logs.join('\n').match(/neon-key|nsk_x|bypass|Bearer/), 'no secret in the log');
}
// The loader falls back (the new bundle fails its first run): checks fail, bucket and pin go back to OLD, issue opened.
{
  const w = world({ fallback: true });
  const r = await w.run();
  ok(!r.ok && /fell back/.test(r.error) && /did not pass probation/.test(r.error), 'fallback detected ' + r.error);
  ok(w.env.TI_CODE_SHA256 === OLD && w.bucket.get('code/collector.mjs') === OLD_SRC && zlib.gunzipSync(w.bucket.get('code/collector.mjs.gz')).toString() === OLD_SRC, 'pin and both bucket copies restored to OLD');
  ok(JSON.stringify(r.restored) === '["bucket object to OLD","gzipped copy to OLD","TI_CODE_SHA256 to OLD"]', 'restore steps reported ' + JSON.stringify(r.restored));
  ok(w.issues.length === 1 && w.issues[0].title === 'Collector deploy failed' && w.issues[0].body.includes(OLD) && w.issues[0].body.includes(NEW) && /fell back/.test(w.issues[0].body) && w.comments.length === 0,
    'issue with the evidence, no success comment');
}
// Dry run: every read, no write.
{
  const w = world();
  const r = await w.run({ env: { DRY_RUN: '1' } });
  ok(r.ok && w.writes.length === 0 && w.comments.length === 0 && w.issues.length === 0 && w.env.TI_CODE_SHA256 === OLD, 'dry run writes nothing ' + w.writes);
  ok(w.logs.some((l) => /\[dry run\] would push and pin/.test(l)) && w.logs.some((l) => /\[dry run\] service/.test(l)), 'dry run still reads and reports');
}
// OLD cannot be confirmed (no kept copy): stops before any write.
{
  const w = world({ keptOld: false });
  const r = await w.run();
  ok(!r.ok && /not confirmed/.test(r.error) && w.writes.length === 0 && /nothing needed/.test(w.issues[0].body), 'unconfirmed OLD: no write, issue opened');
}
// A plain kept copy (before 3.2.0) still confirms OLD.
{
  const w = world({ keptOld: true });
  const r = await w.run();
  ok(r.ok && w.env.TI_CODE_SHA256 === NEW, 'a plain kept copy confirms OLD');
}
// A run holding its lease in the window: the switch waits until the lease is released.
{
  const w = world({ leases: [{ job: 'sources', until: at('10:12:10') }] });
  const r = await w.run();
  const pinAt = r.evidence.steps.find((s) => s.name === 'pinned').at;
  ok(r.ok && r.evidence.steps.some((s) => s.name === 'leases held' && s.jobs.includes('sources')) && Date.parse(pinAt) >= at('10:12:10') && D.inWindow(Date.parse(pinAt)), 'waits out a held lease ' + pinAt);
}
// The service deployment serves another build: stops before any write.
{
  const w = world({ serveSha: 'd'.repeat(64) });
  const r = await w.run();
  ok(!r.ok && /serves code d{64}, the build is/.test(r.error) && w.writes.length === 0, 'service/build mismatch stops the deploy');
}
// Nothing to do when the built bundle is already pinned.
{
  const w = world();
  w.bucket.set('code/collector.mjs', NEW_SRC); w.bucket.set(`code/by-sha/${NEW}.mjs.gz`, zlib.gzipSync(NEW_SRC)); w.env.TI_CODE_SHA256 = NEW;
  const r = await w.run();
  ok(r.ok && r.unchanged && w.writes.length === 0, 'unchanged bundle: nothing deployed');
}
// Missing secrets: a notice and a skip, no request at all.
{
  const logs = [];
  const r = await D.deploy({ env: { NEON_API_KEY: 'x' }, http: async () => { throw new Error('no request expected'); }, log: (l) => logs.push(l), bundlePath });
  ok(r.skipped && r.missing.length === 4 && /^::notice::Collector deploy skipped: repository secrets not set: NEON_STORAGE_KEY_ID/.test(logs[0]), 'skip with a notice when secrets are missing');
}
// Loader change: code deploy first, checked by the next scheduled run; a failed collector check then restores both.
{
  const w = world({ fallback: true });
  const r = await w.run({ files: ['neon/loader.mjs', 'neon/parts/10-core.mjs'], prevLoader: Buffer.from('// loader v1\n') });
  ok(w.deploys[0].zip && w.deploys.some((d) => d.environment && d.environment.TI_CODE_SHA256 === NEW), 'loader deployed before the pin');
  ok(!r.ok && r.restored.includes('loader to its previous code') && w.deploys[w.deploys.length - 1].zip, 'loader restored on failure ' + JSON.stringify(r.restored));
}

// ---------------------------------------------------------------- the workflow
{
  const wf = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'collector-auto-deploy.yml'), 'utf8');
  ok(/concurrency:\n  group: collector-production-deploy\n  cancel-in-progress: false/.test(wf), 'one deploy at a time');
  ok(/workflow_run:\n    workflows: \[Site\]\n    types: \[completed\]\n    branches: \[main\]/.test(wf) && /dry_run:/.test(wf), 'runs after the Site workflow on main, and by hand with dry_run');
  ok(/\n    environment: collector-production\n/.test(wf), 'deploy job runs in the collector-production environment');
  ok(/node test\/run_all\.mjs/.test(wf) && wf.indexOf('node test/run_all.mjs') < wf.indexOf('run: node .github/scripts/collector_deploy.mjs'), 'offline suite before the deploy step');
  ok(/workflow_run\.conclusion == 'success'/.test(wf), 'only after a successful Site run');
  for (const s of D.SECRETS) ok(wf.includes(`secrets.${s}`), 'workflow passes ' + s);
  ok(!/secrets\.(?!NEON_API_KEY|NEON_STORAGE_KEY_ID|NEON_STORAGE_SECRET|VERCEL_AUTOMATION_BYPASS_SECRET|VERCEL_TOKEN|GITHUB_TOKEN)/.test(wf), 'no other secret');
}

console.log(`PASS ${pass} checks (collector auto-deploy)`);
