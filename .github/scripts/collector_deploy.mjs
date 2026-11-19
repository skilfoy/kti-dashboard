// Automated collector deploy (runbook section 8, the procedure run by hand on 3 November 2026), run by
// .github/workflows/collector-auto-deploy.yml after the Site workflow deploys a main commit that changes the collector.
//
//   1. OLD   the hash of ti-docs/code/collector.mjs, confirmed as the pinned TI_CODE_SHA256 by the loader's own copy
//            code/by-sha/OLD.mjs.gz (since 3.2.0; code/by-sha/OLD.mjs for a copy kept earlier), written only after a
//            good run of a bundle whose hash matched the pin.
//   2. NEW   the bundle built in this run; the service deployment for the commit must report the same hash (op=sha).
//   3. Loader (only when neon/loader.mjs changed): code deploy of the loader, checked by the next scheduled run.
//   4. Wait  until 7 to 12 minutes after a trigger minute (:04, :19, :34, :49) with no lease held in op=status, so the
//            switch lands between runs (scheduled runs arrive up to six minutes late, now and then twelve).
//   5. Push  presigned uploads of code/collector.mjs and its gzipped copy code/collector.mjs.gz (read first by the
//            loader since 3.2.0) through the service (op=push, op=push&gz=1), each checked by reading it back.
//   6. Pin   environment-only deploy {TI_CODE_SHA256: NEW, TI_CODE_SHA256_PREV: OLD}; the other variables carry over.
//   7. Check op=run&job=gdelt and op=status report the new version, and code/by-sha/NEW.mjs.gz exists (probation
//            passed, no fallback).
//   On a failed check after step 5: both bucket copies and TI_CODE_SHA256 go back to OLD (and the loader to its previous
//   code if step 3 ran), and an issue "Collector deploy failed" carries the evidence. On success the merged pull request
//   gets a comment. DRY_RUN=1 does every read and prints every write without making it.
// Secrets (repository): NEON_API_KEY, NEON_STORAGE_KEY_ID, NEON_STORAGE_SECRET, VERCEL_AUTOMATION_BYPASS_SECRET,
// VERCEL_TOKEN; GITHUB_TOKEN from the workflow. No secret value is ever printed.
import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { deflateRawSync, crc32, gzipSync, gunzipSync } from 'node:zlib';
import { pathToFileURL } from 'node:url';

export const CONFIG = {
  project: 'square-breeze-55687399', branch: 'br-summer-scene-b8t048y2', slug: 'ti', bucket: 'ti-docs',
  storage: 'https://br-summer-scene-b8t048y2.storage.c-14.us-east-1.aws.neon.tech', region: 'us-east-1',
  vercelProject: 'prj_eISaKjcBNEHSxvuO7OvW6Nf94s5P', vercelTeam: 'team_J1AYAuYaWSGEP7cjBp80rdJp',
  neonApi: 'https://console.neon.tech/api/v2',
};
export const SECRETS = ['NEON_API_KEY', 'NEON_STORAGE_KEY_ID', 'NEON_STORAGE_SECRET', 'VERCEL_AUTOMATION_BYPASS_SECRET', 'VERCEL_TOKEN'];
export const TRIGGER_MINUTES = [4, 19, 34, 49];
export const WINDOW = { openAfterMin: 7, closeAfterMin: 12 };
export const COLLECTOR_PATHS = [/^neon\//, /^lib\/collector\.js$/, /^pipeline\/collector_build\.py$/];

const sha256 = (b) => createHash('sha256').update(b).digest('hex');

// ---------------------------------------------------------------- decisions (pure, tested)
export const missingSecrets = (env) => SECRETS.filter((k) => !env[k]);
export const collectorChanged = (files) => files.some((f) => COLLECTOR_PATHS.some((re) => re.test(f)));
export const loaderChanged = (files) => files.includes('neon/loader.mjs');
// Milliseconds to wait before the switch: 0 inside a window (7 to 12 minutes after a trigger minute), else the time to
// the next window's opening.
export function waitForWindow(now) {
  const d = new Date(now);
  const sec = d.getUTCMinutes() * 60 + d.getUTCSeconds() + d.getUTCMilliseconds() / 1000;
  for (let k = 0; k <= TRIGGER_MINUTES.length; k++) {
    const base = k < TRIGGER_MINUTES.length ? TRIGGER_MINUTES[k] : TRIGGER_MINUTES[0] + 60;
    const open = (base + WINDOW.openAfterMin) * 60, close = (base + WINDOW.closeAfterMin) * 60;
    const prevClose = (base - 15 + WINDOW.closeAfterMin) * 60;
    if (sec >= open && sec < close) return 0;
    if (sec < open && sec >= prevClose) return Math.round((open - sec) * 1000);
  }
  return 0;
}
export const inWindow = (now) => waitForWindow(now) === 0;
// The jobs whose lease is held at `now`, from op=status (leases: [{job, holder, until}]); an unreadable answer counts as
// held, so the switch waits rather than guesses.
// A run holds its lease for at most 15 minutes (the reports job, 900 s). A lease held further ahead is an operator's
// pause (19 November 2026: the retired ocia1 job's month-long hold kept the deploy waiting until it gave up), and a
// paused job does not run, so it does not block the switch.
export const PAUSE_MS = 20 * 60e3;
export function leasesHeld(status, now) {
  const L = status && Array.isArray(status.leases) ? status.leases : null;
  if (!L) return ['(status unreadable)'];
  return L.filter((l) => Date.parse(l.until) > now && Date.parse(l.until) <= now + PAUSE_MS).map((l) => l.job);
}
export function leasesPaused(status, now) {
  const L = status && Array.isArray(status.leases) ? status.leases : [];
  return L.filter((l) => Date.parse(l.until) > now + PAUSE_MS).map((l) => l.job);
}
// The loader's kept copy: gzipped since 3.2.0, plain before. Returns the source or null.
export async function keptCopy(S, sha) {
  const z = await S.get(`code/by-sha/${sha}.mjs.gz`);
  if (z) { try { const src = gunzipSync(z); if (sha256(src) === sha) return src; } catch { /* fall through */ } }
  const p = await S.get(`code/by-sha/${sha}.mjs`);
  return p && sha256(p) === sha ? p : null;
}
// Why the switch failed, from what step 7 saw; an empty list means it passed.
export function judgeSwitch(e) {
  const why = [];
  if (!e.envDeploy || e.envDeploy.status !== 'completed') why.push(`environment deploy not completed (${e.envDeploy ? e.envDeploy.status : 'no answer'})`);
  const names = new Set((e.envDeploy && e.envDeploy.environment) || []);
  const lost = (e.namesBefore || []).filter((n) => !names.has(n));
  if (lost.length) why.push('environment lost ' + lost.join(', '));
  if (!names.has('TI_CODE_SHA256_PREV')) why.push('TI_CODE_SHA256_PREV not listed');
  if (!e.run || e.run.http !== 200) why.push(`gdelt run answered HTTP ${e.run ? e.run.http : 'none'}`);
  else {
    if (e.run.version !== e.newVersion) why.push(`gdelt run answered version ${e.run.version}, expected ${e.newVersion} (the loader fell back or kept the old bundle)`);
    if (!e.run.ok) why.push('gdelt job failed: ' + String(e.run.error || 'no error text').slice(0, 200));
  }
  if (!e.status || e.status.version !== e.newVersion) why.push(`op=status reports version ${e.status ? e.status.version : 'none'}, expected ${e.newVersion}`);
  if (e.probation !== true) why.push(`code/by-sha/${String(e.newSha).slice(0, 12)}.mjs.gz missing or altered: the new bundle did not pass probation`);
  return why;
}
// Version string inside a built bundle.
export const versionOf = (src) => (String(src).match(/export const VERSION = '([^']+)'/) || [])[1] || null;

// ---------------------------------------------------------------- zip (one stored entry, for the loader deploy)
export function zipOne(name, data) {
  const body = Buffer.from(data), comp = deflateRawSync(body), nameB = Buffer.from(name), crc = crc32(body) >>> 0;
  const lh = Buffer.alloc(30);
  lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(body.length, 22); lh.writeUInt16LE(nameB.length, 26);
  const cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(8, 10); cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(comp.length, 20); cd.writeUInt32LE(body.length, 24);
  cd.writeUInt16LE(nameB.length, 28); cd.writeUInt32LE((0o100644 << 16) >>> 0, 38); cd.writeUInt32LE(0, 42);
  const local = Buffer.concat([lh, nameB, comp]), central = Buffer.concat([cd, nameB]);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10); eocd.writeUInt32LE(central.length, 12); eocd.writeUInt32LE(local.length, 16);
  return Buffer.concat([local, central, eocd]);
}

// ---------------------------------------------------------------- storage (SigV4, the credential's key pair)
const hmac = (k, s) => createHmac('sha256', k).update(s).digest();
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
function signingKey(secret, day, region) { let k = hmac('AWS4' + secret, day); k = hmac(k, region); k = hmac(k, 's3'); return hmac(k, 'aws4_request'); }
// Presigned URL (query-string SigV4, host the only signed header), as the operator endpoint's op=push expects.
export function presignUrl({ method, endpoint, path, keyId, secret, region = 'us-east-1', amzDate, expires = 600 }) {
  const ep = new URL(endpoint), day = amzDate.slice(0, 8), scope = `${day}/${region}/s3/aws4_request`;
  const q = { 'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': `${keyId}/${scope}`, 'X-Amz-Date': amzDate, 'X-Amz-Expires': String(expires), 'X-Amz-SignedHeaders': 'host' };
  const cq = Object.keys(q).sort().map((k) => enc(k) + '=' + enc(q[k])).join('&');
  const cpath = path.split('/').map(enc).join('/');
  const creq = [method, cpath, cq, 'host:' + ep.host + '\n', 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const sts = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(creq)].join('\n');
  const sig = createHmac('sha256', signingKey(secret, day, region)).update(sts).digest('hex');
  return `${ep.origin}${cpath}?${cq}&X-Amz-Signature=${sig}`;
}
const amzNow = () => new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
export function storage(env, http = fetch) {
  const key = (k) => `/${CONFIG.bucket}/${k}`;
  const url = (method, k) => presignUrl({ method, endpoint: CONFIG.storage, path: key(k), keyId: env.NEON_STORAGE_KEY_ID, secret: env.NEON_STORAGE_SECRET, region: CONFIG.region, amzDate: amzNow() });
  return {
    async get(k) { const r = await http(url('GET', k)); if (r.status === 404) return null; if (!r.ok) throw new Error(`storage GET ${k}: HTTP ${r.status}`); return Buffer.from(await r.arrayBuffer()); },
    async put(k, body) { const r = await http(url('PUT', k), { method: 'PUT', body, headers: { 'content-type': k.endsWith('.gz') ? 'application/gzip' : 'text/javascript' } }); if (!r.ok) throw new Error(`storage PUT ${k}: HTTP ${r.status}`); },
    uploadUrl: (k) => url('PUT', k),
  };
}

// ---------------------------------------------------------------- Neon API, Vercel API, operator endpoint, GitHub
export function neon(env, http = fetch) {
  const base = `${CONFIG.neonApi}/projects/${CONFIG.project}/branches/${CONFIG.branch}/functions/${CONFIG.slug}`;
  const auth = { authorization: 'Bearer ' + env.NEON_API_KEY, accept: 'application/json' };
  const fn = (j) => (j && j.function) || j;
  return {
    async get() { const r = await http(base, { headers: auth }); if (!r.ok) throw new Error('Neon get function: HTTP ' + r.status); return fn(await r.json()); },
    async deploy({ environment, zip }) {
      const form = new FormData();
      if (zip) form.append('zip', new Blob([zip], { type: 'application/zip' }), 'function.zip');
      if (environment) form.append('environment', JSON.stringify(environment));
      const r = await http(base + '/deployments', { method: 'POST', headers: auth, body: form });
      if (!r.ok) throw new Error('Neon deploy: HTTP ' + r.status + ' ' + (await r.text()).slice(0, 200));
      const j = await r.json();
      return (j && j.deployment) || j;
    },
  };
}
export async function deploymentFor(env, sha, http = fetch) {
  const u = `https://api.vercel.com/v6/deployments?projectId=${CONFIG.vercelProject}&teamId=${CONFIG.vercelTeam}&target=production&sha=${sha}&limit=5`;
  const r = await http(u, { headers: { authorization: 'Bearer ' + env.VERCEL_TOKEN } });
  if (!r.ok) throw new Error('Vercel deployments: HTTP ' + r.status);
  const d = ((await r.json()).deployments || []).find((x) => x.state === 'READY' || x.readyState === 'READY');
  return d ? d.url : null;
}
export function admin(env, host, http = fetch) {
  return async (query, timeoutMs = 60000) => {
    const r = await http(`https://${host}/api/admin?${query}`, { headers: { 'x-vercel-protection-bypass': env.VERCEL_AUTOMATION_BYPASS_SECRET, accept: 'application/json' }, signal: AbortSignal.timeout(timeoutMs) });
    let j = null; try { j = await r.json(); } catch { /* not JSON */ }
    return { http: r.status, json: j };
  };
}
export function github(env, http = fetch) {
  const call = async (method, path, body) => {
    const r = await http(`https://api.github.com/repos/${env.GITHUB_REPOSITORY}${path}`, { method, body: body ? JSON.stringify(body) : undefined,
      headers: { authorization: 'Bearer ' + env.GITHUB_TOKEN, accept: 'application/vnd.github+json', 'content-type': 'application/json', 'user-agent': 'kti-collector-deploy' } });
    if (!r.ok) throw new Error(`GitHub ${method} ${path}: HTTP ${r.status}`);
    return r.status === 204 ? null : r.json();
  };
  return {
    issue: (title, body) => call('POST', '/issues', { title, body, labels: ['collector-deploy'] }),
    async commentOnPr(sha, body) {
      const prs = await call('GET', `/commits/${sha}/pulls`);
      const pr = (prs || []).find((p) => p.merged_at) || (prs || [])[0];
      if (!pr) return null;
      await call('POST', `/issues/${pr.number}/comments`, { body });
      return pr.number;
    },
  };
}

// ---------------------------------------------------------------- the run
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
export async function deploy({ env = process.env, http = fetch, wait = sleep, now = () => Date.now(), log = console.log, bundlePath = 'neon/collector.mjs', loaderPath = 'neon/loader.mjs',
  prevLoader = null, files = [], sha = env.GITHUB_SHA } = {}) {
  const dry = env.DRY_RUN === '1';
  const ev = { sha, dry_run: dry, steps: [] };
  const step = (name, detail) => { ev.steps.push({ at: new Date(now()).toISOString(), name, ...detail }); log(`${dry ? '[dry run] ' : ''}${name}: ${JSON.stringify(detail)}`); };
  const missing = missingSecrets(env);
  if (missing.length) { log(`::notice::Collector deploy skipped: repository secrets not set: ${missing.join(', ')} (see docs/collector-auto-deploy.md)`); return { skipped: true, missing }; }
  const S = storage(env, http), N = neon(env, http), G = github(env, http);
  const src = readFileSync(bundlePath), NEW = sha256(src), newVersion = versionOf(src);
  let OLD = null, oldSrc = null, oldGz = null, pushed = false, pinned = false, loaderDeployed = false, namesBefore = [];
  try {
    // 1. OLD, confirmed by the loader's copy.
    oldSrc = await S.get('code/collector.mjs');
    if (!oldSrc) throw new Error('ti-docs/code/collector.mjs not found');
    OLD = sha256(oldSrc);
    if (!(await keptCopy(S, OLD))) throw new Error(`OLD ${OLD.slice(0, 12)} is not confirmed: code/by-sha/${OLD}.mjs.gz (or .mjs) is missing or altered, so the bucket object may not be the pinned bundle`);
    oldGz = await S.get('code/collector.mjs.gz');
    const before = await N.get();
    namesBefore = (before.current_deployment && before.current_deployment.environment) || [];
    step('old', { old: OLD, old_version: versionOf(oldSrc), new: NEW, new_version: newVersion, deployment: before.current_deployment && before.current_deployment.id, names: namesBefore.length });
    const withLoader = loaderChanged(files) && !!prevLoader;
    if (NEW === OLD && !withLoader) { step('nothing to deploy', { reason: 'the built bundle is already pinned' }); return { ok: true, unchanged: true, evidence: ev }; }
    if (!namesBefore.includes('TI_CODE_SHA256')) throw new Error('the function does not list TI_CODE_SHA256');
    // 2. The service deployment for this commit serves the same bundle.
    let host = null;
    for (let k = 0; k < 20 && !host; k++) { host = await deploymentFor(env, sha, http); if (!host) await wait(30000); }
    if (!host) throw new Error('no READY production deployment for ' + sha);
    const A = admin(env, host, http);
    const shaAns = await A('op=sha');
    const served = shaAns.json && shaAns.json.assets && shaAns.json.assets.code && shaAns.json.assets.code.sha256;
    step('service', { deployment: host, code_sha256: served });
    if (served !== NEW) throw new Error(`deployment ${host} serves code ${served}, the build is ${NEW}`);
    // 3. Loader, only when it changed: code deploy, then the next scheduled run must be good.
    if (withLoader) {
      const w = waitForWindow(now()); if (w) { step('wait for window (loader)', { ms: w }); if (!dry) await wait(w); }
      if (dry) step('would deploy loader', { bytes: readFileSync(loaderPath).length });
      else {
        const d = await N.deploy({ zip: zipOne('index.mjs', readFileSync(loaderPath)) });
        loaderDeployed = true;
        step('loader deployed', { deployment: d.id, status: d.status });
        let fnNow = await N.get();
        for (let k = 0; k < 12 && fnNow.current_deployment.status !== 'completed'; k++) { await wait(10000); fnNow = await N.get(); }
        if (fnNow.current_deployment.status !== 'completed') throw new Error('loader deployment did not complete: ' + fnNow.current_deployment.status);
        // The next scheduled run: leave this window, then wait for the next one to open (2 minutes after the trigger).
        const t0 = now();
        while (inWindow(now())) await wait(60000);
        await wait(waitForWindow(now()));
        const st = await A('op=status', 30000);
        const ran = ((st.json && st.json.runs) || []).filter((r) => Date.parse(r.started_at) > t0);
        step('loader check', { runs_after: ran.length, ok: ran.filter((r) => r.ok).length });
        if (!ran.length || !ran.some((r) => r.job === 'gdelt' && r.ok)) throw new Error('no good scheduled run after the loader deploy');
      }
    }
    if (NEW === OLD) { step('collector unchanged', { reason: 'loader only' }); return { ok: true, evidence: ev }; }
    // 4. Wait for a window with no lease held, then 5. push and 6. pin within it.
    for (let k = 0; ; k++) {
      const w = waitForWindow(now());
      if (w) { step('window', { wait_ms: w }); if (dry) break; await wait(w); }
      const st = await A('op=status', 30000), held = leasesHeld(st.json, now());
      if (!held.length) { step('quiet', { leases_held: 0, paused: leasesPaused(st.json, now()) }); break; }
      if (k >= 40) throw new Error('no quiet moment in 40 tries; leases held: ' + held.join(', '));
      step('leases held', { jobs: held });
      if (dry) break;
      await wait(30000);
    }
    if (dry) step('would push and pin', { upload: ['ti-docs/code/collector.mjs', 'ti-docs/code/collector.mjs.gz'], environment: { TI_CODE_SHA256: NEW, TI_CODE_SHA256_PREV: OLD } });
    else {
      const push = await A('op=push&asset=code&u=' + encodeURIComponent(S.uploadUrl('code/collector.mjs')));
      pushed = true;
      const back = await S.get('code/collector.mjs');
      step('pushed', { http: push.http, sha256: push.json && push.json.sha256, read_back: back && sha256(back) });
      if (push.http !== 200 || !back || sha256(back) !== NEW) throw new Error('upload not confirmed: the object reads back as ' + (back && sha256(back)));
      const pushGz = await A('op=push&asset=code&gz=1&u=' + encodeURIComponent(S.uploadUrl('code/collector.mjs.gz')));
      const backGz = await S.get('code/collector.mjs.gz');
      let gzSha = null; try { gzSha = backGz && sha256(gunzipSync(backGz)); } catch { gzSha = 'unreadable'; }
      step('pushed gzipped copy', { http: pushGz.http, read_back: gzSha });
      if (pushGz.http !== 200 || gzSha !== NEW) throw new Error('gzipped upload not confirmed: it reads back as ' + gzSha);
      const d = await N.deploy({ environment: { TI_CODE_SHA256: NEW, TI_CODE_SHA256_PREV: OLD } });
      pinned = true;
      let fnNow = await N.get();
      for (let k = 0; k < 6 && fnNow.current_deployment.status !== 'completed'; k++) { await wait(5000); fnNow = await N.get(); }
      step('pinned', { deployment: d.id, status: fnNow.current_deployment.status, names: fnNow.current_deployment.environment });
      // 7. Checks.
      let run = await A('op=run&job=gdelt', 60000);
      const job = (j) => ((j && j.jobs) || []).find((x) => x.job === 'gdelt') || {};
      if (job(run.json).skipped) { await wait(20000); run = await A('op=run&job=gdelt', 60000); }
      // An instance that was warm before the pin keeps serving the old bundle until it is recycled (19 November 2026: the
      // gdelt run reached a new instance, op=status an old one 2 seconds later). Ask again for up to two minutes.
      let status = await A('op=status', 30000);
      for (let k = 0; k < 6 && !(status.json && status.json.version === newVersion); k++) { await wait(20000); status = await A('op=status', 30000); }
      const e = { envDeploy: fnNow.current_deployment, namesBefore, newVersion, newSha: NEW,
        run: { http: run.http, version: run.json && run.json.version, ok: !!job(run.json).ok, error: job(run.json).error }, status: { version: status.json && status.json.version },
        probation: !!(await keptCopy(S, NEW)) };
      const why = judgeSwitch(e);
      step('checks', { run: e.run, status: e.status, probation: e.probation, failures: why });
      if (why.length) throw new Error(why.join('; '));
    }
    const msg = `Collector deployed: version ${newVersion}, bundle \`${NEW}\` (was \`${OLD}\`, now TI_CODE_SHA256_PREV). gdelt ran on the new bundle, op=status reports ${newVersion}, and the bundle passed probation (code/by-sha copy present).`;
    if (dry) step('would comment on the merged pull request', { body: msg });
    else step('commented', { pr: await G.commentOnPr(sha, msg + `\n\nRun: ${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`) });
    return { ok: true, evidence: ev };
  } catch (err) {
    step('failed', { error: String(err.message || err) });
    const restored = [];
    if (!dry) {
      try { if (pushed && oldSrc) { await S.put('code/collector.mjs', oldSrc); restored.push('bucket object to OLD'); } } catch (e) { restored.push('bucket restore FAILED: ' + e.message); }
      try { if (pushed && oldSrc) { await S.put('code/collector.mjs.gz', oldGz || gzipSync(oldSrc, { level: 9 })); restored.push('gzipped copy to OLD'); } } catch (e) { restored.push('gzipped copy restore FAILED: ' + e.message); }
      try { if (pinned && OLD) { await N.deploy({ environment: { TI_CODE_SHA256: OLD } }); restored.push('TI_CODE_SHA256 to OLD'); } } catch (e) { restored.push('pin restore FAILED: ' + e.message); }
      try { if (loaderDeployed && prevLoader) { await N.deploy({ zip: zipOne('index.mjs', prevLoader) }); restored.push('loader to its previous code'); } } catch (e) { restored.push('loader restore FAILED: ' + e.message); }
    }
    step('rollback', { restored });
    const body = [`The automated collector deploy of ${sha} failed${dry ? ' (dry run)' : ''}.`, '', `- Error: ${String(err.message || err)}`, `- OLD: \`${OLD}\``, `- NEW: \`${NEW}\` (${newVersion})`,
      `- Restored: ${restored.length ? restored.join('; ') : 'nothing needed (no production write had been made)'}`, '', 'Steps:', '```json', JSON.stringify(ev.steps, null, 1).slice(0, 6000), '```', '',
      `Run: ${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}. Manual procedure: pipeline/RUNBOOK.md section 8.`].join('\n');
    if (dry) log('[dry run] would open issue "Collector deploy failed"');
    else { try { await G.issue('Collector deploy failed', body); } catch (e) { log('could not open the issue: ' + e.message); } }
    return { ok: false, error: String(err.message || err), restored, evidence: ev };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const files = String(process.env.CHANGED_FILES || '').split('\n').filter(Boolean);
  let prevLoader = null;
  try { prevLoader = process.env.PREV_LOADER ? readFileSync(process.env.PREV_LOADER) : null; } catch { /* none */ }
  deploy({ files, prevLoader, sha: process.env.DEPLOY_SHA || process.env.GITHUB_SHA }).then((r) => { if (r && r.ok === false) process.exit(1); }).catch((e) => { console.error(e); process.exit(1); });
}
