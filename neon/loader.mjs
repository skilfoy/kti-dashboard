// Neon Function "ti" entry point. Loads the collector module from the private ti-docs bucket (code/collector.mjs)
// with the branch's injected storage credentials, refuses it unless its SHA-256 equals TI_CODE_SHA256, and hands
// every request to it. Updating the collector is an upload plus a config-only redeploy that sets the new hash.
import { createHash, createHmac } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const E = process.env;
let mod = null, pending = null;
const hm = (k, s) => createHmac('sha256', k).update(s).digest();

async function s3get(key) {
  const ep = new URL(E.AWS_ENDPOINT_URL_S3), region = E.AWS_REGION || 'us-east-1';
  const path = '/' + (E.TI_BUCKET || 'ti-docs') + '/' + key;
  const d = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, ''), day = d.slice(0, 8);
  const empty = createHash('sha256').update('').digest('hex');
  const signed = 'host;x-amz-content-sha256;x-amz-date';
  const creq = ['GET', path, '', 'host:' + ep.host, 'x-amz-content-sha256:' + empty, 'x-amz-date:' + d, '', signed, empty].join('\n');
  const scope = day + '/' + region + '/s3/aws4_request';
  const sts = ['AWS4-HMAC-SHA256', d, scope, createHash('sha256').update(creq).digest('hex')].join('\n');
  let k = hm('AWS4' + E.AWS_SECRET_ACCESS_KEY, day); k = hm(k, region); k = hm(k, 's3'); k = hm(k, 'aws4_request');
  const sig = createHmac('sha256', k).update(sts).digest('hex');
  return fetch(ep.origin + path, { headers: { 'x-amz-date': d, 'x-amz-content-sha256': empty,
    authorization: 'AWS4-HMAC-SHA256 Credential=' + E.AWS_ACCESS_KEY_ID + '/' + scope + ', SignedHeaders=' + signed + ', Signature=' + sig } });
}

async function load() {
  if (!E.TI_CODE_SHA256) throw new Error('TI_CODE_SHA256 is not set');
  const r = await s3get('code/collector.mjs');
  if (!r.ok) throw new Error('collector code: storage HTTP ' + r.status);
  const src = await r.text();
  const h = createHash('sha256').update(src).digest('hex');
  if (h !== E.TI_CODE_SHA256) throw new Error('collector code hash ' + h + ' does not match TI_CODE_SHA256');
  try {
    return await import('data:text/javascript;base64,' + Buffer.from(src).toString('base64'));
  } catch (e) {
    const file = '/tmp/collector-' + h.slice(0, 16) + '.mjs';
    writeFileSync(file, src);
    return import(pathToFileURL(file).href);
  }
}

export default {
  async fetch(request) {
    try {
      if (!mod) mod = await (pending || (pending = load().finally(() => { pending = null; })));
      return await mod.default.fetch(request);
    } catch (e) {
      console.error('loader:', e && e.stack || e);
      return new Response(JSON.stringify({ error: String((e && e.message) || e), stage: mod ? 'handler' : 'load' }), { status: 503, headers: { 'content-type': 'application/json' } });
    }
  },
};
