// Decode a saved web_fetch_vercel_url answer with the page's own wire decoders (page/tfwire.js) and summarize it.
const fs = require('fs'), vm = require('vm'), path = require('path');
const [, , file, kind] = process.argv;
const ctx = { window: {}, globalThis: {}, atob: (s) => Buffer.from(s, 'base64').toString('binary'), TextDecoder, console };
ctx.window = ctx; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'tfwire.js'), 'utf8'), ctx);
const W = ctx.TI_WIRE;
let raw = fs.readFileSync(file, 'utf8');
let env = JSON.parse(raw);
if (Array.isArray(env)) env = JSON.parse(env[0].text);          // tool-result wrapper
if (env && env.type === 'text' && env.text) env = JSON.parse(env.text);
const body = typeof env.text === 'string' ? JSON.parse(env.text) : env;
const packed = body.enc;
const doc = W.unpack(body);
console.log('status', env.status, 'packed', packed, 'wire chars', JSON.stringify(body).length, 'decoded bytes', JSON.stringify(doc).length, 'served_from', doc.served_from, 'age_min', doc.age_min, 'generated', doc.generated);
if (kind === 'threatmap') {
  const nodes = W.threatmapNodes(doc);
  const by = {}; for (const n of nodes) by[n.layer] = (by[n.layer] || 0) + 1;
  const fresh = nodes.filter((n) => n.new).length, stale = nodes.filter((n) => n.stale).length;
  console.log('nodes', nodes.length, by, 'new', fresh, 'stale', stale, 'rows', (doc.rows || []).length, 'kinds', [...new Set(doc.rows.map((r) => r.kind))]);
  console.log('layers', JSON.stringify(doc.layers));
  const s = nodes.find((n) => n.layer === 'ioc'); console.log('sample ioc', JSON.stringify(s));
  const bad = nodes.filter((n) => !isFinite(n.lat) || !isFinite(n.lon) || !n.ip || !n.ref);
  console.log('invalid nodes', bad.length);
} else {
  const kinds = {}; for (const r of doc.rows || []) kinds[r.kind || '-'] = (kinds[r.kind || '-'] || 0) + 1;
  console.log('rows', (doc.rows || []).length, kinds);
  console.log('first', JSON.stringify((doc.rows || [])[0]).slice(0, 400));
  if (kind === 'gdelt') { const fl = doc.rows.filter((r) => r.kind === 'flow'); console.log('flows', fl.length, 'multi-article', fl.filter((f) => (f.articles || 1) >= 2).length, 'coverage', doc.coverage, doc.coverage_live, 'base30_days', doc.base30_days, 'latest', doc.latest); }
}
