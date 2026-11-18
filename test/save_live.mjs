// Saves the production service's current answer to every live query dataset in public/site.json, one envelope
// {status, text} per dataset id, the shape test/dev_server.mjs --live DIR serves. The browser check then renders
// the page against real data shapes: on 17 November 2026 four panels threw on live answers (list and record cells
// arrive as JSON text) while the offline check passed. Datasets that take the reader's input ({{...}}) stay idle.
//   node test/save_live.mjs [--base https://intel.kilfoycyber.com] [--out live-answers]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const BASE = arg('--base', 'https://intel.kilfoycyber.com').replace(/\/+$/, '');
const OUT = path.resolve(arg('--out', 'live-answers'));
const site = JSON.parse(fs.readFileSync(path.join(ROOT, 'public', 'site.json'), 'utf8'));
const todo = Object.entries(site.datasets).filter(([, d]) => d.kind === 'query' && !/\{\{/.test(d.url));
fs.mkdirSync(OUT, { recursive: true });

async function save([id, d]) {
  const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 40000);
  let status = 0, text = '';
  try {
    const r = await fetch(BASE + d.url, { signal: ctl.signal, headers: { 'user-agent': 'kti-site-check/1.0 (+https://github.com/skilfoy/kti-dashboard)' } });
    status = r.status; text = await r.text();
  } catch (e) { text = JSON.stringify({ error: String((e && e.message) || e) }); }
  finally { clearTimeout(timer); }
  fs.writeFileSync(path.join(OUT, id + '.json'), JSON.stringify({ status, text }));
  return [id, status];
}
const results = [];
for (let i = 0; i < todo.length; i += 4) results.push(...(await Promise.all(todo.slice(i, i + 4).map(save))));
const bad = results.filter(([, s]) => s !== 200);
console.log(`saved ${results.length} live answers from ${BASE}: ${results.length - bad.length} answered 200` + (bad.length ? `; ${bad.map(([id, s]) => id + ' ' + s).join(', ')}` : ''));
