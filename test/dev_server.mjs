// Local preview of the site: serves public/ with the headers vercel.json sets, and answers /api/* either from saved
// service answers (--live DIR: one <dataset id>.json envelope {status, text} per live query) or with a 503, which the
// page shows as its "unavailable" state. The real service runs only on Vercel, where it reaches the collector.
//   node test/dev_server.mjs [--port 4173] [--live DIR]
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUB = path.join(ROOT, 'public');
const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const PORT = +arg('--port', process.env.PORT || 4173);
const LIVE = arg('--live', '');
const VJ = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.txt': 'text/plain; charset=utf-8', '.png': 'image/png', '.ico': 'image/x-icon' };

// vercel.json header rules, matched the way Vercel matches a source pattern (path-to-regexp groups).
const rules = (VJ.headers || []).map((h) => ({ rx: new RegExp('^' + h.source.replace(/\(\.\*\)/g, '.*').replace(/\(([^)]+)\)/g, '($1)') + '$'), headers: h.headers }));
function headersFor(p) {
  const out = {};
  for (const r of rules) if (r.rx.test(p)) for (const { key, value } of r.headers) out[key] = value;
  return out;
}

function liveAnswer(url) {
  if (!LIVE) return { status: 503, text: JSON.stringify({ error: 'the threat-feeds service is not running in this local preview' }) };
  const site = JSON.parse(fs.readFileSync(path.join(PUB, 'site.json'), 'utf8'));
  let best = null;
  for (const [id, d] of Object.entries(site.datasets)) {
    if (d.kind !== 'query') continue;
    const u = new URL(d.url, 'http://x');
    if (u.pathname !== url.pathname) continue;
    const fixed = [...u.searchParams].filter(([, v]) => !/\{\{/.test(v));
    if (!fixed.every(([k, v]) => url.searchParams.get(k) === v)) continue;
    if (!best || fixed.length > best.n) best = { id, n: fixed.length };
  }
  const f = best && path.join(LIVE, best.id + '.json');
  if (!f || !fs.existsSync(f)) return { status: 503, text: JSON.stringify({ error: 'no saved answer for ' + url.pathname }) };
  const env = JSON.parse(fs.readFileSync(f, 'utf8'));
  if (best.id === 'live_enrich') {
    const cap = JSON.parse(env.text);
    if (String(cap.q) !== String(url.searchParams.get('q') || '').replace(/^AS/i, '')) return { status: 200, text: JSON.stringify({ ok: true, type: url.searchParams.get('type'), q: url.searchParams.get('q'), at: new Date().toISOString(), results: [] }) };
  }
  return { status: env.status || 200, text: env.text };
}

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) {
    const a = liveAnswer(url);
    res.writeHead(a.status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    return res.end(a.text);
  }
  let p = decodeURIComponent(url.pathname);
  if (p.endsWith('/')) p += 'index.html';
  const file = path.normalize(path.join(PUB, p));
  if (!file.startsWith(PUB)) { res.writeHead(400); return res.end(); }
  const send = (status, f) => {
    res.writeHead(status, { 'content-type': TYPES[path.extname(f)] || 'application/octet-stream', ...headersFor(url.pathname) });
    fs.createReadStream(f).pipe(res);
  };
  fs.stat(file, (err, st) => (err || !st.isFile() ? send(404, path.join(PUB, '404.html')) : send(200, file)));
}).listen(PORT, () => console.log(`site preview on http://localhost:${PORT}` + (LIVE ? ` (live answers from ${LIVE})` : ' (service offline)')));
