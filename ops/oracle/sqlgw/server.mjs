// KTI SQL gateway: the HTTPS endpoint the collector speaks to on the Oracle server. It answers the same contract as
// Neon's SQL over HTTP (POST /sql, one statement {query, params} or a transaction {queries: [...]}, raw text values,
// array rows, field names and type ids), so the collector changes only its URL and credential. Postgres listens on the
// local socket only; this service authenticates as the OS user `kti` by peer authentication, so no database password
// exists. Callers present a bearer token (SQLGW_TOKEN in /etc/kti/sqlgw.env, root-only).
import http from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import pg from 'pg';

const TOKEN = process.env.SQLGW_TOKEN || '';
if (TOKEN.length < 32) { console.error('SQLGW_TOKEN missing or short'); process.exit(1); }
const PORT = +process.env.SQLGW_PORT || 8080, MAX_BODY = 32 * 1024 * 1024;
const pool = new pg.Pool({ host: process.env.SQLGW_PGHOST || '/var/run/postgresql', database: process.env.SQLGW_DB || 'threatintel', max: +process.env.SQLGW_POOL || 10, idleTimeoutMillis: 30000,
  options: '-c TimeZone=UTC -c statement_timeout=90000 -c idle_in_transaction_session_timeout=120000' });
const raw = { getTypeParser: () => (v) => v };
const digest = (s) => createHash('sha256').update(String(s)).digest();
const want = digest('Bearer ' + TOKEN);
const authed = (req) => timingSafeEqual(digest(req.headers.authorization || ''), want);

async function one(client, q) {
  const r = await client.query({ text: String(q.query || ''), values: Array.isArray(q.params) ? q.params : [], rowMode: 'array', types: raw });
  return { command: r.command, rowCount: r.rowCount, fields: (r.fields || []).map((f) => ({ name: f.name, dataTypeID: f.dataTypeID })), rows: r.rows || [] };
}
function send(res, status, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(b), 'cache-control': 'no-store' });
  res.end(b);
}
const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    try { await pool.query('SELECT 1'); return send(res, 200, { ok: true }); } catch (e) { return send(res, 503, { ok: false }); }
  }
  if (req.method !== 'POST' || !req.url.startsWith('/sql')) return send(res, 404, { message: 'not found' });
  if (!authed(req)) return send(res, 401, { message: 'unauthorized' });
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > MAX_BODY) return send(res, 413, { message: 'body too large' }); chunks.push(c); }
  let body;
  try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return send(res, 400, { message: 'invalid JSON' }); }
  const t0 = Date.now(); let client;
  try {
    client = await pool.connect();
    if (Array.isArray(body.queries)) {
      await client.query('BEGIN');
      const results = [];
      try { for (const q of body.queries) results.push(await one(client, q)); await client.query('COMMIT'); }
      catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
      send(res, 200, { results });
    } else send(res, 200, await one(client, body));
  } catch (e) {
    send(res, 400, { message: String((e && e.message) || e), code: e && e.code });
  } finally {
    if (client) client.release();
    const ms = Date.now() - t0; if (ms > 5000) console.log(JSON.stringify({ slow_ms: ms, n: Array.isArray(body && body.queries) ? body.queries.length : 1 }));
  }
});
server.requestTimeout = 120000;
server.listen(PORT, '127.0.0.1', () => console.log(`sqlgw on 127.0.0.1:${PORT}`));
