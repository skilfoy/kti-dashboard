#!/bin/bash
ROLE=search
# KTI Oracle server bootstrap (Ubuntu 24.04, Ampere A1). Runs once as cloud-init user data and logs to
# /var/log/kti-bootstrap.log. It installs Postgres 17 (local socket only), the SQL gateway, SearXNG, Caddy (automatic
# HTTPS on <public-ip>.sslip.io until a kilfoycyber.com name is assigned), nightly backups and host hardening.
# Tokens are generated here and kept in /etc/kti (root-only); none is written to this file.
set -euxo pipefail
exec > >(tee -a /var/log/kti-bootstrap.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
# ROLE: all (database, gateway and SearXNG on one A1 server), db (database and gateway), search (SearXNG only).
ROLE=${ROLE:-all}
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
# Small servers (the 1 GB micros) get a swap file so a burst never ends in the out-of-memory killer.
if [ "$MEM_MB" -lt 4000 ] && [ ! -f /swapfile ]; then
  fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab
  sysctl -w vm.swappiness=10 && echo 'vm.swappiness=10' > /etc/sysctl.d/90-kti.conf
fi

apt-get update
apt-get install -y curl ca-certificates gnupg lsb-release jq fail2ban unattended-upgrades debian-keyring debian-archive-keyring apt-transport-https
[ "$ROLE" = db ] || apt-get install -y docker.io

# Postgres 17 (PGDG)
install -d /usr/share/postgresql-common/pgdg
curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list
# Node 24 (NodeSource) and Caddy (Cloudsmith)
curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy
[ "$ROLE" = search ] || apt-get install -y postgresql-17 postgresql-contrib-17 nodejs

if [ "$ROLE" != search ]; then
# Postgres: socket only, tuned for 12 GB, UTC
PGC=/etc/postgresql/17/main
if [ "$MEM_MB" -lt 4000 ]; then SB=128MB; EC=512MB; WM=4MB; MW=64MB; MC=25; else SB=2GB; EC=6GB; WM=32MB; MW=512MB; MC=60; fi
cat > $PGC/conf.d/kti.conf <<EOF
listen_addresses = ''
shared_buffers = $SB
effective_cache_size = $EC
work_mem = $WM
maintenance_work_mem = $MW
max_connections = $MC
timezone = 'UTC'
log_timezone = 'UTC'
shared_preload_libraries = 'pg_stat_statements'
EOF
systemctl restart postgresql
id kti 2>/dev/null || useradd --system --create-home --shell /usr/sbin/nologin kti
sudo -u postgres psql -v ON_ERROR_STOP=1 <<'EOF'
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kti') THEN CREATE ROLE kti LOGIN; END IF; END $$;
SELECT 'CREATE DATABASE threatintel OWNER kti' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'threatintel')\gexec
EOF
sudo -u postgres psql -d threatintel -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS pg_trgm; CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"

# Tokens (root-only)
install -d -m 700 /etc/kti
[ -f /etc/kti/sqlgw.env ] || echo "SQLGW_TOKEN=$(openssl rand -hex 32)" > /etc/kti/sqlgw.env
chmod 600 /etc/kti/*.env

# SQL gateway
install -d -o kti -g kti /opt/kti-sqlgw
cat > /opt/kti-sqlgw/server.mjs <<'EOF_SERVER'
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
EOF_SERVER
cat > /opt/kti-sqlgw/package.json <<'EOF_PKG'
{ "name": "kti-sqlgw", "private": true, "type": "module", "dependencies": { "pg": "^8.13.0" } }
EOF_PKG
chown -R kti:kti /opt/kti-sqlgw
sudo -u kti -H bash -c 'cd /opt/kti-sqlgw && npm install --omit=dev --no-audit --no-fund'
POOL=10; [ "$MEM_MB" -lt 4000 ] && POOL=4
cat > /etc/systemd/system/kti-sqlgw.service <<EOF
[Unit]
Description=KTI SQL gateway
After=network.target postgresql.service
[Service]
User=kti
EnvironmentFile=/etc/kti/sqlgw.env
Environment=SQLGW_POOL=$POOL
ExecStart=/usr/bin/node /opt/kti-sqlgw/server.mjs
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now kti-sqlgw

fi

install -d -m 700 /etc/kti
[ -f /etc/kti/searx.env ] || echo "SEARX_PATH=sx-$(openssl rand -hex 24)" > /etc/kti/searx.env; chmod 600 /etc/kti/searx.env
if [ "$ROLE" != db ]; then
# SearXNG (JSON output on, bound to localhost)
install -d /etc/searxng
[ -f /etc/searxng/settings.yml ] || cat > /etc/searxng/settings.yml <<EOF
use_default_settings: true
server:
  secret_key: "$(openssl rand -hex 32)"
  limiter: false
  image_proxy: false
search:
  formats: [html, json]
  safe_search: 0
EOF
docker rm -f searxng 2>/dev/null || true
docker run -d --name searxng --restart unless-stopped -p 127.0.0.1:8888:8080 -v /etc/searxng:/etc/searxng:rw searxng/searxng:latest

fi

# Host firewall: the Oracle Ubuntu image rejects all but SSH; open 80 (certificate challenge) and 443
iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp -m state --state NEW --dport 80 -j ACCEPT
iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp -m state --state NEW --dport 443 -j ACCEPT
netfilter-persistent save || true

# Caddy: HTTPS for <ip>.sslip.io; /sql to the gateway, /<secret path>/ to SearXNG, everything else 404
PUBIP=$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')
HOST=${PUBIP//./-}.sslip.io
. /etc/kti/searx.env
cat > /etc/caddy/Caddyfile <<EOF
$HOST {
  encode zstd gzip
$([ "$ROLE" != search ] && printf '  handle /sql* {\n    reverse_proxy 127.0.0.1:8080\n  }\n  handle /healthz {\n    reverse_proxy 127.0.0.1:8080\n  }\n')
$([ "$ROLE" != db ] && printf '  handle_path /%s/* {\n    reverse_proxy 127.0.0.1:8888\n  }\n' "$SEARX_PATH")
  handle {
    respond 404
  }
  header -Server
}
EOF
echo "$HOST" > /etc/kti/host
systemctl restart caddy


if [ "$ROLE" != search ]; then
# Nightly backups: custom-format dump, 7 kept locally; uploaded when /etc/kti/backup_par holds an Object Storage
# pre-authenticated request URL (write-only) ending in /o/
install -d -o postgres -g postgres -m 700 /var/backups/kti
cat > /usr/local/bin/kti-backup <<'EOF'
#!/bin/bash
set -euo pipefail
f=/var/backups/kti/threatintel-$(date -u +%Y%m%dT%H%MZ).dump
sudo -u postgres pg_dump -Fc -d threatintel -f "$f"
ls -1t /var/backups/kti/threatintel-*.dump | tail -n +8 | xargs -r rm -f
if [ -s /etc/kti/backup_par ]; then curl -fsS -X PUT --upload-file "$f" "$(cat /etc/kti/backup_par)$(basename "$f")" >/dev/null; fi
EOF
chmod 755 /usr/local/bin/kti-backup
echo '17 9 * * * root /usr/local/bin/kti-backup >> /var/log/kti-backup.log 2>&1' > /etc/cron.d/kti-backup

fi

systemctl enable --now fail2ban
echo "KTI bootstrap complete: $HOST"
