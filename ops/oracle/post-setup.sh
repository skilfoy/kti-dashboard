#!/bin/bash
# Run on the KTI server as root after bootstrap: memory floor for Oracle's idle-reclamation rule, and the migrate tool.
set -euo pipefail
# Oracle may reclaim an Always Free A1 instance when CPU (p95), network and memory all stay under 20% for 7 days. The
# database and gateway use little memory, so a resident 3 GB buffer keeps memory above the line (12 GB total). Converting
# the tenancy to Pay As You Go also exempts it; Always Free resources stay free there.
if [ "$(awk '/MemTotal/ {print int($2/1048576)}' /proc/meminfo)" -ge 8 ]; then
cat > /usr/local/bin/kti-ballast.mjs <<'EOS'
const b = Buffer.alloc(3 * 1024 ** 3);
for (let i = 0; i < b.length; i += 4096) b[i] = 1;
setInterval(() => { for (let i = 0; i < b.length; i += 4096 * 64) b[i] ^= 1; }, 600000);
EOS
cat > /etc/systemd/system/kti-ballast.service <<'EOS'
[Unit]
Description=KTI memory floor (Always Free idle rule)
[Service]
ExecStart=/usr/bin/node --max-old-space-size=64 /usr/local/bin/kti-ballast.mjs
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
EOS
systemctl daemon-reload && systemctl enable --now kti-ballast
fi

# kti-migrate: copy schema ti from Neon. The connection string is read from the terminal and never stored.
cat > /usr/local/bin/kti-migrate <<'EOS'
#!/bin/bash
set -euo pipefail
read -rsp 'Neon connection string: ' NEON_URL; echo
f=/var/backups/kti/neon-import-$(date -u +%Y%m%dT%H%MZ).dump
PGSSLMODE=require pg_dump "$NEON_URL" -Fc --no-owner --no-acl -n ti -f "$f"
unset NEON_URL
chown postgres "$f"
sudo -u postgres psql -q -d threatintel -c "DROP SCHEMA IF EXISTS ti CASCADE"
cat "$f" | sudo -u kti pg_restore -d threatintel --no-owner --no-acl --exit-on-error
sudo -u kti psql -q -d threatintel -c "UPDATE ti.lease SET until = 'epoch'" -c "ANALYZE"
sudo -u kti psql -d threatintel -At -c "SELECT relname||'='||n_live_tup FROM pg_stat_user_tables WHERE schemaname='ti' ORDER BY n_live_tup DESC LIMIT 12"
echo "restored from $f"
EOS
chmod 750 /usr/local/bin/kti-migrate
echo post-setup ok
