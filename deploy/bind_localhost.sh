#!/usr/bin/env bash
set -euo pipefail

echo "Binding PostgreSQL and Redis to 127.0.0.1..."

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0"
  exit 1
fi

shopt -s nullglob
pg_confs=(/etc/postgresql/*/main/postgresql.conf)
if [ ${#pg_confs[@]} -eq 0 ]; then
  echo "PostgreSQL config not found under /etc/postgresql"
  exit 1
fi

for conf in "${pg_confs[@]}"; do
  if grep -qE '^#?listen_addresses\s*=' "$conf"; then
    sed -i "s/^#\?listen_addresses\s*=.*/listen_addresses = 'localhost'/" "$conf"
  else
    echo "listen_addresses = 'localhost'" >> "$conf"
  fi
  echo "Updated $conf"
done

hba_files=(/etc/postgresql/*/main/pg_hba.conf)
for hba in "${hba_files[@]}"; do
  if ! grep -qE '^host\s+all\s+all\s+127\.0\.0\.1/32' "$hba"; then
    echo "host    all    all    127.0.0.1/32    scram-sha-256" >> "$hba"
  fi
  echo "Checked $hba"
done

if systemctl list-unit-files | grep -q '^postgresql'; then
  systemctl restart postgresql
else
  echo "postgresql service not installed; skipped restart"
fi

REDIS_CONF=""
for candidate in /etc/redis/redis.conf /etc/redis.conf; do
  if [ -f "$candidate" ]; then
    REDIS_CONF="$candidate"
    break
  fi
done

if [ -z "$REDIS_CONF" ]; then
  echo "Redis config not found"
  exit 1
fi

if grep -qE '^#?bind\s+' "$REDIS_CONF"; then
  sed -i "s/^#\?bind\s\+.*/bind 127.0.0.1 ::1/" "$REDIS_CONF"
else
  echo "bind 127.0.0.1 ::1" >> "$REDIS_CONF"
fi

if grep -qE '^#?protected-mode\s+' "$REDIS_CONF"; then
  sed -i "s/^#\?protected-mode\s\+.*/protected-mode yes/" "$REDIS_CONF"
else
  echo "protected-mode yes" >> "$REDIS_CONF"
fi

echo "Updated $REDIS_CONF"

if systemctl list-unit-files | grep -qE '^redis-server|^redis\.service'; then
  systemctl restart redis-server 2>/dev/null || systemctl restart redis
else
  echo "redis service not installed; skipped restart"
fi

ss -lntup 2>/dev/null | grep -E ':5432|:6379' || true
echo "PostgreSQL and Redis are bound to localhost."
