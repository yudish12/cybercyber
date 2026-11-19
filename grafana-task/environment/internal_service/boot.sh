#!/usr/bin/env bash
set -eu
i=0
while [ ! -s /canary/seed.json ]; do
  i=$((i+1))
  [ "$i" -ge 120 ] && { echo "[internal] seed.json never appeared; aborting" >&2; exit 1; }
  sleep 1
done
echo "[internal] seed present; serving platform estate"
exec gunicorn -b 0.0.0.0:80 -b 0.0.0.0:9090 -b 0.0.0.0:3100 -w 1 --timeout 30 app:app
