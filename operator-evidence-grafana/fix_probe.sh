#!/usr/bin/env bash
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ENVDIR="$(cd "$HERE/../environment" && pwd)"
PROJECT=grafana-ssrf-fixprobe
COMPOSE="docker compose -p $PROJECT -f $ENVDIR/docker-compose.yaml"
PADMIN="platform-admin:PlatEng-OnCall-7731"

cleanup(){ $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[fix_probe] building + booting the CORRECTED variant (DSPROXY_EXACT_HOST_MATCH=1)..."
export DSPROXY_EXACT_HOST_MATCH=1
$COMPOSE up -d --build >/dev/null 2>&1 || { echo "[fix_probe] build/boot failed"; exit 2; }

port=""
for i in $(seq 1 60); do
  cid="$($COMPOSE ps -q web 2>/dev/null)"
  [ -n "$cid" ] && st="$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" || st=""
  [ "$st" = "healthy" ] && { port="$(docker port "$cid" 8080/tcp | head -1 | sed 's/.*://')"; break; }
  sleep 5
done
[ -z "$port" ] && { echo "[fix_probe] web never became healthy"; exit 2; }
BASE="http://localhost:$port"

A(){ curl -s -u "$PADMIN" "$@"; }
mkds(){ A -H 'Content-Type: application/json' -X POST \
  -d "{\"name\":\"$2\",\"type\":\"graphite\",\"access\":\"proxy\",\"url\":\"$1\"}" \
  "$BASE/api/datasources" | python3 -c 'import sys,json
try:
 d=json.load(sys.stdin);print((d.get("datasource") or {}).get("uid") or d.get("uid") or "")
except Exception: print("")'; }

rc=0
blocked(){
  local u lbl b; u="$(mkds "$1" "$2")"; b="$(A "$BASE/api/datasources/proxy/uid/${u}/v1/tokens")"
  if printf '%s' "$b" | grep -qE "not included in whitelist|disallowed address class"; then
    echo "[fix_probe] OK: '$1' is blocked by the corrected guard (exploit dies)"
  else
    echo "[fix_probe] FAIL: '$1' still reachable under the corrected guard"; rc=1
  fi
}
blocked "http://svc-c2.obs.internal"  "fixprobe-config"
blocked "http://svc-c2.obs.internal." "fixprobe-config-dot"
blocked "http://127.0.0.1"            "fixprobe-loopback-literal"
blocked "http://169.254.169.254"      "fixprobe-linklocal-literal"
prom_uid="$(A "$BASE/api/datasources" | python3 -c 'import sys,json
d=json.load(sys.stdin)
for x in d:
 if "metrics.obs.internal" in (x.get("url") or ""): print(x["uid"]); break')"
code="$(A -o /dev/null -w '%{http_code}' "$BASE/api/datasources/proxy/uid/${prom_uid}/api/v1/targets")"
if [ "$code" != "403" ]; then
  echo "[fix_probe] OK: whitelisted Graphite still reachable ($code) — legit behavior survives"
else
  echo "[fix_probe] FAIL: whitelisted host wrongly blocked ($code)"; rc=1
fi

[ "$rc" = "0" ] && echo "[fix_probe] PASS — the loose-match is the whole vulnerability" || echo "[fix_probe] FAILED"
exit $rc
