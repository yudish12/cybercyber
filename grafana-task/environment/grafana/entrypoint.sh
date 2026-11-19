#!/bin/sh
set -e

GF_DATA="/var/lib/grafana"
mkdir -p "$GF_DATA" 2>/dev/null || true
_sk="$GF_DATA/.gf_secret_key"; _ap="$GF_DATA/.gf_admin_pw"
[ -s "$_sk" ] || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$_sk"
[ -s "$_ap" ] || head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$_ap"
export GF_SECURITY_SECRET_KEY="${GF_SECURITY_SECRET_KEY:-$(cat "$_sk")}"
export GF_SECURITY_ADMIN_PASSWORD="${GF_SECURITY_ADMIN_PASSWORD:-$(cat "$_ap")}"

BASE="http://localhost:3000"
AU="${GF_SECURITY_ADMIN_USER:-admin}"
AP="${GF_SECURITY_ADMIN_PASSWORD}"
PADMIN_USER="${PLATFORM_ADMIN_USER:-platform-admin}"
PADMIN_PASS="${PLATFORM_ADMIN_PASS:-pe-admin-pw}"
MARKER="/var/lib/grafana/.seed_complete"
SEEDLOG="/var/lib/grafana/seed.log"
RESP="/tmp/seed_resp.$$"

post() {
  resp_code="$(curl -s -u "$AU:$AP" -H 'Content-Type: application/json' \
                 -o "$RESP" -w '%{http_code}' -X POST -d "$2" "$BASE$1" 2>/dev/null)"
  resp_body="$(cat "$RESP" 2>/dev/null)"
  case "$resp_code" in 2*) return 0 ;; *) return 1 ;; esac
}
patch() {
  resp_code="$(curl -s -u "$AU:$AP" -H 'Content-Type: application/json' \
                 -o "$RESP" -w '%{http_code}' -X PATCH -d "$2" "$BASE$1" 2>/dev/null)"
  resp_body="$(cat "$RESP" 2>/dev/null)"
  case "$resp_code" in 2*) return 0 ;; *) return 1 ;; esac
}
put() {
  resp_code="$(curl -s -u "$AU:$AP" -H 'Content-Type: application/json' \
                 -o "$RESP" -w '%{http_code}' -X PUT -d "$2" "$BASE$1" 2>/dev/null)"
  resp_body="$(cat "$RESP" 2>/dev/null)"
  case "$resp_code" in 2*) return 0 ;; *) return 1 ;; esac
}
get() {
  resp_code="$(curl -s -u "$AU:$AP" -o "$RESP" -w '%{http_code}' "$BASE$1" 2>/dev/null)"
  cat "$RESP" 2>/dev/null
}
randpw() { head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

seed() {
  i=0
  while [ "$i" -lt 90 ]; do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null)" = "200" ] && break
    i=$((i + 1)); sleep 2
  done
  [ -z "$AP" ] && { echo "[seed] admin password not set; skipping seed" >&2; return 1; }
  [ -f "$MARKER" ] && { echo "[seed] marker present; this volume is already seeded"; return 0; }

  put "/api/orgs/1" '{"name":"Platform Engineering"}' ||
    { echo "[seed] FAILED renaming org 1 (HTTP $resp_code)" >&2; return 1; }

  for pair in \
    "alice.chen:Alice Chen" "bob.kumar:Bob Kumar" "carol.diaz:Carol Diaz" \
    "dave.singh:Dave Singh" "erin.park:Erin Park" "frank.ito:Frank Ito"; do
    login="${pair%%:*}"; name="${pair#*:}"
    get "/api/users/lookup?loginOrEmail=$login" >/dev/null
    if [ "$resp_code" != "200" ]; then
      pw="$(randpw)"
      if ! post "/api/admin/users" \
        "{\"name\":\"$name\",\"email\":\"$login@corp.example\",\"login\":\"$login\",\"password\":\"$pw\"}"; then
        echo "[seed] FAILED creating user $login (HTTP $resp_code)" >&2; return 1
      fi
    fi
  done

  uid="$(get "/api/users/lookup?loginOrEmail=$PADMIN_USER" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' | head -1)"
  if [ -z "$uid" ]; then
    if ! post "/api/admin/users" \
      "{\"name\":\"Platform Admin\",\"email\":\"$PADMIN_USER@corp.example\",\"login\":\"$PADMIN_USER\",\"password\":\"$PADMIN_PASS\"}"; then
      echo "[seed] FAILED creating $PADMIN_USER (HTTP $resp_code)" >&2; return 1
    fi
    uid="$(printf '%s' "$resp_body" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' | head -1)"
  fi
  [ -z "$uid" ] && { echo "[seed] FAILED: could not resolve $PADMIN_USER uid" >&2; return 1; }
  if ! patch "/api/orgs/1/users/$uid" '{"role":"Admin"}'; then
    post "/api/orgs/1/users" "{\"loginOrEmail\":\"$PADMIN_USER\",\"role\":\"Admin\"}" ||
      { echo "[seed] FAILED granting $PADMIN_USER org Admin (HTTP $resp_code)" >&2; return 1; }
  fi

  tid="$(get '/api/teams/search?name=SRE%20On-call' | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' | head -1)"
  if [ -z "$tid" ]; then
    if post "/api/teams" '{"name":"SRE On-call","email":"sre@corp.example"}'; then
      tid="$(printf '%s' "$resp_body" | sed -n 's/.*"teamId":\([0-9][0-9]*\).*/\1/p')"
    fi
  fi
  if [ -n "$tid" ]; then
    members="$(get "/api/teams/$tid/members")"
    for login in alice.chen bob.kumar; do
      muid="$(get "/api/users/lookup?loginOrEmail=$login" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' | head -1)"
      [ -z "$muid" ] && continue
      case "$members" in
        *"\"login\":\"$login\""*) : ;;
        *) post "/api/teams/$tid/members" "{\"userId\":$muid}" || true ;;
      esac
    done
  fi

  : > "$MARKER" || { echo "[seed] FAILED: cannot write marker $MARKER" >&2; return 1; }
  echo "[seed] done (marker written: $MARKER)"
}

( seed || echo "[seed] INCOMPLETE — marker not written; container will remain unhealthy" ) \
  >>"$SEEDLOG" 2>&1 &
exec /run.sh "$@"
