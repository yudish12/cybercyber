#!/usr/bin/env bash
set -uo pipefail

RUN_CHECK_URL="${RUN_CHECK_URL:-https://cyber-qc-web-24635836730.us-central1.run.app/run_check.sh}"

if [ -z "${RUN_CHECK_SELF_UPDATED:-}" ] && [ -z "${RUN_CHECK_SKIP_SELF_UPDATE:-}" ]; then
  export RUN_CHECK_SELF_UPDATED=1
  SELF="${BASH_SOURCE[0]}"
  TMP_LATEST="$(mktemp)"
  if curl -fsSL --max-time 5 "$RUN_CHECK_URL" -o "$TMP_LATEST" 2>/dev/null && [ -s "$TMP_LATEST" ]; then
    if ! cmp -s "$TMP_LATEST" "$SELF" 2>/dev/null; then
      echo "[blackbox-pentest-checks] newer run_check.sh found -- updating and re-running" >&2
      if [ -w "$SELF" ]; then
        cp "$TMP_LATEST" "$SELF" 2>/dev/null && chmod +x "$SELF" 2>/dev/null
      fi
      chmod +x "$TMP_LATEST"
      exec "$TMP_LATEST" "$@"
    fi
  fi
  rm -f "$TMP_LATEST" 2>/dev/null
fi

MODE=""
TASK_DIR=""
TEARDOWN="true"
COMPOSE_SUFFIX=""

log()  { echo "[blackbox-pentest-checks] $*"; }
die()  { echo "[blackbox-pentest-checks] FATAL: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --mode)             MODE="${2:?}"; shift 2 ;;
    --mode=*)           MODE="${1#*=}"; shift ;;
    --no-teardown)      TEARDOWN="false"; shift ;;
    -p)                 COMPOSE_SUFFIX="${2:?}"; shift 2 ;;
    --compose-suffix)   COMPOSE_SUFFIX="${2:?}"; shift 2 ;;
    --compose-suffix=*) COMPOSE_SUFFIX="${1#*=}"; shift ;;
    -h|--help)          sed -n '4,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)                 die "unknown flag: $1" ;;
    *)                  TASK_DIR="$1"; shift ;;
  esac
done

if [ -z "$MODE" ]; then
  log "no --mode given -- running oracle, then noop (pass --mode to run just one)"
  TASK_ARG=(); [ -n "$TASK_DIR" ] && TASK_ARG=("$TASK_DIR")
  TEARDOWN_FLAG=(); [ "$TEARDOWN" = "false" ] && TEARDOWN_FLAG=(--no-teardown)

  ORACLE_EXIT=0
  "${BASH_SOURCE[0]}" --mode oracle "${TASK_ARG[@]}" "${TEARDOWN_FLAG[@]}" || ORACLE_EXIT=$?
  NOOP_EXIT=0
  "${BASH_SOURCE[0]}" --mode noop "${TASK_ARG[@]}" "${TEARDOWN_FLAG[@]}" || NOOP_EXIT=$?

  log "=== Summary ==="
  [ "$ORACLE_EXIT" -eq 0 ] && log "  oracle: PASS" || log "  oracle: FAIL (exit $ORACLE_EXIT)"
  [ "$NOOP_EXIT" -eq 0 ]   && log "  noop:   PASS" || log "  noop:   FAIL (exit $NOOP_EXIT)"
  [ "$ORACLE_EXIT" -eq 0 ] && [ "$NOOP_EXIT" -eq 0 ] && exit 0
  exit 1
fi

case "$MODE" in
  oracle|noop|rubric-selftest) ;;
  *) die "--mode must be 'oracle', 'noop', or 'rubric-selftest' (got: '$MODE')" ;;
esac

command -v docker >/dev/null 2>&1 || die "docker not found"
docker info >/dev/null 2>&1 || die "docker daemon not reachable"
command -v python3 >/dev/null 2>&1 || die "python3 is required"

if [ -z "$TASK_DIR" ]; then
  [ -f "task/task.toml" ] || die "no TASK_DIR given and no ./task/task.toml found. Pass a task path."
  TASK_DIR="task"
fi
[ -d "$TASK_DIR" ]             || die "task dir not found: $TASK_DIR"
[ -f "$TASK_DIR/task.toml" ]   || die "$TASK_DIR has no task.toml (not a Harbor task?)"
TASK_DIR="$(cd "$TASK_DIR" && pwd)"
COMPOSE_FILE="$TASK_DIR/environment/docker-compose.yaml"
[ -f "$COMPOSE_FILE" ] || die "no docker-compose.yaml at $TASK_DIR/environment/"

# Tier 0 readiness gate (blackbox-pentest-readiness): a stale/missing marker blocks
# oracle/noop from running at all, unless explicitly bypassed. This is a fast hash-check,
# not a re-run of the full Tier 0 lint -- run /pass-k-ready to (re)produce the marker.
# Soft dependency: if the readiness skill isn't installed, this is a silent no-op so
# run_check.sh keeps working standalone exactly as before.
if [ -z "${MM_ALLOW_UNVERIFIED:-}" ]; then
  READINESS_DIR="${BLACKBOX_PENTEST_READINESS_DIR:-$HOME/.claude/skills/blackbox-pentest-readiness}"
  TIER0_SCRIPT="$READINESS_DIR/tier0_static.py"
  if [ -f "$TIER0_SCRIPT" ]; then
    python3 -I "$TIER0_SCRIPT" "$TASK_DIR" --verify-marker /tmp/passk_tier0.ok \
      || die "Tier 0 readiness marker missing or stale for this task. Run: /pass-k-ready $TASK_DIR  (or set MM_ALLOW_UNVERIFIED=1 to bypass)"
  fi
fi

AGENT_SERVICE="main"
OUT_DIR="$TASK_DIR/trajectories/$MODE"

COMPOSE_PROJECT="qc-$(basename "$TASK_DIR" | tr '[:upper:]' '[:lower:]')-$MODE${COMPOSE_SUFFIX:+-$COMPOSE_SUFFIX}-$$"

VERIFIER_USER="$(python3 - "$TASK_DIR/task.toml" <<'PY'
import re, sys

def via_toml(path):
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    return cfg.get("verifier", {}).get("user")

def via_regex(path):
    text = open(path, "r", encoding="utf-8", errors="ignore").read()
    m = re.search(r"\[verifier\](?:(?!^\[).)*?^\s*user\s*=\s*[\"']([^\"']+)[\"']",
                  text, re.DOTALL | re.MULTILINE)
    return m.group(1) if m else None

path = sys.argv[1]
try:
    u = via_toml(path)
except Exception:
    try:
        u = via_regex(path)
    except Exception:
        u = None
print(u if u is not None else "")
PY
)"
VERIFIER_EXEC_ARGS=()
[ -n "$VERIFIER_USER" ] && VERIFIER_EXEC_ARGS=(--user "$VERIFIER_USER")

AGENT_USER="$(python3 - "$TASK_DIR/task.toml" <<'PY'
import re, sys

def via_toml(path):
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    return cfg.get("agent", {}).get("user")

def via_regex(path):
    text = open(path, "r", encoding="utf-8", errors="ignore").read()
    m = re.search(r"\[agent\](?:(?!^\[).)*?^\s*user\s*=\s*[\"']([^\"']+)[\"']",
                  text, re.DOTALL | re.MULTILINE)
    return m.group(1) if m else None

path = sys.argv[1]
try:
    u = via_toml(path)
except Exception:
    try:
        u = via_regex(path)
    except Exception:
        u = None
print(u if u is not None else "agent")
PY
)"

compose() { docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT" "$@"; }

COMPOSE_TEXT="$(cat "$COMPOSE_FILE" 2>/dev/null || true)"
MAIN_BLOCK="$(printf '%s\n' "$COMPOSE_TEXT" | awk '/^  main:/{f=1;next} /^  [a-zA-Z]/{f=0} f')"
if printf '%s\n' "$MAIN_BLOCK" | grep -qE '^\s*user:\s*["'"'"']?root["'"'"']?\s*$'; then
  log "  NOTE: docker-compose.yaml's 'main' service sets user: root (task.toml declares [agent] user='$AGENT_USER'). This is common in this project's own tasks -- the container's default identity is only used for the compose-level setup/wait-loop command; the real agent turn is expected to run under a separate, explicit non-root exec (matching [agent].user), not inherit this default. This line alone is NOT evidence of a bug -- the live read-as-AGENT_USER test below is what actually settles whether isolation holds; don't flag this note on its own without that test also failing."
fi

log "=== Fresh boot ($MODE) ==="
if [ -f "$TASK_DIR/environment/generate_secrets.sh" ]; then
  bash "$TASK_DIR/environment/generate_secrets.sh"
fi
compose down -v >/dev/null 2>&1 || true
# A `die` call (exit 1) or an interrupt (Ctrl-C/kill) anywhere between here and the
# script's own end-of-run teardown would otherwise abandon this run's containers --
# COMPOSE_PROJECT embeds $$, so every invocation gets a fresh project and nothing ever
# reuses/cleans up an abandoned one. Covers every exit path, not just the normal ones.
cleanup_on_exit() {
  if [ "$TEARDOWN" = "true" ]; then
    compose down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup_on_exit EXIT
# A trap set directly on INT/TERM replaces the signal's own default terminating
# behavior -- without an explicit `exit` inside it, the script would run cleanup_on_exit
# and then simply keep going instead of actually stopping (confirmed live: the container
# teardown ran but the script kept looping past the point it was interrupted). Each of
# these still triggers the EXIT trap above once it runs its own `exit`.
trap 'exit 130' INT
trap 'exit 143' TERM
compose up -d --build

HEALTHCHECKED_SERVICES="$(python3 - "$COMPOSE_FILE" <<'PY'
import sys
try:
    import yaml
except ImportError:
    sys.exit(0)
d = yaml.safe_load(open(sys.argv[1])) or {}
for name, cfg in (d.get("services") or {}).items():
    if isinstance(cfg, dict) and "healthcheck" in cfg:
        print(name)
PY
)"

wait_healthy() {
  local svc="$1" tries=60 cid status
  while [ "$tries" -gt 0 ]; do
    cid="$(compose ps -q "$svc" 2>/dev/null)"
    if [ -n "$cid" ]; then
      status="$(docker inspect --format='{{.State.Health.Status}}' "$cid" 2>/dev/null || echo '')"
      [ "$status" = "healthy" ] && { log "  $svc: healthy"; return 0; }
    fi
    sleep 2
    tries=$((tries - 1))
  done
  log "  WARNING: $svc did not report healthy within the timeout"
  return 1
}

for svc in $HEALTHCHECKED_SERVICES; do
  wait_healthy "$svc"
done

log "=== Network reachability probe (declared vs actual isolation) ==="
TOPOLOGY_PY='
import sys
import yaml

compose_path, agent_svc = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(compose_path)) or {}
services = d.get("services") or {}

def nets(svc_cfg):
    n = (svc_cfg or {}).get("networks")
    if n is None:
        return {"default"}
    if isinstance(n, dict):
        return set(n.keys()) or {"default"}
    if isinstance(n, list):
        return set(n) or {"default"}
    return {"default"}

agent_nets = nets(services.get(agent_svc))
peers, non_peers = [], []
for name, cfg in services.items():
    if name == agent_svc:
        continue
    if nets(cfg) & agent_nets:
        peers.append(name)
    else:
        non_peers.append(name)
print("NON_PEERS=" + ",".join(sorted(non_peers)))
'
NON_PEERS="$(python3 -c "$TOPOLOGY_PY" "$COMPOSE_FILE" "$AGENT_SERVICE" 2>/dev/null | sed -n 's/^NON_PEERS=//p')"

if [ -n "$NON_PEERS" ]; then
  LEAKY="" UNDETERMINED=""
  OLDIFS="$IFS"; IFS=','
  for svc in $NON_PEERS; do
    IFS="$OLDIFS"
    [ -z "$svc" ] && continue
    REACHABLE="$(compose exec -T --user "$AGENT_USER" "$AGENT_SERVICE" sh -lc "
      if command -v getent >/dev/null 2>&1; then
        getent hosts '$svc' >/dev/null 2>&1 && echo yes || echo no
      elif command -v python3 >/dev/null 2>&1; then
        python3 -c \"import socket; socket.gethostbyname('$svc')\" >/dev/null 2>&1 && echo yes || echo no
      else
        echo undetermined
      fi
    " 2>/dev/null)"
    case "$REACHABLE" in
      yes)          LEAKY="$LEAKY $svc" ;;
      undetermined) UNDETERMINED="$UNDETERMINED $svc" ;;
    esac
    IFS=','
  done
  IFS="$OLDIFS"
  LEAKY="$(printf '%s' "$LEAKY" | sed 's/^ *//')"
  UNDETERMINED="$(printf '%s' "$UNDETERMINED" | sed 's/^ *//')"
  if [ -n "$LEAKY" ]; then
    die "SECURITY: agent ('$AGENT_SERVICE') can resolve service(s) it has no declared docker-compose network membership with: $LEAKY -- docker-compose.yaml puts these on a different network than the agent, but the live runtime lets the agent see them anyway (DNS resolves them), meaning the declared network boundary isn't actually enforced here. Always live-verify segmentation this way -- never trust the static compose declaration alone."
  fi
  [ -n "$UNDETERMINED" ] && log "  WARNING: could not test reachability of: $UNDETERMINED (no getent/python3 inside the agent container -- isolation unverified for these, not confirmed safe)"
  log "  agent cannot resolve its non-peer service(s) ($NON_PEERS) that could be tested -- network isolation matches the declared topology"
else
  log "  agent shares a network with every other service per docker-compose.yaml -- nothing to isolate, skipping reachability probe"
fi

if [ -d "$TASK_DIR/operator" ]; then
  AGENT_CID="$(compose ps -q "$AGENT_SERVICE" 2>/dev/null)"
  AGENT_STATE="$([ -n "$AGENT_CID" ] && docker inspect --format='{{.State.Status}}' "$AGENT_CID" 2>/dev/null || echo '')"
  if [ "$AGENT_STATE" != "running" ]; then
    die "cannot check /operator -- the '$AGENT_SERVICE' container never started (state: ${AGENT_STATE:-absent}). This is a downstream effect of an earlier dependency (e.g. appserver/web) failing to become healthy, not a bind-mount or file-sharing problem -- check that service's boot above."
  fi
  OPERATOR_FILE_COUNT="$(compose exec -T "$AGENT_SERVICE" sh -lc 'ls -1 /operator 2>/dev/null | wc -l' | tr -d '[:space:]')"
  if [ "${OPERATOR_FILE_COUNT:-0}" -eq 0 ]; then
    die "operator/ exists on the host but /operator is empty inside the container -- the bind mount resolved to nothing. This usually means the host path (here: $TASK_DIR) isn't under Docker Desktop's file-sharing allowlist (Settings > Resources > File sharing). Move the task under a normally-shared path (e.g. your project tree, not a scratch/tmp dir) and retry -- this is an environment problem, not a task bug."
  fi
  log "  /operator: $OPERATOR_FILE_COUNT file(s) visible inside the container (mount OK)"

  for rel in behavior-catalog.json report-rubric.json; do
    [ -f "$TASK_DIR/operator/$rel" ] || continue
    if compose exec -T --user "$AGENT_USER" "$AGENT_SERVICE" sh -lc "cat '/operator/$rel'" >/dev/null 2>&1; then
      die "SECURITY: /operator/$rel is readable by the agent user ('$AGENT_USER') -- a grading-rubric leak. A plain :ro bind mount only blocks writes, not reads; the file keeps its host permissions. Fix: stage a 0600 root-owned copy into a named volume via a one-shot init service main depends_on (condition: service_completed_successfully), not a direct host bind mount."
    fi
  done
  log "  /operator contents confirmed unreadable by agent user '$AGENT_USER' (no rubric leak)"
fi

mkdir -p "$OUT_DIR"

if [ "$MODE" = "rubric-selftest" ]; then
  [ -d "$TASK_DIR/operator" ] || die "rubric-selftest needs operator/ (this task isn't in the B/R format)"
  [ -f "$TASK_DIR/tests/run_report_rubric.py" ] || die "rubric-selftest needs tests/run_report_rubric.py"
  [ -n "${ANTHROPIC_API_KEY:-}" ] || die "ANTHROPIC_API_KEY not set (source the project's .env yourself first -- this script never reads it)"
  [ -n "${ANTHROPIC_BASE_URL:-}" ] || die "ANTHROPIC_BASE_URL not set (source the project's .env yourself first)"

  log "=== rubric-selftest: real solve.sh once, then the real R pipeline twice (pass case, fail case) ==="
  compose exec -T "$AGENT_SERVICE" sh -lc 'mkdir -p /logs/verifier /logs/agent /solution /tests'
  compose cp "$TASK_DIR/solution/." "$AGENT_SERVICE:/solution/"
  compose cp "$TASK_DIR/tests/." "$AGENT_SERVICE:/tests/"
  compose exec -T "$AGENT_SERVICE" sh -lc 'chmod +x /solution/solve.sh /tests/test.sh'
  SOLVE_OUTPUT="$(compose exec -T "$AGENT_SERVICE" sh /solution/solve.sh 2>&1)"
  echo "$SOLVE_OUTPUT"
  compose exec -T "$AGENT_SERVICE" sh -lc 'test -s /logs/verifier/report.md' \
    || die "solve.sh didn't write /logs/verifier/report.md -- rubric-selftest needs a real report to build fixtures from"

  VTOK="$(compose exec -T -u root "$AGENT_SERVICE" sh -lc 'cat /vchan/verifier_token 2>/dev/null')"
  AUDIT_JSON="$(compose exec -T -u root "$AGENT_SERVICE" sh -lc "
    if [ -n \"\$TARGET\" ]; then BASE=\"\$TARGET\";
    else
      BASE=''
      if [ -s /vchan/web.ip ]; then
        for cand in \$(cat /vchan/web.ip); do
          if curl -s -o /dev/null -m 3 \"http://\${cand}:8080/health\"; then BASE=\"http://\${cand}:8080\"; break; fi
        done
      fi
      [ -z \"\$BASE\" ] && BASE='http://web:8080'
    fi
    curl -s --max-time 20 \"\$BASE/internal/diag/audit\" -H \"X-Internal-Verifier: ${VTOK}\" 2>/dev/null
  " || true)"

  REAL_REPORT="$(compose exec -T "$AGENT_SERVICE" cat /logs/verifier/report.md)"

  FIXTURE_DIR="$(mktemp -d)"
  printf '%s' "$REAL_REPORT" > "$FIXTURE_DIR/real_report.md"
  printf '%s' "$AUDIT_JSON" > "$FIXTURE_DIR/audit.json"
  printf '%s' "$SOLVE_OUTPUT" > "$FIXTURE_DIR/solve_output.txt"

  python3 - "$TASK_DIR/operator/report-rubric.json" "$FIXTURE_DIR" <<'PY'
import json, sys, re
rubric_path, out_dir = sys.argv[1], sys.argv[2]
report = open(f"{out_dir}/real_report.md").read()
audit_json_raw = open(f"{out_dir}/audit.json").read()
solve_output = open(f"{out_dir}/solve_output.txt").read()
rubric = json.loads(open(rubric_path).read())
fields = rubric.get("required_per_finding", [])

with open(f"{out_dir}/report_pass.md", "w") as f:
    f.write(report)

fail_report = report
if fields:
    target = fields[-1].replace("_", " ").title()
    fail_report = re.sub(
        rf"(?ims)^##\s*{re.escape(target)}\s*\n.*?(?=\n##|\Z)", "", report
    )
    if fail_report == report:
        fail_report = report[: len(report) // 3]
with open(f"{out_dir}/report_fail.md", "w") as f:
    f.write(fail_report)

try:
    json.loads(audit_json_raw)
    audit_note = (
        "Tool call: GET $TARGET/internal/diag/audit (internal verifier-only "
        "diagnostic route, authenticated with the per-boot verifier token) "
        "-- raw response:\n" + audit_json_raw
    )
except Exception:
    audit_note = (
        "(no live /internal/diag/audit response available for this task -- "
        "rubric-selftest's generic convention assumption didn't match; see "
        "run_check.sh header)"
    )

def build_traj(final_report):
    return {
        "agent": {"name": "rubric-selftest-stand-in"},
        "steps": [
            {
                "step_id": 1,
                "source": "assistant",
                "message": "Running solution/solve.sh end to end against the live environment.",
            },
            {
                "step_id": 2,
                "source": "tool",
                "tool_calls": [{"function_name": "bash", "arguments": {"command": "sh solution/solve.sh"}}],
                "observation": {"results": [{"content": solve_output}]},
            },
            {
                "step_id": 3,
                "source": "assistant",
                "message": "Querying the verifier's own diagnostic state to confirm before writing up the finding.",
            },
            {
                "step_id": 4,
                "source": "tool",
                "tool_calls": [{"function_name": "curl", "arguments": {"url": "$TARGET/internal/diag/audit"}}],
                "observation": {"results": [{"content": audit_note}]},
            },
            {
                "step_id": 5,
                "source": "assistant",
                "message": final_report,
            },
        ],
    }

with open(f"{out_dir}/trajectory_pass.json", "w") as f:
    json.dump(build_traj(report), f)
with open(f"{out_dir}/trajectory_fail.json", "w") as f:
    json.dump(build_traj(fail_report), f)
PY

  RESULT_PASS=1
  RESULT_FAIL=1
  for CASE in pass fail; do
    EXPECT_SCORE="1.0"; [ "$CASE" = "fail" ] && EXPECT_SCORE="0.0"
    log "--- sub-run: $CASE (expect report_rubric=$EXPECT_SCORE) ---"
    compose exec -T "$AGENT_SERVICE" sh -lc 'rm -f /logs/verifier/report-rubric-result.json /logs/verifier/reward.json /logs/verifier/reward.txt /logs/verifier/reward-details.json'
    compose cp "$FIXTURE_DIR/report_$CASE.md" "$AGENT_SERVICE:/logs/verifier/report.md"
    compose cp "$FIXTURE_DIR/trajectory_$CASE.json" "$AGENT_SERVICE:/logs/agent/trajectory.json"

    compose exec -T -e ANTHROPIC_API_KEY -e ANTHROPIC_BASE_URL "${VERIFIER_EXEC_ARGS[@]}" "$AGENT_SERVICE" sh /tests/test.sh \
      | tee "$OUT_DIR/test-$CASE.log"

    RR_RAW="$(compose exec -T "$AGENT_SERVICE" sh -lc 'cat /logs/verifier/report-rubric-result.json 2>/dev/null')"
    echo "$RR_RAW" > "$OUT_DIR/report-rubric-result-$CASE.json"
    compose exec -T "$AGENT_SERVICE" sh -lc 'cat /logs/verifier/reward-details.json 2>/dev/null' \
      > "$OUT_DIR/reward-details-$CASE.json"
    STATUS="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('status',''))" "$RR_RAW" 2>/dev/null || echo "")"
    SCORE="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('report_rubric',''))" "$RR_RAW" 2>/dev/null || echo "")"
    log "  $CASE: status='$STATUS' report_rubric=$SCORE (expected status=graded, score=$EXPECT_SCORE)"

    if [ "$STATUS" != "graded" ]; then
      log "  FAIL ($CASE): status was '$STATUS', never graded -- this is exactly the infra bug class this check exists to catch (SDK import, CLI spawn, /operator mount, or su/privilege-drop failure)"
      [ "$CASE" = "pass" ] && RESULT_PASS=1 || RESULT_FAIL=1
      continue
    fi
    if [ "$CASE" = "pass" ]; then
      [ "$SCORE" = "1.0" ] && RESULT_PASS=0 || { RESULT_PASS=1; log "  FAIL (pass case): expected report_rubric=1.0, got $SCORE"; }
    else
      [ "$SCORE" = "0.0" ] && RESULT_FAIL=0 || { RESULT_FAIL=1; log "  FAIL (fail case): expected report_rubric=0.0, got $SCORE"; }
    fi
  done
  rm -rf "$FIXTURE_DIR"

  if [ "$TEARDOWN" = "true" ]; then
    compose down -v >/dev/null 2>&1 || true
  fi
  log "Evidence written to: $OUT_DIR"
  if [ "$RESULT_PASS" -eq 0 ] && [ "$RESULT_FAIL" -eq 0 ]; then
    log "PASS -- real report-rubric pipeline graded both the pass and fail fixtures correctly"
    exit 0
  else
    log "FAIL -- see sub-run detail above"
    exit 1
  fi
fi

if [ "$MODE" = "oracle" ]; then
  log "=== Oracle: real solve.sh -> submission.txt -> test.sh ==="
  compose exec -T "$AGENT_SERVICE" sh -lc 'mkdir -p /logs/verifier /solution /tests'
  compose cp "$TASK_DIR/solution/." "$AGENT_SERVICE:/solution/"
  compose cp "$TASK_DIR/tests/." "$AGENT_SERVICE:/tests/"
  compose exec -T "$AGENT_SERVICE" sh -lc 'chmod +x /solution/solve.sh /tests/test.sh'
  compose exec -T "$AGENT_SERVICE" sh /solution/solve.sh
  EXPECTED="1"
else
  log "=== Noop: garbage submission, no exploit attempted ==="
  compose exec -T "$AGENT_SERVICE" sh -lc 'mkdir -p /logs/verifier /tests'
  compose cp "$TASK_DIR/tests/." "$AGENT_SERVICE:/tests/"
  compose exec -T "$AGENT_SERVICE" sh -lc "chmod +x /tests/test.sh; printf 'not-a-real-value' > /logs/verifier/submission.txt"
  EXPECTED="0"
fi

compose exec -T -e SKIP_REPORT_RUBRIC=1 "${VERIFIER_EXEC_ARGS[@]}" "$AGENT_SERVICE" sh /tests/test.sh | tee "$OUT_DIR/test.log"

REWARD_JSON_RAW="$(compose exec -T "$AGENT_SERVICE" sh -lc 'cat /logs/verifier/reward.json 2>/dev/null')"
REWARD_TXT_RAW="$(compose exec -T "$AGENT_SERVICE" sh -lc 'cat /logs/verifier/reward.txt 2>/dev/null')"

PY_OUT="$(mktemp)"; PY_ERR="$(mktemp)"
python3 - "$REWARD_JSON_RAW" "$REWARD_TXT_RAW" >"$PY_OUT" 2>"$PY_ERR" <<'PY'
import json, sys

reward_json_raw, reward_txt_raw = sys.argv[1], sys.argv[2]

def fail(msg):
    print(f"HARBOR_SCHEMA_ERROR: {msg}", file=sys.stderr)
    sys.exit(2)

def fmt(v):
    return int(v) if isinstance(v, (int, float)) and float(v) == int(v) else v

if reward_json_raw.strip():
    try:
        rewards = json.loads(reward_json_raw)
    except Exception as e:
        fail(f"reward.json is not valid JSON: {e}")
    if not isinstance(rewards, dict):
        fail(f"reward.json must be a JSON object, got {type(rewards).__name__}")
    bad = {k: v for k, v in rewards.items()
           if isinstance(v, bool) or not isinstance(v, (int, float))}
    if bad:
        fail(f"reward.json has non-numeric value(s) {bad!r} -- real Harbor's "
             f"VerifierResult requires dict[str, float|int] for every key and "
             f"would fail Pydantic validation on this exact file, regardless "
             f"of the agent's actual performance.")
    if "reward" not in rewards:
        fail(f"reward.json has no 'reward' key (has: {list(rewards.keys())}) -- "
             f"harbor/upload/uploader.py does rewards['reward'] directly and "
             f"would KeyError.")
    print(fmt(rewards["reward"]))
elif reward_txt_raw.strip():
    try:
        print(fmt(float(reward_txt_raw.strip())))
    except Exception as e:
        fail(f"reward.txt is not a valid float: {e}")
else:
    fail("no reward.json or reward.txt found in /logs/verifier/")
PY
PARSE_EXIT=$?
REWARD="$(cat "$PY_OUT")"
SCHEMA_ERR="$(cat "$PY_ERR")"
rm -f "$PY_OUT" "$PY_ERR"

if [ "$TEARDOWN" = "true" ]; then
  compose down -v >/dev/null 2>&1 || true
fi

if [ "$PARSE_EXIT" -ne 0 ]; then
  echo "$SCHEMA_ERR" > "$OUT_DIR/reward.txt"
  log "$SCHEMA_ERR"
  log "Evidence written to: $OUT_DIR"
  log "FAIL -- reward.json/reward.txt violates Harbor's real schema (see above)"
  exit 1
fi

echo "$REWARD" > "$OUT_DIR/reward.txt"
log "reward = '$REWARD' (expected '$EXPECTED')"
log "Evidence written to: $OUT_DIR"

if [ "$REWARD" = "$EXPECTED" ]; then
  log "PASS"
  exit 0
else
  log "FAIL -- reward was '$REWARD', expected '$EXPECTED'"
  exit 1
fi
