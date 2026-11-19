#!/bin/bash
cd /
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/logs/verifier/reward.json
mkdir -p /logs/verifier

echo '{"reward": 0}' > "$OUT"
echo 0 > /logs/verifier/reward.txt

rewardkit "$HERE/behavior" --workspace "$HERE" --output "$OUT" || true

python3 -I - "$OUT" > /logs/verifier/reward.txt <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); v=d.get("reward")
if v is None: v=max(d.values()) if d else 0.0
print(1 if float(v)>=1.0 else 0)
PY

echo "[verify] behavior gate reward=$(cat /logs/verifier/reward.txt 2>/dev/null || echo 0) (official; fail-closed default was 0)"

mkdir -p /logs/verifier/stages
python3 -I "$HERE/stages/check.py" \
  --traj "${TRAJ:-/logs/agent/trajectory.json}" \
  --reward "$OUT" \
  --output /logs/verifier/stages >/dev/null 2>&1 || true

RR_OUT=/logs/verifier/report-rubric-result.json
printf '{"reward": 0, "status": "pending"}\n' > "$RR_OUT"
if [ "${SKIP_REPORT_RUBRIC:-}" = "1" ]; then
  printf '{"reward": 0, "status": "skipped"}\n' > "$RR_OUT"
else
  case "${ANTHROPIC_BASE_URL:-}" in
    ""|*anthropic.com*|*localhost*|*127.0.0.1*)
      echo "infra_error: ANTHROPIC_BASE_URL unset or points at the public Anthropic API or a local address; refusing to grade report rubric" >&2
      printf '{"reward": 0, "status": "infra_error"}\n' > "$RR_OUT"
      ;;
    *)
      if rewardkit "$HERE/report" --workspace "$HERE" --output "$RR_OUT"; then :; else
        printf '{"reward": 0, "status": "judge_error"}\n' > "$RR_OUT"
      fi
      ;;
  esac
fi
