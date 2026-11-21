#!/usr/bin/env bash
# enumerate.sh <task_root> — list a Deep Hack bundle's files by category.
# FACTS ONLY: this scores nothing. The manual audit still opens every decision-relevant file.
# BLIND ORDER (SKILL Step 1.5 #1): write the red-team list BEFORE reading difficulty_explanation,
# unintended_findings.json, delivery.json or any NOTICE. This listing names those files; it does not
# ask you to read them first. A single-agent audit is not fully blind (you have read the trap library):
# use a separate red-team agent given only the bundle + rubric.json when you can.
set -u
ROOT="${1:?usage: enumerate.sh <task_root>  (the dir that contains task.toml)}"
[ -f "$ROOT/task.toml" ] || { echo "ERROR: $ROOT/task.toml not found — pass the inner task/ dir"; exit 1; }

sec() { printf '\n=== %s ===\n' "$1"; }
exists() { for f in "$@"; do [ -e "$ROOT/$f" ] && echo "  $f"; done; }

sec "IDENTITY (task.toml: name/cwe/kind/version now; difficulty_explanation only AFTER the red-team list)"
grep -nE '^(name|cwe|vulnerability_kind|version)\b|\[task\]|\[metadata\]' "$ROOT/task.toml" 2>/dev/null | sed 's/^/  /'

sec "HARNESS / CONFIG (read each in full; task.toml difficulty_explanation only after the red-team list)"
exists task.toml instruction.md instruction_L0.md instruction_L1.md instruction_L2.md fresh_state.json \
       environment/docker-compose.yaml environment/docker-compose.yml

sec "BUILDER CLAIMS (read in full only AFTER the Step 1.5 #1 red-team list)"
exists delivery.json unintended_findings.json environment/NOTICE.md
find "$ROOT/environment" -mindepth 2 -name NOTICE.md 2>/dev/null | sed "s|$ROOT/|  |"

sec "DOCKERFILES (read each — digest pins, non-root agent)"
find "$ROOT/environment" -name Dockerfile 2>/dev/null | sed "s|$ROOT/|  |"

sec "EXPLOIT CONTRACT — gateway/app services (read in full)"
find "$ROOT/environment" -maxdepth 3 -name '*.py' -not -path '*/node_modules/*' 2>/dev/null | sed "s|$ROOT/|  |"
find "$ROOT/environment" -maxdepth 3 \( -name 'boot.sh' -o -name 'entrypoint.sh' \) 2>/dev/null | sed "s|$ROOT/|  |"

sec "GRADING (read each in full)"
find "$ROOT/tests" -type f 2>/dev/null | sed "s|$ROOT/|  |" | sort

sec "SOLUTION / OPERATOR (read each in full)"
find "$ROOT/solution" "$ROOT/operator" -type f -not -name '*.pyc' 2>/dev/null | sed "s|$ROOT/|  |" | sort

sec "SERVER ATTACK SURFACE — API routes (OPEN THE SINK + ALL SIBLINGS/DECOYS; danger-sweep the rest)"
APIDIR="$(find "$ROOT/environment" -type d -name api 2>/dev/null | head -1)"
if [ -n "${APIDIR:-}" ]; then
  n=$(find "$APIDIR" -name route.ts -not -name '*.test.ts' | wc -l | tr -d ' ')
  echo "  ($n served route.ts files under ${APIDIR#$ROOT/})"
  find "$APIDIR" -name route.ts -not -name '*.test.ts' | sed "s|$APIDIR/|    |;s|/route.ts||" | sort
fi

sec "SERVER LIB (read session-middleware, db, schema; danger-sweep the rest)"
LIBDIR="$(find "$ROOT/environment" -type d -name lib 2>/dev/null | head -1)"
[ -n "${LIBDIR:-}" ] && find "$LIBDIR" -maxdepth 1 -name '*.ts' -not -name '*.test.ts' | sed "s|$LIBDIR/|  |" | sort

sec "TRAJECTORIES"
# v1.4: oracle/ and noop/ each hold reward.txt + a NON-EMPTY test.log (an empty test.log is missing evidence, F1)
for d in oracle noop; do
  for f in reward.txt test.log; do
    p="$ROOT/trajectories/$d/$f"
    if [ -s "$p" ]; then
      if [ "$f" = reward.txt ]; then echo "  trajectories/$d/reward.txt = $(head -c 40 "$p")"
      else echo "  trajectories/$d/test.log: $(wc -l < "$p" | tr -d ' ') line(s)"; fi
    elif [ -e "$p" ]; then echo "  trajectories/$d/$f: EMPTY (missing evidence -- F1)"
    else echo "  trajectories/$d/$f: MISSING (F1)"; fi
  done
done
if [ -d "$ROOT/trajectories/pass@k" ]; then
  n=$(find "$ROOT/trajectories/pass@k" -path '*/agent/trajectory.json' 2>/dev/null | wc -l | tr -d ' ')
  echo "  MODE: POST-PASS@K -- trajectories/pass@k/ holds $n trial(s) with agent/trajectory.json"
else
  echo "  MODE: PRE-PASS@K -- no trajectories/pass@k/ (pass@5 clauses are DEFERRED; SKILL.md 'Mode, rulings and blocking rules')"
fi

sec "NOT SECURITY-RELEVANT (do NOT read line-by-line; note for EN1 scale only)"
UI=$(find "$ROOT" -path '*/components/*' -name '*.tsx' 2>/dev/null | wc -l | tr -d ' ')
PG=$(find "$ROOT" -name 'page.tsx' 2>/dev/null | wc -l | tr -d ' ')
WH=$(find "$ROOT" -path '*/vendor-wheels/*' 2>/dev/null | wc -l | tr -d ' ')
echo "  UI components: $UI | page.tsx: $PG | vendored wheels: $WH  (danger-sweep; each wheel METADATA License is still an EN4 check, Step 1.5 #11)"
