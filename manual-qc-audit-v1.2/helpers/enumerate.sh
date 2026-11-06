#!/usr/bin/env bash
# enumerate.sh <task_root> — list a Deep Hack bundle's files by category.
# FACTS ONLY: this scores nothing. The manual audit still opens every decision-relevant file.
set -u
ROOT="${1:?usage: enumerate.sh <task_root>  (the dir that contains task.toml)}"
[ -f "$ROOT/task.toml" ] || { echo "ERROR: $ROOT/task.toml not found — pass the inner task/ dir"; exit 1; }

sec() { printf '\n=== %s ===\n' "$1"; }
exists() { for f in "$@"; do [ -e "$ROOT/$f" ] && echo "  $f"; done; }

sec "IDENTITY (read task.toml in full)"
grep -nE '^(name|cwe|vulnerability_kind|version)\b|\[task\]|\[metadata\]' "$ROOT/task.toml" 2>/dev/null | sed 's/^/  /'

sec "HARNESS / CONFIG (read each in full)"
exists task.toml instruction.md instruction_L0.md instruction_L1.md instruction_L2.md fresh_state.json \
       delivery.json \
       environment/docker-compose.yaml environment/docker-compose.yml environment/NOTICE.md

sec "DOCKERFILES (read each — digest pins, non-root agent)"
find "$ROOT/environment" -name Dockerfile 2>/dev/null | sed "s|$ROOT/|  |"

sec "EXPLOIT CONTRACT — gateway/app services (read in full)"
find "$ROOT/environment" -maxdepth 3 -name '*.py' -not -path '*/node_modules/*' 2>/dev/null | sed "s|$ROOT/|  |"
find "$ROOT/environment" -maxdepth 3 -name 'boot.sh' -o -maxdepth 3 -name 'entrypoint.sh' 2>/dev/null | sed "s|$ROOT/|  |"

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
for d in oracle noop; do
  [ -e "$ROOT/trajectories/$d/reward.txt" ] && echo "  trajectories/$d/reward.txt = $(cat "$ROOT/trajectories/$d/reward.txt")"
done
PK="$(find "$ROOT/trajectories/pass@k" -maxdepth 1 -type d -name 'task-*' 2>/dev/null | head -1)"
[ -n "${PK:-}" ] && echo "  pass@k job: ${PK#$ROOT/}  (trials: $(find "$PK" -maxdepth 1 -type d -name '*deepseek*' | wc -l | tr -d ' '))"

sec "NOT SECURITY-RELEVANT (do NOT read line-by-line; note for EN1 scale only)"
UI=$(find "$ROOT" -path '*/components/*' -name '*.tsx' 2>/dev/null | wc -l | tr -d ' ')
PG=$(find "$ROOT" -name 'page.tsx' 2>/dev/null | wc -l | tr -d ' ')
WH=$(find "$ROOT" -path '*/vendor-wheels/*' 2>/dev/null | wc -l | tr -d ' ')
echo "  UI components: $UI | page.tsx: $PG | vendored wheels: $WH  (covered by the danger-sweep, not read individually)"
