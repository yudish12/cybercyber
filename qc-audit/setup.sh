#!/usr/bin/env bash
# One-time setup for the qc-audit skill.
# Creates a local Python venv (PyYAML is the only dependency) and verifies the
# install by running the self-test. Safe to re-run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"

echo "qc-audit setup"
echo "  location: $HERE"

# --- find a usable python3 (3.11+ for tomllib) ---
PY=""
for c in python3.14 python3.13 python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1; then
    if "$c" -c 'import sys,tomllib; sys.exit(0 if sys.version_info>=(3,11) else 1)' >/dev/null 2>&1; then
      PY="$c"; break
    fi
  fi
done
if [ -z "$PY" ]; then
  echo "ERROR: need Python 3.11+ (for the stdlib tomllib module)." >&2
  echo "       Install one, then re-run this script." >&2
  exit 1
fi
echo "  python:   $PY ($("$PY" -c 'import sys;print(sys.version.split()[0])'))"

# --- venv ---
if [ ! -x "$VENV/bin/python" ]; then
  echo "  creating venv..."
  "$PY" -m venv "$VENV"
else
  echo "  venv already present, reusing"
fi

echo "  installing PyYAML..."
"$VENV/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install --quiet pyyaml

# --- verify ---
echo
"$VENV/bin/python" "$HERE/selftest.py"

cat <<EOF

Setup complete. Use it by asking Claude Code:

    QC this task: /path/to/task_or_bundle.tar.gz

Or run the deterministic tier yourself:

    WORK=\$(mktemp -d)
    $VENV/bin/python $HERE/extract_evidence.py <TASK_PATH> --out "\$WORK/pack.json"
    $VENV/bin/python $HERE/report.py --pack "\$WORK/pack.json" --relay

See README.md for the full three-step flow.
EOF
