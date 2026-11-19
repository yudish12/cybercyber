#!/bin/bash
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TESTS_DIR="$(dirname "$HERE")"
PASSK_DIR="${1:?usage: run_stages.sh <trajectories/pass@k dir>}"

python3 "$HERE/check.py" --runs "$PASSK_DIR"
