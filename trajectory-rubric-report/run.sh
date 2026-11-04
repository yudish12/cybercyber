#!/usr/bin/env bash
set -uo pipefail
###############################################################################
# Just run this: ./run.sh <TASK_DIR> [--jobs-dir DIR] [--rubrics PATH]
#                          [--judge-model MODEL] [--max-transcript-chars N]
#                          [--skip-rubric-quality-check] [--force-grade-despite-quality]
#
# First runs an RB1 rubric-quality pre-check against the rubric itself (no
# transcript needed) -- atomic/objective/self-contained/clearly-triggered/
# positively-phrased criteria, stage-success + no-reward-hacking coverage --
# printing the result to the terminal (no file written for this step). BY
# DEFAULT, a 'fail' verdict STOPS here: no trial is graded and no
# trajectory_analysis_report.md is written until the rubric itself is fixed.
# Pass --force-grade-despite-quality to grade anyway despite a 'fail', or
# --skip-rubric-quality-check to skip this whole step (old pre-gate behavior).
#
# Then grades every trial in TASK_DIR's pass@k job against its rubrics.json
# (expects the top-level "Criteria": [{id, stage, category, criterion}, ...]
# shape), writing one trajectory_analysis_report.md per trial alongside that
# trial's own raw transcript and verifier output.
#
# Needs: python3, and ANTHROPIC_API_KEY + ANTHROPIC_BASE_URL already sourced
# into this shell (source the project's .env yourself first -- this script
# never reads that file).
#
# Independent skill from the sibling `sandbox_skills` skill one directory up
# (which runs pass@1 trials) -- this one grades trials an earlier run already
# produced, from any source (sandbox_skills, blackbox-pentest-pass1, or
# ops/launch_fleet.py); point --jobs-dir at it.
###############################################################################

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/skills/trajectory-rubric-report/grade_trajectories.py"

exec python3 "$SCRIPT" "$@"
