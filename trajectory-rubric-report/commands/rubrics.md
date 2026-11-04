---
description: Grade every trial in a pass@k job against a task's rubrics.json, writing one trajectory_analysis_report.md per trial with a completion score, per-stage breakdown, blocking stage, and failure reason. First runs an RB1 rubric-quality pre-check against the rubric itself and, by default, hard-gates on it (no trial graded, no report written until the rubric passes or the gate is bypassed).
argument-hint: "[task-dir] [--jobs-dir DIR] [--rubrics PATH] [--judge-model MODEL] [--max-transcript-chars N] [--skip-rubric-quality-check] [--force-grade-despite-quality]"
---

Use the `trajectory-rubric-report` skill (read its `SKILL.md` first, in full
-- it's short) to grade an already-completed pass@k job against its task's
rubrics.json. This is a second, LLM-judged opinion layered on top of the
deterministic verifier's reward -- it does not replace it, and it does not
run any trials itself. Running `/rubrics` with no arguments at all is the
common case: it resolves the task dir itself (see step 2) and runs with
every other default.

Arguments (all optional): $ARGUMENTS
- `task-dir` -- the Harbor task directory whose rubrics a prior pass@k run
  (from `sandbox_skills`, `blackbox-pentest-pass1`, or
  `ops/launch_fleet.py`) was graded against. If omitted, resolve it yourself
  (step 2) instead of asking.
- `--jobs-dir` -- defaults to `<task-dir>/trajectories/pass@k`.
- `--rubrics` -- defaults to `<task-dir>/rubrics.json`, else
  `<jobs-dir>/rubrics.json`.
- `--judge-model` -- defaults to `fireworks_ai/kimi-k3` (independent of the
  models actually run in the trials being graded).
- `--skip-rubric-quality-check` / `--force-grade-despite-quality` -- bypass
  or override the RB1 rubric-quality hard gate described below.

Steps:
1. Read `~/.claude/skills/trajectory-rubric-report/SKILL.md` in full.
2. Resolve `task-dir`: if `$ARGUMENTS` names one, use it; otherwise use
   `./task` if it has a `task.toml`, else the most recently modified
   directory under `./` (or `./trajectories/`'s parent) containing a
   `trajectories/pass@k/` folder. If neither resolves to something real,
   say so and stop -- do not guess at a path that doesn't exist.
3. Confirm `ANTHROPIC_API_KEY` + `ANTHROPIC_BASE_URL` are already sourced
   into this shell (`set -a; source ./.env; set +a` from the project root,
   same convention as every other skill here) -- this script never reads
   `.env` itself.
4. Run the grader:
   ```bash
   python3 ~/.claude/skills/trajectory-rubric-report/grade_trajectories.py <resolved task-dir> <remaining flags from $ARGUMENTS>
   ```
   This first prints the RB1 rubric-quality verdict to the terminal (not
   written to a file) -- a `fail` verdict stops here by default; no trial
   is graded until the rubric itself is fixed, or the gate is bypassed per
   the flags above.
5. Report a concise summary per trial: completion score, blocking stage (if
   any), and the failure reason at that stage -- cite the report file's own
   evidence rather than restating the agent's self-narration. Do not restate
   passing trials at length.
