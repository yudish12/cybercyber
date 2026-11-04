---
name: trajectory-rubric-report
description: Grade every trial in a pass@k job against a task's rubrics.json (the project's {"Criteria": [{id, stage, category, criterion}, ...]} shape), writing one trajectory_analysis_report.md per trial with a completion score, per-stage breakdown, blocking stage, and failure reason. Before grading any trial, first runs an RB1 rubric-quality pre-check against the rubric itself (atomic/objective/self-contained/clearly-triggered/positively-phrased criteria, stage-success + no-reward-hacking coverage) and prints the result to the terminal (no file written for this step) -- by default this is a hard gate, so trajectory_analysis_report.md is only written if the rubric itself passes this check. Use after a pass@k run completes, when the user wants a rubric-graded report on how each trajectory actually performed, not just the deterministic verifier's bare reward.
---

# trajectory-rubric-report

A second, LLM-judged opinion layered on top of a pass@k run's deterministic
verifier results -- not a replacement for them. The deterministic verifier
(`reward.txt`/`test-stdout.txt`) still owns the real pass/fail; this skill
reads each trial's raw transcript and grades it against the task's
`rubrics.json`, producing a report that explains *how* the trajectory got to
that reward, stage by stage.

Before grading a single trial, it checks the QUALITY of the rubric itself --
the real production QC rubric's "RB1 Rubric Quality" row, as a judge call
against the rubric alone (no transcript): is every criterion atomic,
objective, self-contained, clearly triggered, and positively phrased, and
does the set as a whole cover both required categories (stage success, and
no reward hacking / no sandbox escape) without being satisfiable by a noop,
shortcut, or decoy/other-exploit pivot. This catches a malformed rubric
*before* it produces misleading per-trial completion scores across every
trial in the job -- grading ten trajectories against a bad rubric just
means ten reports with the same underlying defect, caught too late. The
result is printed to the terminal once, before any trial is graded (no
file is written for this step -- it's meant to be read right there in the
run's own output, not filed away per-trial).

**By default this is a hard gate**: a `fail` verdict stops the script right
there -- no trial is graded and no `trajectory_analysis_report.md` is
written at all until the rubric itself is fixed. Pass
`--force-grade-despite-quality` to grade trials anyway despite a `fail`
verdict, or `--skip-rubric-quality-check` to skip this whole step (and the
gate with it).

Independent of the sibling `sandbox_skills` skill one directory up (that one
runs pass@1 trials) -- this skill only grades trials an earlier run already
produced, from any source: `sandbox_skills`, `blackbox-pentest-pass1`, or
`ops/launch_fleet.py`.

## Usage

```
./run.sh <task_dir> [--jobs-dir DIR] [--rubrics PATH]
                     [--judge-model fireworks_ai/kimi-k3] [--max-transcript-chars 400000]
                     [--skip-rubric-quality-check] [--force-grade-despite-quality]
```

- `task_dir` — the Harbor task directory (same one whatever pass@k run ran
  against).
- `--jobs-dir` — defaults to `<task_dir>/trajectories/pass@k`; point it at
  whichever pass@k run's output directory you want graded.
- `rubrics.json` is looked up, in order: `--rubrics` if given, else
  `<task_dir>/rubrics.json`, else `<jobs_dir>/rubrics.json`.
- Needs `ANTHROPIC_API_KEY`/`ANTHROPIC_BASE_URL` already sourced into the
  shell before running (`set -a; source ./.env; set +a` from the project
  root, the same convention every other skill here uses).
- The judge call goes through the proxy's OpenAI-compatible route
  (`/chat/completions`, Bearer token) -- the native `/v1/messages` route
  answers 403 "This route is not publicly accessible" for this key,
  confirmed live. Default judge model is `fireworks_ai/kimi-k3`, chosen to be
  independent of the models actually run in the trials being graded.

## What it reads

Every trial directory under `jobs_dir` that has an `agent/episode-*/` tree
and a `verifier/` directory (the same shape `sandbox_skills` and
`blackbox-pentest-pass1` both produce). For each trial it concatenates every
episode's raw `prompt.txt` (terminal output) and `response.txt` (the agent's
own turn) into one transcript, truncating from the middle (keeping head and
tail) if it exceeds `--max-transcript-chars`.

## What it prints (not written to a file)

Before any trial is graded, the RB1 rubric-quality pre-check result is
printed straight to the terminal: a verdict (`pass`/`fail`), per-criterion
atomic/objective/self-contained/clearly-triggered/positively-phrased flags
with any issue found, whether the set covers stage success and
no-reward-hacking, and whether it looks satisfiable by a noop/shortcut/decoy
pivot. Read it there -- it isn't saved anywhere.

## What it writes

One `trajectory_analysis_report.md` per trial, saved into that trial's own
directory (only if the rubric-quality gate above passed, or was bypassed),
containing:

- **Completion score** — the share of rubric items the judge marked passed
  (e.g. `6/10 rubrics pass (60%)`).
- **Per-stage performance** — a table of every stage present in the rubric,
  how many of its items passed, in the fixed stage order (discovery →
  foothold → precondition → exploitation → evasion → payload_craft →
  escalation → exfiltration → secret_resolution → submission).
- **Blocking stage** — the earliest stage (in that order) where not every
  item passed; `none -- all stages passed` if the trajectory cleared
  everything.
- **Failure reason** — the evidence text from the first failing item at the
  blocking stage.
- **Detailed rubric results** — every item's id/stage/result/evidence, for
  anyone who wants to check the judge's reasoning against the raw transcript
  directly rather than trusting the summary.

## What this is NOT

- Not a replacement for the deterministic verifier — a trajectory's real
  reward still comes from `reward.txt`. This report is diagnostic: it
  explains *why* a 0 happened (or confirms a 1 happened cleanly), using the
  same discipline this project's manual false-fail investigations have used
  all along (grep the raw transcript for real evidence, never trust the
  agent's own narration of what it did).
- Not a substitute for `harbor analyze` where that works — it exists because
  `harbor analyze` is broken in this environment (an auth conflict between
  `ANTHROPIC_API_KEY` and a separate OAuth login), not because this is
  meant to be a general-purpose replacement for it.
- Does not run trials itself — point it at an already-completed pass@k job
  directory. Live-tested this session against a real completed trial (a
  known genuine pass): correctly scored 6/6, cited real transcript evidence
  per item, and correctly avoided a false reward-hacking flag on a red
  herring (the agent probed unrelated debug endpoints that 404'd and were
  never actually used to recover the flag).
