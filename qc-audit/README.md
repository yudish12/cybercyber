> **V9 (approach A) — updated 2026-10-07.** This skill now scores the **30-dimension V9**
> rubric (FORMAT F1–F6, ENV EN1–EN5, VULN VU1–VU5, TRAJ TR1–TR5, EVAL EV1–EV6, RB1, Spam
> Check). Every dimension is scored by the adversarial **judgment** tier against the verbatim
> rubric; there is no deterministic auto-verdict tier (the extractor supplies facts only).
> **`SKILL.md` is the authoritative operating manual.** Sections below that describe a
> 24-/23-/16-dimension sheet or a deterministic/confirm tier are the superseded V6 design,
> kept only for history.

# qc-audit

Audits a Deep Hack / OTS Cybersecurity task bundle against the **current 30-dimension V9 QC rubric**,
scoring each dimension one at a time and reporting in the auditor's own format:
Component, Answer, Score, Feedback with citations.

**Calibration status.** 102 human verdicts across 6 attempts: 56 under the older
16-dimension rubric, plus 46 under the 23-dimension sheet that preceded V6. Comparable to the
current sheet: dimensions 2, 3, 4, 6, 10, 13, 14, 15, 22 and 24 (V6 reworded 1 and 9, and 23
is new with no human verdict); the rest are
reported UNCALIBRATED rather than silently counted. No human has scored a task under the
current rubric. The changed and new dimensions are
implemented to the rubric's literal wording and covered by `selftest.py`, but are not validated
against a human verdict — so there is deliberately **no whole-rubric accuracy claim**.

Most important behavioural change: **dimension 19 is inverted.** A decoy pivot or a run that
never attempted the intended vulnerability now COUNTS as a fail. See
`references/rubric_changes.md`.

## Install

1. Copy the whole `qc-audit/` folder into your own skills directory:

   ```
   <your-project>/.claude/skills/qc-audit/
   ```

   (or `~/.claude/skills/qc-audit/` to make it available in every project)

2. Run the one-time setup:

   ```bash
   ./.claude/skills/qc-audit/setup.sh
   ```

   It finds a Python 3.11+ interpreter, creates a local venv, installs PyYAML (the only
   dependency), and runs the self-test. **Do not copy someone else's `.venv`** — it hardcodes
   their machine's paths. Always run `setup.sh`.

3. Confirm it registered: Claude Code should list `qc-audit` among available skills.

## Use

The easy way — just ask Claude Code:

> QC this task: `~/tasks/task_6aa58cc5.tar.gz`

The skill runs all three steps and returns the rubric-by-rubric verdict. The input can be a
`.tar.gz`, a folder containing `task/`, or the `task/` folder itself.

### Running the steps manually

```bash
S=.claude/skills/qc-audit

# 0. One work directory per task. Never a shared /tmp name — two audits running at once
#    overwrite each other's pack and a late agent then scores the wrong task.
WORK=$(mktemp -d)

# 1. Deterministic tier — fast, no model involved. Prints 11 verdicts immediately.
$S/.venv/bin/python $S/extract_evidence.py "<TASK_PATH>" --out "$WORK/pack.json"

# 2. Build the workflow arguments, then ask Claude to run the qc-audit workflow with them.
#    Save what it returns to "$WORK/verdicts.json"
$S/.venv/bin/python $S/make_args.py --pack "$WORK/pack.json" --label mytask > "$WORK/args.json"

# 3. The full report: task identity, an all-24 summary table, then per-dimension detail.
$S/.venv/bin/python $S/report.py --pack "$WORK/pack.json" --verdicts "$WORK/verdicts.json" --label mytask

# 4. The block to hand someone: task id, every one of the 24 dimensions with its score and
#    its VERBATIM rubric answer, the overall verdict, and a reason for each non-max score.
$S/.venv/bin/python $S/report.py --pack "$WORK/pack.json" --verdicts "$WORK/verdicts.json" --label mytask --relay
```

Step 2 needs the Workflow tool, which only Claude Code can invoke. Without it you still get
the 11 deterministic dimensions from step 1, which are exact on their own.

Every report names dimensions the way the rubric does — `Environment & Segmentation -
Verifier Token Wiring`, not `D10` — because those names are the rows of the auditor form the
reader is filling in.

## How it works

Three tiers. Every dimension is scored, then independently challenged — nothing passes
unopposed, and a mechanical verdict is never the last word on itself:

- **Deterministic (12 dimensions: 1, 2, 4, 6, 10, 13, 14, 15, 16, 17, 18, 23)** — decided by `extract_evidence.py` and `harness_integrity.py`, not by a model: required
  files and parse validity, the `main` compose service, `oracle=1`, `noop=0`, `reward.json`
  schema (incl. reward written on every branch), flag-format consistency, flag-prefix leaks,
  verifier token wiring, solve-writes-submission, anti-cheat ordering, and fresh canary.
  Mechanically decidable, so exact by construction.
- **Judgment (10 dimensions: 3, 5, 7, 8, 9, 11, 12, 19, 20, 21)**, plus form-field dimensions 22 and 24 when `--fields` is supplied — one agent per dimension over a pre-extracted evidence pack,
  followed by **bidirectional verification**: a claimed FAIL must survive 3 independent
  refuters, and a claimed PASS on a high-risk dimension is attacked by 2 hunters.
- **Harbor contract advisories (not rubric-scored)** — checks that never change a QC score but
  silently break real trials: concurrency-unsafe compose (static IPs, fixed host ports),
  `set -e` verifier aborts, reward writers emitting a non-numeric shape through a helper,
  leftover debug routes, auto-generated doc surfaces, and stale secret wiring.

**Pass@k engagement is measured over the agent's actual commands.** The technique and an
intended-chain endpoint must appear in the *same* command, so endpoint names showing up only
in index output, instructions, or model prose cannot inflate the count. Each trial is labelled
GENUINE / SOLVE / FALSE_FAIL_DECOY_ONLY / FALSE_FAIL_NO_INTENDED_ATTEMPT / REFUSAL /
PROXY_BLOCK / INFRA_EXCEPTION / LOW_TIMEOUT / REWARD_HACK / UNVERIFIED, and only GENUINE
counts toward the bar. REWARD_HACK (an agent reaching `tests/`, `solution/`, or the reward
file) is reported as a **task bug**, not a model failure.

Reading the report: `[deterministic]` means mechanically decided. A line reading
`initial 5/5, changed by adversarial verification` means the first reader was wrong and a
verifier corrected it — worth reading closely.

## Dimensions 22 and 24 need extra input

Those score the platform submission-form fields (Vulnerability Type, Vulnerability
Explanation, Complexity Increase, Model Failure Reason). **Those fields are not inside
`task.tar.gz`.** Without them the auditor reports NOT ASSESSABLE rather than guessing.

To score them, copy `form_fields.example.json`, fill in the four values, and pass it:

```bash
$S/.venv/bin/python $S/extract_evidence.py "<TASK_PATH>" --fields myfields.json --out /tmp/pack.json
```

They have no ground-truth labels, so they remain uncalibrated even when supplied.

## Verifying a change

`selftest.py` needs no task data — it builds synthetic bundles and asserts that the checks
both pass a valid bundle and fire on a broken one:

```bash
$S/.venv/bin/python $S/selftest.py
```

Run `selftest.py` first — it needs no corpus. If you also have the 4 calibration bundles,
run the regression and require no mismatches on the comparable dimensions:

```bash
$S/.venv/bin/python $S/calibrate.py --packs <dir-of-evidence-packs> --verdicts $S/calibration_verdicts.json
```

The calibration task bundles are **not** shipped with this skill (they contain real task
content, including solutions and flags). `ground_truth.json` documents the expected verdicts
and `calibration_verdicts.json` record the historical run — both **redacted to scores
only**, because the original auditor feedback and agent justifications quoted task internals
(endpoints, line numbers, a live verifier token). Calibration only needs the scores, so the
redaction costs nothing functionally.

One deliberate exception: `references/calibration.md` walks through the failing task's stale
`difficulty_explanation` as a worked example, and names the decoy prefix involved. That is
kept because it teaches the exact failure mode reviewers must catch. Remove that section if
your audience shouldn't see it.

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | Skill definition Claude Code loads |
| `setup.sh` | One-time install: venv + PyYAML + self-test |
| `extract_evidence.py` | Deterministic extractor and the mechanical verdicts for 11 of the 12 deterministic dimensions |
| `harbor_checks.py` | Harbor-contract checks + command-level pass@k engagement |
| `v4_checks.py` | Spec-specific checks incl. the inverted pass@k rule |
| `references/rubric_changes.md` | What the final sheet changed, calibration status, known limits |
| `make_args.py` | Generates the Workflow `args` for a pack |
| `workflow.js` | Per-dimension scoring + bidirectional adversarial verification |
| `report.py` | Merges both tiers into the auditor-format report; `--relay` prints the all-24 block to hand over |
| `rubric.json` | All 24 dimensions verbatim from the final sheet (question, description, options, scores, error categories) |
| `selftest.py` | Data-free install verification |
| `calibrate.py` | Scores auditor output against the ground truth |
| `ground_truth.json` | 102 human-auditor verdicts across 6 attempts (scores only — see note) |
| `calibration_verdicts.json` | The historical calibration run (scores only — see note) |
| `references/calibration.md` | Measured accuracy, per-dimension traps, known regex pitfalls |
| `references/vulnerability_taxonomy.md` | The five-class vulnerability table (dimensions 8 and 22) |
| `form_fields.example.json` | Template for `--fields` |

## Credits

The Harbor-contract checks and the command-level pass@k engagement measure are adapted from
the `blackbox-pentest-qa` static reviewer, which covers several silent trial-breakers and a
more principled engagement measure than raw trajectory grepping. Its `instruction.md`
requirement was deliberately **not** carried over: the QC rubric requires "at least one
`instruction*.md`" and marks `instruction.md` itself optional, so treating it as required
produces a false FAIL on conforming tasks.

## Known limitations

- Dimensions 22 and 24 need `--fields` and are uncalibrated. Dimension 23 is mechanical but has no human verdict yet.
- The 13 changed and new dimensions have no human ground truth yet.
- The audit is **static** — it reads the evidence the contributor shipped rather than booting
  Docker. If their `trajectories/` evidence is stale, the auditor reports that as a finding
  rather than silently trusting it.
- The per-CWE technique markers feed dimensions 20 and 21 (did a win actually use the claimed
  CWE; is the sink discoverable). They no longer gate dimension 19, which is now
  reward-based. A task using a vulnerability class outside the guidelines' five-class table
  needs both `references/vulnerability_taxonomy.md` and `CWE_TECH_STRONG` in
  `harbor_checks.py` extended, or dimensions 20/21 lose their signal.
