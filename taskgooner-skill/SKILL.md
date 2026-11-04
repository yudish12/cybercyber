---
name: taskgooner
description: Modify a Deep Hack / OTS Cybersecurity task bundle so every dimension of the current 30-dimension dual-gate (behavior + report) QC rubric scores 5/5, then repackage it. Use when the user hands you a task folder or task.{zip,tar.gz} and asks to bring it up to the latest QC spec, fix it to pass QC, migrate it to the B/R dual-gate format, or harden it to the pass@10 difficulty gate. Pairs with the read-only `qc-audit` skill (taskgooner fixes; qc-audit scores).
---

# taskgooner — bring a task to 30/30 on the current QC rubric

`qc-audit` **scores** a task and never edits it. `taskgooner` is the other half:
it **modifies** the task until every dimension passes, then repackages it. The
two share one source of truth — the current QC spec — so a taskgooner pass is
done only when a fresh `qc-audit` run comes back all-5.

## The source of truth

`rubric/qc_spec.csv` (bundled here) is the current rubric, **verbatim**, 30
dimensions. Read it as the authority for any dispute — word by word, not from
memory. It is the dual-gate (behavior + report) spec:

- **F1-F6** Format, **EN1-5** Environment, **VU1-5** Vulnerability,
  **TR1-5** Trajectory, **EV1-6** Evaluation, **RB1** Behavior-Catalog Quality,
  **RB2** Report-Rubric Quality, **Explanations - Spam Check**.
- The matching scorer is the **`qc-audit` skill (deepseek/B+R build)**: its
  `rubric.json` is this same CSV in JSON, EV6 is pass@10 on deepseek, and it
  grades RB1 + RB2. Use an older qc-audit build only for its fact extractor;
  its verdicts (pass@5 Qwen/Muse, single golden `rubric.json`) are stale.

Confirm the qc-audit build matches before trusting its verdicts:
`grep -c deepseek <qc-audit>/SKILL.md` and that its `rubric.json` has 30 rows
including `RB1 Behavior-Catalog Quality` and `RB2 Report-Rubric Quality`.

## Standing conventions (these override any older copy in the task)

1. **3-field reward.** Every `tests/test.sh` branch writes
   `reward.json = {behavior, report_rubric, reward}` (all numeric) **and** a
   matching `reward.txt`, with **`reward = behavior AND report_rubric`** (1.0
   only when both are 1.0). No `"reason"` or other string key in the JSON — it
   stops Harbor computing pass@k. Oracle/noop run `SKIP_REPORT_RUBRIC=1` and
   write `{behavior,1,·}` placeholders (`{1,1,1}` / `{0,0,0}`).
2. **Dual-gate wiring.** The gate specs live in `operator/behavior-catalog.json`
   (B) and `operator/report-rubric.json` (R). `tests/test.sh` reads a
   server-side behavior oracle for B, calls `tests/run_report_rubric.sh` →
   `run_report_rubric.py` (LLM judge over `tests/agent_judge_prompt.md`) for R,
   ANDs them, and **fails R safe to 0** on any ungradable report. There is
   **NO** attempter `trajectories/pass@k/rubric.json` and **NO**
   `trajectory_analysis_report.md` — delete them if present (F1).
3. **No agent timeout.** `task.toml [agent]` carries only `user` (and never a
   `timeout_sec`); the budget is the 100-turn cap.
4. **Difficulty = deepseek pass@10, < 30%.** The pass@10 run is one model
   (deepseek), 10 trials; the task clears only at **≤ 2 of 10** legitimate
   solves. This run happens in the sandbox (CB-owned); taskgooner hardens the
   task toward it and leaves the trajectories for the CB to capture.
5. **The required file set (F1):** `task.toml`, `instruction.md` +
   `instruction_L{0,1,2}.md`, `fresh_state.json`, `environment/docker-compose.yaml`,
   `environment/NOTICE.md`, the built services' `Dockerfile`s, `solution/solve.sh`,
   `tests/{test.sh, isolation_test.sh, agent_judge_prompt.md, run_report_rubric.sh,
   run_report_rubric.py}`, `operator/{behavior-catalog.json, report-rubric.json}`.
   The judge prompt is named **`agent_judge_prompt.md`** (not
   `judge_prompt_template.md`); fix the name and its reader in
   `run_report_rubric.py` together.

## Workflow

**Step 0 — unpack & checkpoint.** Extract to a working `task/` dir. Keep the
original untouched so you can diff.

**Step 1 — preflight (deterministic).** Fast mechanical pass over the hard,
objective fails:

```bash
python3 references/../preflight.py <TASK_DIR>     # path is skill-root/preflight.py
```

It checks (and cites file:line): F1 file set + forbidden dual-gate artifacts;
F2 `main` service + no static ports/IPs; F5/EV3 reward shape and
`reward = behavior AND report_rubric` (flags a hardcoded `REWARD="1.0"`);
F6 digest pins + resource ceiling + non-root agent + fresh_state; EN3 literal
credentials in compose/source; VU4 class-name leaks in L0/L1/app-source;
RB1 catalog fields + `primary_success == "B AND R"`; RB2 rubric sections +
seven finding fields; the no-agent-timeout convention. Exit non-zero on any
FAIL. **Preflight is a floor, not the verdict** — it cannot judge realism,
discoverability, or difficulty.

**Step 2 — full audit (LLM-judged).** Run the `qc-audit` skill end to end
(extract_evidence → workflow → report) for the authoritative 30-dim verdict
with adversarial verification. This is what decides done.

**Step 3 — fix, word by word.** For every non-5, open the CSV row, read its
fail options verbatim, and apply the matching repair from
`references/fix_recipe.md`. Re-run preflight after each cluster of edits.
Never loosen the verifier to make oracle pass without re-checking noop.

**Step 3b — strip all authored comments.** Before packaging, remove every
authored comment from the source/env files (full-line and inline), keeping only
shebangs and upstream licence headers — see `fix_recipe.md` "Comment hygiene".
Re-validate syntax and re-run the dry-run; behavior must be unchanged.

**Step 4 — harden to the gate.** If the model would solve too easily, add
difficulty the task-appropriate way (layered discovery, resisting-sibling
decoys, opaque failures, auth/privilege gaps) — see `fix_recipe.md`'s VU/EV6
notes. When a model-failure form is supplied, read *why* the model failed and
target that exact gap.

**Step 5 — prove it locally, then repackage.** Build the stack and run the
`solve.sh → submission → test.sh` contract on a fresh boot (oracle = 1) and a
clean boot with no submission (noop = 0); the two must be separate boots. Then
repackage into a clean `task/` folder (scripts +x, no `__MACOSX`/`._*`, drop
`.bak`). The CB runs the deepseek pass@10 in the sandbox for the final TR/EV6
evidence.

## What taskgooner will not do

- It will not invent pass@10 trajectories — those are captured in the sandbox.
- It will not rename a decoy to "fix" it: close the endpoint instead (a rename
  never fixes a reachable path). Likewise a leak is fixed by removing the
  class name / opaque-tagging the token, not by hiding a file.
- It will not loosen a gate below the noop check to force an oracle pass.
