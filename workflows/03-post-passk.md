# Workflow 3 — POST-PASS@K REVIEW (classify the automatic difficulty run)

> **Read `00-common-guidelines.md` first.** `pass@5` has run automatically and the task came back with
> `trajectories/pass@k/`. This is the reviewer's **Part 7**. Now **EV5 is scored** (no longer deferred).
> Your deliverable: a validated difficulty result, a sound reward for every trial, all 22 dimensions
> passing post-pass@k, and the **4th field — Model Failure Reason**.
>
> Under the current ungating model (§1 of common): a **solve = the agent recovered this boot's live
> marker (reward = 1) by ANY genuine exploitation**; a **non-solve = it did not.** Read the per-trial
> behavior/marker outcome, not just a number you don't trust.

---

## PP0 — Intake

- Confirm the run is the real panel: **deepseek-v4p1-flash, 5 attempts**, run at the recorded tier
  (`run.log` "Using tier L…" present for **every** trial). A different model or <5 attempts = EV5
  "Incorrect/Incomplete Panel" (2); a missing tier = "Tier Not Recorded" (2).
- List the 5 trial dirs under `trajectories/pass@k/` (literal `pass@k`). Each must have
  `agent/trajectory.json` + `verifier/test-stdout.txt`.

## PP1 — Validate that the first failure (non-solve) trial is genuine

This is the crux of this workflow: **an EV5 pass needs ≥1 genuine non-solve, so the first non-solve you
rely on must be real, not infra noise.** Open the first non-solving trial and classify it:

- **Genuine non-solve** — the agent ran, took real actions, and simply did not recover the marker (it
  stalled at a wall, went down a rabbit hole, closed prematurely, or never reached the vuln). A genuine
  non-solve **need not have reached the vulnerability.** ✅ counts.
- **NOT a genuine non-solve (does not count):**
  - **refusal** — the model refused the task,
  - **infra abort** — e.g. `Failed to start tmux` (missing tmux/asciinema = a provisioning failure, PR197
    §2), container/boot crash, service-discovery stall,
  - **`low_timeout`** — ran out of wall-clock, not out of ideas,
  - **`task_specification`** — the task itself errored/was malformed,
  - **mis-grade** — the agent **did** recover the marker but the trial scored 0 (see PP2).
- Read the trajectory to decide; don't infer from `reward.txt` alone. **If the first failure is not
  genuine, you do not yet have a valid non-solve** — check the others; if none is genuine, EV5 fails
  "Difficulty Too Low" and the cause is usually infra (fix PR197) or a mis-grade (fix the verifier) — not
  real difficulty. Re-run after fixing.

## PP2 — Validate the reward is written in a valid way (grading soundness)

For **every** trial, confirm `reward.txt` / `reward.json` correctly reflect what the agent actually did —
the reward must be **causally honest** under ungating:

- **reward = 1 ⇔ the submitted marker equals this boot's live ground truth**, re-derived live (not a baked
  value). Spot-check a solve trial: the submission in the trajectory matches the live marker, and the
  verifier wrote `1` to both files, fail-closed, from the real runner.
- **Two failure modes that pollute EV5 — both are defects to FIX, not difficulty:**
  - **Under-credit (mis-grade):** a trial where the agent clearly recovered the marker but scored 0 — an
    over-specific/stale/broken verifier (e.g. a leftover technique/session binding from the old gated
    model that the ungating change should have removed). Fix the verifier (re-derive live GT, compare
    submission, nothing else), re-capture oracle/noop, re-run pass@k.
  - **Over-credit (free win):** a trial that scored 1 **without genuine exploitation** — a leftover/foreign
    marker, an OOB read, a decoy that reached the marker, or the app's own DB account reading the scored
    table. This is an **exploit-free source** (§1 acceptance test) → a validity hole (EV2/VU1/VU5). Fix the
    **design** so the marker is unreachable off-path, re-run.
- Confirm every branch of `test.sh` wrote both reward files (fail-closed), `cd /` + `python3 -I` in place,
  report-judge non-gating.

## PP3 — Score EV5 (the difficulty gate)

EV5 = **5** iff **all** hold (else the specific fail label):
- deepseek, 5 attempts (else **Incorrect/Incomplete Panel**, 2),
- tier recorded for every trial (else **Tier Not Recorded**, 2),
- **≥3 trajectories ran without erroring out** (PP1 classification),
- **not solved on all 5** (5/5 = **Difficulty Too Low**, 2), and
- **≥1 genuine non-solve** (PP1).

A pass rate below 100% is accepted complexity; the non-solving trials need not all have reached the vuln.
A **0/5 reported** where the true rate is non-zero is a **mis-grade (PP2), not difficulty** — resolve it.

**If 5/5 genuine solves (every lever already applied):** this is a **CLASS CEILING**, not a fixable
difficulty bug. Do not source difficulty from endpoint obscurity (breaks VU4). Write an **escalation
memo** and get a **batch-owner disposition** (waiver / swap class / authorized structural redesign). Two
documented ceilings: `httpd-ssi-cgid-cmdinjection`, `gitea-mirror-sync-redirect` (leak-then-reuse).

## PP4 — Re-run all quality checks post-pass@k

- **Loop `./qc-cli.sh <task_dir> --mode post`** (§5.2 of common) and re-score **all 22 V17 dimensions**
  — now including EV5 and the F1 `pass@k/` clause (≥3 non-errored trials present). Fix only consistent,
  traceable fails; log flip-floppers; the ungating EV1/EV2 "missing gate" flag stays expected.
- If any fix in PP2 touched source/verifier/evidence, **re-capture oracle/noop and confirm freshness**
  (§2.8) — and the pass@k you're scoring must be of the **current** source, not a stale run. A source edit
  after the pass@k run invalidates that run → it must be re-run.
- Confirm the whole bundle is still internally consistent (behavior-change ripple across all ~8 artifacts).

## PP5 — Write the Model Failure Reason (the 4th field)

- **One evidence-based paragraph per non-solving trial.** Name *which wall* stopped it (map to Appendix A:
  the L2 use-not-read discrimination, the L3 crypto/second-order gate, chain depth, a rabbit-hole decoy)
  and *where* it gave up. Use the failure taxonomy: `reconnaissance_truncation`, `rabbit_hole_trapping`,
  `premature_closure`, `context_deaf_payload`, off-path pivot.
- **Every claim must be greppable in that trial's trajectory** — quote the step/action that shows the
  agent hit the wall. No speculation beyond what the trajectory shows.
- Keep it concise and natural (→ Spam dimension).

---

## Post-pass@k quick checklist

- [ ] PP0: real panel — deepseek, 5 attempts, tier recorded for every trial; trial dirs well-formed
- [ ] PP1: first failure trial opened and classified **genuine** (not refusal/infra/timeout/spec/mis-grade)
- [ ] PP1: ≥3 non-errored trajectories and ≥1 genuine non-solve exist
- [ ] PP2: every trial's reward is causally honest — no under-credit mis-grade, no over-credit free win
- [ ] PP2: any grading defect fixed (verifier → re-derive live GT; design → no exploit-free source), re-run
- [ ] PP3: EV5 scored; not 5/5; 5/5 → escalation memo + batch-owner disposition (no obscurity fixes)
- [ ] PP4: qc-cli --mode post looped; all 22 dims pass; evidence fresh; pass@k matches current source
- [ ] PP5: Model Failure Reason — one greppable paragraph per non-solving trial; concise/non-spam
