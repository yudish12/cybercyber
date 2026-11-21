# Deep Hack workflows

Aligned, de-noised handbooks for the three roles. Each is self-contained for an agent with no project
context. **Always read `00-common-guidelines.md` first**, then the one workflow for your task.

| File | Use when |
|---|---|
| **`00-common-guidelines.md`** | Always first. Goal, the **ungated reward model** (§1), hard constraints (§2), the V17 ship bar (§3), folder tree (§4), tooling (§5), pass@k mechanics (§6), PR197 infra gate (§7), ownership (§8), + **Appendix A** difficulty levers and **Appendix B** anti-patterns. |
| **`01-attempt.md`** | You build/harden a task. You do **not** run pass@k. (P0–P5) |
| **`02-review-l0.md`** | You audit a previous attempter's bundle **before** pass@k. Difficulty judgment first, then every dimension, then guarantee a fair pass@k. (R1–R6) |
| **`03-post-passk.md`** | `trajectories/pass@k/` is present. Validate the non-solve + reward soundness, score **EV5**, write the **Model Failure Reason**. (PP0–PP5) |
| **`master-prompt.md`** | The compact paste-to-a-fresh-agent dispatch — one block per task type. |

**The one idea that changed everything (see 00 §1):** reward is **ungated** — `reward = 1` iff the
submitted marker equals the live ground truth, by **any** path. There is no intended-path/technique gate.
The no-shortcut guarantee now lives entirely in **design**: the marker must be impossible to obtain
without a genuine exploit, with **exactly one path** reaching it. Automated QC (qc-cli, chunked workers)
still encodes the old gate, so an EV1/EV2 "missing technique gate" flag is **expected** and is cleared by
the design proof, not by adding a gate.
