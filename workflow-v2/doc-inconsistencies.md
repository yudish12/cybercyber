# workflow-v2 — known inconsistencies and the resolution we follow

Found 2026-11-13 while cross-reading `guidelines.md`, `taskworkflow.md` and `pre-submission-checklist.md`.
Until the docs are patched, apply the **Resolution** column, not the stale line.

| # | Where | Inconsistency | Resolution we follow |
|---|---|---|---|
| 1 | taskworkflow §2 P0 step 4 (l.114-115), §3.3 hermetic bullet (l.255), §9 (l.544); guidelines §9 (l.779) | Still says `main` is `network_mode: no-network`, "no proxy to check" | PR #197 wins: `main` has **no `networks:` key**, `allowlist` + `allowed_hosts=[<gateway>]` in `[environment]` and `[agent]` when `main` reaches a sibling; `no-network` only for single-container. Debug "empty response" as discovery/health + sidecar allowlist, not "no proxy". |
| 2 | taskworkflow §3.1 (l.147-149) vs guidelines §8.1 / checklist N6 | taskworkflow says `cpus = 1.0` is the safe ceiling; guidelines/checklist say do not default — confirm the host with the batch owner (batch_01 convention is 2) | `cpus` must be declared. Value = **open question to confirm with the batch owner**; flag it as NOT-VERIFIED (N6) rather than silently changing it. Recommend `1.0` only if the host is unknown and the platform has 1-CPU sandboxes. |
| 3 | checklist S3 (l.341) | `grep '^[[:space:]]*timeout_sec' task.toml` also hits the legitimate `[verifier] timeout_sec` and `[environment.healthcheck] timeout_sec` → false FAIL | Scope it to the `[agent]` table only: `awk '/^\[agent\]/{a=1;next} /^\[/{a=0} a&&/^[[:space:]]*timeout_sec/' task.toml` must be empty. |
| 4 | checklist A6 (l.51-53) | Freshness only compares against `trajectories/oracle/reward.txt`; a stale pass@5 passes A6 if oracle/noop were re-run after a source edit | Also compare against the **oldest** `trajectories/pass@k/**/agent/trajectory.json`; any source file newer than it ⇒ pass@5 stale ⇒ re-run. |
| 5 | Model Failure Reason scope: taskworkflow §1 diagram + §8 say "per non-solving trial"; guidelines §8.2 + checklist X4 say "per trial … exact success/stop point" | Scope mismatch | Follow the stricter rule: **one paragraph per trial** (solves give the success point; non-solves give the stop point + one §7.5 label). |
| 6 | Workspace | `blackbox-pentest-pass1/` (reviewer Part-7 runner) is not unzipped beside `task/` | Needed only for Part 7; flag before the pass@k step. |
| 7 | guidelines §2.3 vs SOT §1.7 | guidelines lists only five CWE types; prior tasks (cacti CWE-78) shipped other classes by user decision | Check the SOT §1.7 list for the task's class before deciding F4; if outside, raise to the user, do not silently re-class. (jiro/rsc-source-exposure CWE-502: user kept it out-of-catalog, 2026-11-13.) |

## Notes from the dolibarr audit (lessons now folded into the main docs)
These recurred enough to generalize; each is now in `guidelines.md`/`taskworkflow.md`/the checklist at the
cited dimension, recorded here so the determinations aren't re-litigated:
- **EV2 "exploit-free credit" is the stickiest fail.** Two moves close it by construction: bind credit to a
  **server-observed technique signal** (gateway saw the intended endpoint/act), not the marker merely
  appearing; and scope the scored secret so the **app's own DB/service account can't read it** (dedicated
  reader credential the exploit must recover). Either alone is insufficient. → gl §10 EV2 / §6.2, checklist EV2.
- **The platform LLM judge is non-deterministic.** On this task EN2/VU2/VU4/VU6 each flipped PASS↔FAIL
  across runs on the **same** bundle; only EV2 and F6 (CVE provenance) failed consistently and were the real
  ones. Rule: re-run, fix the consistent/traceable fails, log the flippers as noise. → gl §11.8, checklist A3.
- **A wrong-product CVE is a hard fail that hides behind a perfect task.** We shipped a Gitea CVE id under a
  Dolibarr task. Verify every CVE id vs NVD (product + version range + flaw) before it enters any file. →
  gl §10 F4 / §11.9, checklist F4.
- **No authoring/changelog narration in bundle docs or comments** ("removed the guard", "was CVE-X, now…",
  "neutralized the RCE string"). Describe the final state only; re-grep `environment/**` for leak terms
  after editing any comment (your own new comment is the usual fresh leak). → gl §11.10.
- **Verifier timeouts are a chain**: inner check (`check.py`) ≥ its runner's (`behavior.sh`) retry budget;
  `[verifier] timeout_sec` ≥ inner check + report judge. A less-patient verifier false-aborts an earned
  solve. → gl §10 EN4, checklist EN4.
- **Capture evidence from the FIRST solve on a FRESH boot.** Stateful exploits (plant a record, consume a
  one-shot) can't re-run on the same boot; wait for stable health after `down -v && up` before capturing
  (a stale pre-`down` boot looks healthy). → gl §11.5.
- **Wheel license = full METADATA expression** (not truncated to the first token); **first-party license =
  a token** (`Proprietary`), never `N/A`. → gl §10 EN4, checklist EN4.
- **Ship `tests/stages/run_stages.sh`** alongside the rubric, mirroring the sibling runners. → taskworkflow §2 SOT-extras.

## Notes from the jiro audit (NOT doc bugs — corrected my own earlier assumptions)
- `atif-trajectory` (hyphen) in `tests/report/rubric.toml` is the **correct** rewardkit key — every known-good archive task uses it. Not a typo.
- A VU3 `environment/**` leak-term hit is only a real fail when the file is **agent-reachable** (served / in the running image / in `main`). Expert-only grading + provenance files (NOTICE.md CVE line, gateway grading code, tests/report criteria, operator catalog — the last two aren't even under `environment/`) legitimately name the scored CWE/CVE. Judge reachability, not just the grep.
