# workflow-v2 — known inconsistencies and the resolution we follow

Found 2026-11-13 while cross-reading `guidelines.md`, `taskworkflow.md` and `pre-submission-checklist.md`.
Until the docs are patched, apply the **Resolution** column, not the stale line.

## V17 update (2026-11-17) — rubric now 22 dimensions, EN5 split out
The QC rubric advanced to **V17** (`6a97344…-V17-…-rubric.csv`, 22 scored dimensions). Applied across
`guidelines.md`, `taskworkflow.md`, `pre-submission-checklist.md`, `reviewer-guidelines.md`,
`sot-rules-enforcement-matrix.md` and both `manual-qc-audit-v13-parallel` / `manual-qc-audit-v14` skills:
- **Provenance / Licensing is its own dimension `EN5`** (split out of EN4). EN4 keeps Reproducibility +
  digest-pinning (`Unbounded or Unpinned`); EN5 owns NOTICE provenance + every third-party license.
- **EN5 is graded 2/3/5 on a where-pivot:** in `NOTICE.md` → 5; not in NOTICE but **credited elsewhere in
  the task files** → **3 Non-Fail** (this *relaxes* the old "only the top-level NOTICE.md counts" auto-fail);
  attributed **nowhere** → 2 Fail.
- **New hard-fail:** a third-party component that **cannot be legally used for commercial purposes** → 2 Fail.
- **First-party (self-written) code needs no provenance.**
- **VU5 "Fake or Stubbed Decoy": Fail(2) → Non-Fail(3)** (this was already in v14; now also in v13-parallel).
- The ship bar is now **all 22 at 5**. `references/calibration_log.md` predates V17 and tags provenance cases
  "EN4" — read those as **EN5**, under the 2/3/5 grading.

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
- **VU3 covers ALL task-authored source under `environment/**`, including expert-only gateway / proxy / verifier / init / harness code — reachability is NOT a free pass** (determination 2026-11-17 on jiro/image-cache-deception; supersedes the earlier "only a real fail when agent-reachable / gateway grading code legitimately names the CWE" reading). A comment, docstring, **or identifier** that **narrates this task's scored class or mechanism** (e.g. `cache-poisoning`, `prime_snapshot_cache`, a `cache_key_confusion` label) is a scored VU3 fail even though the agent cannot read the gateway's source — strip it to a neutral, effect-named token (`warm_snapshot_copy`, `attestation_via_disclosed_snapshot`, "serves the stored image without re-checking authorization"). **Narrow functional exemptions that MAY name the class** (because they must, to work): `instruction_L2` (by design); the **top-level `NOTICE.md` provenance line** (the CVE id + upstream CWE, as a licensing fact); and **report-grading criteria** that reference the class to judge the agent's own report (`tests/report/rubric.toml`, `operator/report-rubric.json`). **Not task narration:** unmodified upstream vendor code naming *other* (non-scored) classes in its own security comments, and a **generic identifier** that merely contains a word like `cache` for an app's own unrelated feature (a client API-response cache, a permission-check cache). Judge whether it telegraphs THIS task's vuln — but do not treat "the agent can't reach it" as a pass for task-authored narration of the scored flaw.

## 2026-11-18 — resolved: RB1 keystroke-vs-server-event contradiction + new runner-gated checks
- **RB1 contradiction RESOLVED.** `guidelines.md` §6.4 (decisive stages credit SOLELY from the gate/audit;
  missing signal → `{s:False}`, never `passed`) is now marked **authoritative**, and the `reviewer-guidelines.md`
  RB1 row was rewritten to match (server-observed event per reached stage; no keystroke/substring credit;
  no collapse). The old "a trajectory-credited technique_fidelity stage anchored on the literal target's own
  keystrokes is acceptable" wording is superseded — do not apply it.
- **New checks added (grafana/ssrf-guard-drop retro, `feedbacks/workflow-gaps-from-grafana-retro.md`):**
  pre-sub **A1** (oracle must come from the real runner; fabricated/non-building = score 1), **A8** (`dash -n`
  every script — runner uses `sh`), **A9** (image builds; no `|| true`-masked build step; from-source vendored),
  **A10** (`operator/` mounted-or-absent — runner FATALs otherwise), **A11** (wheel-METADATA→NOTICE license
  diff; never ADD comments; leak re-grep after every edit). Mirrored in `guidelines.md` §8.1 + §10.1,
  `taskworkflow.md` P2 + §3.4, and `sot-rules-enforcement-matrix.md` §8.
