# Workflow-v2 gap retrospective — grafana/ssrf-guard-drop (2026-11-18)

Written for: whoever maintains the `workflow-v2/` docs. Maps every real issue this task hit to the
workflow weakness that let it reach the platform, with the doc location and a concrete fix. The task
itself is now green locally (oracle=1/noop=0); this is about why the *process* didn't catch the problems
earlier.

## The one root cause (everything else is downstream of it)

**The workflow trusts shipped oracle/noop evidence it never forces anyone to reproduce, and the
"self-audit" it leans on is static — blind to build, shell, runtime and packaging.**

The grafana image, as shipped, **could not build** (`go build -o /out/grafana` with no `mkdir -p /out`,
masked by `|| true`). Therefore the shipped `trajectories/oracle/reward.txt=1` **was never a real
capture** — it was fabricated or taken against a different build (tell: all evidence files shared one
mtime, and the image fails at `COPY --from=gbuilder /out/grafana`). That single fake artifact then hid
*four* independent blockers (build failure, non-POSIX solve, non-POSIX maze_test, operator/ FATAL),
because the only gate that exercises those — actually running the `blackbox-pentest-checks` runner, which
**builds the images, boots them, and runs `sh /solution/solve.sh`** — was skipped by the attempter and is
**explicitly skippable by the reviewer**:

- `reviewer-guidelines.md` Part 2.1/2.2: "your job is to test the claim, not to repeat the work by
  default… If oracle and noop evidence is clean, do not re-run them." Acceptance criteria are
  *content/consistency/mtime* only — **nothing requires proving the image builds or that the evidence came
  from the real runner.** A fabricated oracle whose image can't build passes 2.2.
- `taskworkflow.md` P2 and `pre-submission-checklist.md` A1/A2 describe running the checks but never say
  "the build must succeed" or "this evidence must come from the runner, not by hand."

**Fix (highest value):** make a successful real-runner build + oracle=1 + noop=0 a **mandatory,
non-skippable gate** for the attempter *and* the reviewer. Delete the "accept shipped evidence without
re-running" shortcut, or qualify it to "only if you have personally re-run the runner on this exact tree
and it built." Evidence whose image does not build is a fabrication → Overall Quality 1, not a pass.

## Why the self-audit (manual-qc-audit / cyber_quality_check) can't be the gate

It is **static**. It cannot see: a build failure, a bash-ism that dies under `sh`, an unmounted
`operator/`, a wheel's real license, or whether services boot. In this task the static QC twice reported
**"READY — no blocking defect"** while four blockers existed, then flip-flopped with **false-positive
fail-closed** rows (EN2/VU3/VU5/EN4) that obscured the two real static defects (EN5 license, RB1 collapse).
So the workflow's P3 is simultaneously **over-trusted** (treated as the ship gate) and **noisy**. P2 (real
run) is the real gate; P3 is advisory. The docs imply the opposite ordering.

## Issue → workflow gap → fix

| # | Real issue | Should have been caught by | Why the workflow missed it | Fix (where) |
|---|---|---|---|---|
| 1 | `solve.sh` `<<<` here-string → oracle fails under the runner's `sh`/dash | P2 real runner (`sh /solution/solve.sh`) | fabricated oracle (root cause) **and** the words dash/POSIX/`<<<`/"solve runs under sh" appear **nowhere** in workflow-v2 | Add to `pre-submission-checklist.md` + `taskworkflow.md` P2: run `dash -n` on **every** shipped `.sh`; state the runner executes `solve.sh`/`test.sh` under `/bin/sh` (dash), so no `<<<`, `local` is ok, no `${v:a:b}`, no arrays |
| 2 | `maze_test.sh` `<<<` + `${t:0:12}` | same | same | same dash-n lint (covers all scripts, not just solve) |
| 3 | grafana Dockerfile won't build (`go build -o /out/...` no `mkdir`; `\|\| true` masks it) | P2 (the build) | fabricated oracle; **no "confirm the image builds" step**; **no lint for `\|\| true` on artifact-producing RUNs**; from-source build not addressed | Mandatory real build; add a Dockerfile lint: no `\|\| true`/`; true` on a RUN whose output a later stage COPYs; require an explicit `test -x`/existence assert after a build that produces a binary |
| 4 | `operator/` present but unmounted → runner **FATAL**; also a latent leak (walkthrough probe scripts in the bundle) | P2 (runner FATALs) | fabricated oracle; workflow calls `operator/` an "optional B/R-spec home" but **never states** (a) the runner FATALs on present-but-unmounted `operator/`, (b) don't put expert probe scripts there | Document the `operator/` rule in `guidelines.md` §1/§2 + checklist: `operator/` is **either** the mounted, access-controlled B/R-spec dir **or absent**; never a home for expert probes/logs (those live outside `task/`) |
| 5 | EN5: `python_dateutil` NOTICE license wrong (`PSF-2.0` vs real `BSD-3-Clause AND Apache-2.0`) | P3 EN5 self-audit | the rule exists in prose ("check each wheel's metadata, not the summary") but is **executed by eyeball**; easy to miss 1 of 61 | Ship a helper: extract every `vendor-wheels/*.whl` METADATA `License`/classifiers and diff against `NOTICE.md`; flag mismatches. Make it a checklist command |
| 6 | RB1: st3/st4/st5 keystroke-spoofable (orig); then the re-anchor's `decisive()→passed` fallback = prerequisite collapse | P3 RB1 + reviewers | **doc contradiction**: `guidelines.md` §6.4 says decisive stages credit **solely** from the gate/audit and the no-evidence branch is `{s: False}`; `reviewer-guidelines.md` RB1 says "keystroke-anchored on the literal target" **passes**. The lenient reading was applied | Resolve the contradiction in favor of §6.4: decisive `technique_fidelity`/`outcome` stages credit **only** from server-observed signals; missing signal → `False`, never `passed`/all-true. Fix the `reviewer-guidelines.md` RB1 row |
| 7 | My own fix **added comments naming "SSRF"** into `environment/**` (a VU3/F5 leak) | §8.1 strip-comments + post-edit leak re-grep | §8.1 is advisory and end-of-process; there is **no "don't add comments" rule** and **no enforced re-grep after each edit** | Make it a hard gate: no authored comments in `environment/**`; **re-run the §8.1 LEAK grep after every edit**, not just before packaging; add "never add explanatory comments to task files" to the authoring rules |
| 8 | Fabricated/stale oracle accepted | reviewer-guidelines 2.2 + freshness advisory | freshness is **mtime-only** (fabricated files had a consistent mtime and "matched the files"); nothing proves the capture is real | See root-cause fix. Also strengthen freshness: an oracle `test.log` must contain the runner's own markers (build log, `reward = '1' (expected '1')`), not just `[disc]`/hand-text |
| 9 | QC judge noise (EN2/VU3/VU5/EN4 fail-closed FPs) + "READY" missing the real blockers | — | workflow positions the static/LLM QC as the gate; it is blind to build/runtime and noisy on live-state rows | Reframe doc ordering: **P2 real build+run is authoritative**; P3 LLM-judge rows are advisory, re-run, fix only consistent/traceable ones (this is in §11.8 but the P-order undercuts it) |
| 10 | Build hermeticity (grafana from-source fetches GitHub + Go modules at build) — latent; built locally only because network was available | enforcement-matrix §5 flags it as a **gap**, advisory | the §2.6 upstream-app CVE/build rules are a known ❌ gap cluster (matrix §5/§7), never promoted to a checklist step | Promote matrix §5 items to real checklist checks; for from-source builds, require vendoring the source tarball + a Go module cache (same philosophy as the vendored pip wheels) so the build is offline |

## The two-line summary for the docs

1. **Nothing ships on trust.** The attempter and the reviewer must each run the real
   `blackbox-pentest-checks` runner on the exact tree; the image **must build**, oracle **must** read 1,
   noop **must** read 0, captured by the runner (not by hand). Fabricated/unreproducible evidence = score 1.
2. **Add the checks a static audit can't do, as explicit steps:** `dash -n` every script; Dockerfile lint
   for `|| true`-masked build steps and build-time network fetches of source/modules; the `operator/`
   mounted-or-absent rule; a wheel-METADATA→NOTICE license diff; and a mandatory LEAK re-grep after every
   edit. These five would have caught issues #1–#7 before the platform ever saw them.
