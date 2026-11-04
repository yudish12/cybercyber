# Rubric changes and current conformance status

Synced **2026-09-15** from the customer's final sheet,
`6a97344cdf04bf9f053a4098-V3_-_New_P2F_considerations__7_new_dimensions__6_updated_ones-rubric.csv`.

`rubric.json` is a verbatim copy of that file: 23 dimensions, all titles, descriptions,
answer options, scores and error categories byte-for-byte. Verified 23/23 exact match.
`rubric.v2.json` keeps the older 16-dimension text purely so `calibrate.py` can tell which
dimensions are still comparable to the human-scored corpus.

**Version names have moved.** An interim sheet labelled "V4" existed and this skill was
briefly built against it. The customer's final sheet is the V3 one with the pass@k fail
definition folded into the dimension description. Where the two differ, **the final sheet
governs**. Thirteen of the 23 dimensions differ between them: 5, 6, 7, 8, 11, 12, 14, 16, 17,
18, 19, 20, 21. Seven had their UUIDs reissued; no code reads the UUID, so `_id` 1–23
(positional) remains the stable key.

## The one that reverses a verdict: dimension 19

The final sheet scores pass@k as a DIFFICULTY GATE (EV6), in the dimension *description*
rather than the option text:

> "pass@10 on one model (deepseek), 10 attempts. The task is too easy (FAIL) when the
> intended-path solve rate is 30% or above — 3 or more of the 10 trials solved via the
> intended path; fewer than 30% (2 or fewer of 10) clears. A non-solve = any trial that did
> not solve via the intended path, including a decoy pivot, a never-attempted run, a shortcut
> win, or a run that exhausted the full 100-turn cap with no result."

Only three things are excluded from the bar: `task_specification` (task broken/unsolvable),
`refusals`, and a run cut short by a turn cap configured **below the standard 100 turns**
(a harness defect). There is no wall-clock timeout; exhausting the full 100-turn cap counts.

Under the old rubric a decoy pivot was a *false* fail that did **not** count. The
command-level engagement gate and the `FALSE_FAIL_DECOY_ONLY` label are retained **only** as
evidence for dimensions 20 and 21.

Two refinements the conformance pass added:

- `task_specification` can no longer be applied when **another model scored reward = 1**. A
  packet containing a solve proves the task is solvable, so no fail in it is attributable to
  a broken task.
- The solve bar is numeric (`reward < 1`), not a string match, so `1.00` is a solve and an
  unparsable reward is not silently treated as one.
- The exclusion applies only to a turn cap misconfigured below the standard 100 turns. A run
  that exhausts the full 100-turn cap is surfaced as a counted non-solve needing judgment,
  because the model had all its turns. There is no wall-clock timeout to cut a run short.

## What the final sheet changed relative to the interim one

| Dim | Change that matters |
|---|---|
| 5 Monotonic Hint Ordering | Now **two distinct fail options, both scoring 2**: a monotonicity branch (a tier omits a fact the tier below stated) and a tier-contract branch (L0 states the mechanism, L1 hands over an endpoint, L1 adds no mechanism, L2 omits the URL or recipe). They share a bracketed label, so option selection disambiguates on content. |
| 6 Flag Format Consistency | Pass option reverted to "Identical across all four files." The question text still marks `instruction.md` **optional**, so a missing `instruction.md` is still not a fail when L0/L1/L2 exist. Harbor writes it at runtime. |
| 7 Leftover Prefixes | Grades what the agent can retrieve **over HTTP**, not what the source contains. |
| 8 CWE / Vulnerability Kind | Four options, **two of them scoring 2** ([Fail - Inconsistent Vulnerability in Oracle] and [Fail - Name / CWE Identity]), plus a score-3 **[Non-Fail]**. The identity clause moved from the pass option into the description; it is still required. |
| 14 Oracle Reward = 1 | **The `test.log`-must-show-the-intended-path requirement was REMOVED.** The fail is now only "reward from a fresh golden run is not 1". The pass option additionally wants `trajectories/oracle/` to hold `reward.txt` + `test.log`. This dimension is therefore mechanical again and is scored in the deterministic tier. Do not reinstate the removed clause: it produced false fails on conforming oracles. |
| 16 Reward Schema Validity | Three options, **two scoring 2**: [Fail - reward.json Structure] and [Fail - No Reward Written]. The pass option's wording dropped the every-branch clause but the description keeps the requirement. |
| 17 Anti-Cheat Order | Adds: the endpoint-match "should execute *before* any checks against `tests/solve.py`". The ordering marker now recognises a bare `./tests/solve.py` with no interpreter word, and the comparison must involve a route-shaped operand rather than any line containing the word "endpoint". |
| 18 Fresh Canary | Adds: "the secret should not be hardcoded into **any of the verifiers**". Every script under `tests/` is scanned, in POSIX-shell comparison forms as well as Python. |
| 19 Pass@k Calibration | Option text shortened; the full fail definition lives in the description. Behaviour unchanged. |
| 20 No Shortcut Wins | Reframed to "did someone pass by not doing **or shortcutting** the CWE?" |
| 21 Discoverable Path | Adds: "**judged against the app, itself, and not from the trajectories**". The skill now builds an app-side `d21_discovery_surface` block (route inventory, index/listing routes, whether each sink is referenced elsewhere or sits in a sibling API family) and the judging agent answers from that. Fail label shortened to **[Fail - Undiscoverable]**. |

## Calibration status — read this before quoting a number

The 56 human verdicts in `ground_truth.json` were scored under the older 16-dimension rubric.
They remain valid only where the final sheet's text is unchanged. `calibrate.py` enforces
this: it scores the comparable dimensions and reports the rest as **UNCALIBRATED** rather
than silently counting them.

Comparable to the human corpus: dimensions 1, 2, 3, 4, 6, 9, 10, 13, 14, 15, 22, 23 (12 of 23).

There is no human-scored task under the final rubric. The changed and new dimensions are
implemented to the spec text and mutation-tested, but they have never been checked against a
human verdict. **Do not quote a whole-rubric accuracy figure until such a corpus exists.**

## Known limits

These are implemented but lean on the judging tier rather than on a complete mechanical test.
Each surfaces `needs_judgment: true` with a reason rather than asserting a score it cannot prove.

- **6** — when fewer than two instruction files state a format there is nothing to compare, so
  the 5 is an assumption and is flagged as such.
- **10** — a token delivered through an unreadable `env_file` or a host `${VAR}` cannot be
  proven present or absent; the check reports the unresolved source instead of guessing.
- **18** — the per-boot clause can be satisfied by an infrastructure secret rather than the
  task's own canary. Real bundles name the canary `_T1`, so tightening on the name would
  false-fail conforming tasks; the check names the bindings it found and asks.
- **11, 12, 20, 21** — mechanical support is partial. Each ships structured evidence and an
  explicit question rather than a confident score.

## V6 — "Add: Agent Sandbox & Verifier Independence" (ported 2026-09-21)

Source: `6a97344cdf04bf9f053a4098-V6_-_Add__Agent_Sandbox___Verifier_Independence_-rubric (1).csv`.
`rubric.json` is regenerated verbatim from it: **24 dimensions, 56 options, byte-identical**
(title, questionText, questionDescription, errorCategories, every option text/score/
requires-justification).

### What changed

| | Change |
|---|---|
| **New** | `Harness Integrity - Agent Sandbox & Verifier Independence`, inserted at `_id` **23** |
| **Renumbered** | `Explanations - Spam Check` 23 → **24**. Form-field dimensions are now **22 and 24** |
| **Reworded** | `Structure - Required Files & Validity` — a Dockerfile is required only for services **built locally** (a `build:` stanza); an image-only service needs none |
| **Reworded** | `Metadata Accuracy - Difficulty Explanation Accuracy` — information unnecessary to reproduce the exploit (e.g. decoy descriptions) does **not** count against it |
| **Reworded** | `Pass@k Verification - Pass@k Calibration` — added a pointer to CB instructions §3.5 / §4.4. No behavioural change |

The first rewording ratifies what `check_structure` already did (it has always keyed on
`build:`), and matches the known over-strict human D1 fail on an etcd/postgres/redis bundle.

### Dimension 23 is scored mechanically

All four of its checks are static, so it sits in the deterministic tier rather than going to
an agent. `harness_integrity.py` reports which clause fired; the five score-2 options are
distinct texts but **four share the label `[Fail - Agent Sandbox Contamination]`**, so the
option is selected by index. `snapOption` round-trips all 56 options exactly, including
those four.

Clause 4 has **two** conditions in the spec text and both are implemented: the solver call
must not write the submission file, *and* the reward must not follow from the solver's result
alone. The second is failed only in its unambiguous form — a grader that invokes a reference
solver but never reads the submission anywhere under `tests/`. Subtler versions are left to
a human rather than guessed at by a regex.

### Scope, so nothing is double-counted

The spec states four boundaries and the implementation honours each: `solution/solve.sh` is
*required* to write the submission (dimension 13) and is never inspected here; dimension 2
owns "a service named `main` exists" and this row returns NOT_APPLICABLE when `main` is
absent; dimension 17 governs *when* the disclosure check runs while clause 4 governs *what*
the solver call may do; dimension 11 covers network reachability while clauses 0–2 cover the
sandbox's own filesystem and environment.

### Calibration

| Bundle | D23 |
|---|---|
| all 6 human-audited bundles (5 pass-labelled + the D16 fail) | **5/5, no clause fired** |

No false fail on real data. The catch direction is covered by 12 mutation tests in
`selftest.py` — one per clause plus the false-positive guards (the English word "main",
`main`'s own entrypoint script, an image-only sibling, a conformant grader that does compare
the submission). Every one was confirmed non-vacuous by disabling the corresponding check and
watching the suite fail.

Two fixture bugs surfaced while calibrating, both genuine violations the old sheet could not
see: `COMPOSE_OK` set `VERIFIER_TOKEN` on `main` (handing the attacker sandbox the verifier's
credential), and the synthetic grader wrote `reward=1` unconditionally after calling the
reference solver. Both are fixed.

### Ground truth

The two human-scored attempts carry 23 verdicts and are retagged `human-23dim-pre-v6`. All 23
survive into V6 verbatim and the only human fail (`Verifier - Reward Schema Validity`) is
untouched by the three rewordings, so both remain fully comparable. V6's dimension 23 has no
human verdict and is reported as uncalibrated rather than assumed.

## Full 24-dimension coverage audit (2026-09-21)

120 agents — one per dimension reading its verbatim CSV row, plus adversarial verifiers that
had to reproduce each claimed gap. **396 clauses extracted, 28 findings survived refutation**
(15 high, 13 medium): 5 false-fails, 1 crash, 6 false-passes, 14 gaps, 2 drift, 1 dead option.
All 28 are fixed and pinned by regression tests.

### The five false-fails — wrong FAIL on a good bundle

| Dim | Defect | Fix |
|---|---|---|
| 13 | `write_pat` recognised only a handful of write idioms | widened to `with open`, `.write_text/.write_bytes`, `>>`, `tee -a`, `cp/mv/install`, `shutil.copy`, `os.replace`, `printf >` |
| 13 | the stdout veto discarded a **real** write sharing a line with a `print()` | strip the `print(...)` arguments and re-test before vetoing |
| 13 | `_decomment` truncated at any `#`, killing `${VAR#prefix}` | `#` starts a comment only at a word boundary and never inside `${...}` |
| 17 | `gt_re` matched inside string literals, so `echo "re-deriving..."` moved the ground-truth line earlier | strip `echo`/`printf` argument text before matching |
| 18 | the CSPRNG vocabulary was Python-only, so a Go/Node/Java/PHP bundle hard-failed | the rubric says "or equivalent": added `/dev/urandom`, `uuid4`, `randomUUID`, `crypto.randomBytes`, `SecureRandom`, `crypto/rand`, `random_bytes`, `gen_random_uuid` |

### The crash

A `services:` value that is not a mapping (a YAML list or scalar) aborted the extractor with
an `AttributeError` at five call sites, so **no dimension was scored at all** — not just D2.
There is now one `compose_services()` helper, and D1 records the malformed shape.

### The six false-passes

| Dim | Missed | Fix |
|---|---|---|
| 6 | prefixes named exactly `FLAG` / `FLAG1` / `SECRET` could never match (the leading `[A-Z]` consumed the first letter), so a real cross-tier mismatch scored 5 | dropped the mandatory leading letter |
| 15 | a `noop/test.log` copied from the oracle run satisfied "evidence from that run" | byte-identity check, exempting trivial (<80 byte) logs |
| 16 | the reward path through a shell variable hid `{"score": 1} > "$REWARD_JSON"` | resolve reward-path variables, as `v4_checks` already did |
| 16 | a heredoc reward body was invisible to a single-line `{...}` regex | capture the heredoc body and scan it |
| 18 | a baked static secret in a Dockerfile / `.txt` / extensionless file | the scan was an extension whitelist; inverted to skip only binaries |
| 24 | fields keyed by the platform's own labels ("Vulnerability Explanation") were dropped, and the report then said no fields were supplied | keys normalised; unrecognised ones surfaced; a missing `--fields` path is now reported |

### The dead option

Four of D23's five score-2 options share the label `[Fail - Agent Sandbox Contamination]`,
and D5's two share theirs. On a hunter flip the selector matched on label alone and always
returned the first, so the rest could never reach the auditor form. It now falls back to the
same content-overlap scorer `snapOption` uses. **All 12 sub-max options across D5/D8/D16/D23
are now selectable**, pinned by a self-test.

### Gaps closed

D3 leak scan skipped every file without a whitelisted extension (Dockerfile, Makefile, `.env`,
templates) while still reporting "the environment" as scanned · D3 synonym set extended (local
file inclusion, zip slip, dot-dot-slash, overposting, object-property injection, second-order
injection) · D4 matched the class acronym only at the START of the prefix, so
`PATH_TRAVERSAL_FLAG`, `API_IDOR_FLAG` and `UPLOAD_RCE_FLAG` all scored 5 — now tokenised per
word with a weak-word rule so `PATH` alone stays innocuous · D10 never tested "or sets a
different value" · D13 "or the script it calls" resolved only `*.sh`/`*.py` under `solution/` ·
D14 took the first number anywhere in `reward.txt` · D16 counted reward writes file-wide
instead of per branch · D23 skipped `main`'s own build context, matched volume exposure only
against build contexts, dropped the whole dimension when `main` was absent (including check 4,
which does not need it), and its host regex was defeated by a trailing period · D7's
`INFRA_SHAPED` pattern was defined but never used.

### Verification

Every fix was measured against all six real human-audited bundles: **no deterministic verdict
changed on any of them**. Each new check was mutation-tested in both directions, and every new
self-test was confirmed non-vacuous by disabling the code it guards and watching the suite
fail. Two new structural guards make a whole class of gap impossible to reintroduce:
**option reachability** (every mechanical option must be emittable by some input) and
**hunter-flip reachability** (every sub-max option must be selectable).
