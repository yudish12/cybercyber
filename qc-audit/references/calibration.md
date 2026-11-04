# Calibration notes

> ## ⚠ HISTORICAL RECORD — superseded numbering and one superseded rule
>
> This file documents the calibration run against the **older 16-dimension rubric**. It is
> kept because the failure modes it records are still real, but two things in it no longer
> apply to scoring:
>
> 1. **Dimension numbers are the old ones.** Old 14 (Pass@k Calibration) is now **19**.
>    Old 9/10/11/12/13 are now **10/13/14/15/16**. Old 7 and 15 are now **8** and **22**.
> 2. **The genuine-vs-false-fail rule quoted below is SUPERSEDED.** The current rubric
>    replaces it with a difficulty gate: EV6 (old dimension 19) is pass@10 on deepseek and
>    FAILS (too easy) when the intended-path solve rate is >=30% (3+ of 10 solved); a decoy
>    pivot, a never-attempted run, a shortcut win and a run that exhausts the full 100-turn
>    cap are all non-solves. Only `task_specification`, refusals and a below-standard turn cap
>    (under 100 turns) are excluded. The engagement markers described here are now evidence for dimensions
>    **20 and 21 only**. See `rubric_changes.md`.



Derived from 4 real task bundles with 56 human-auditor verdicts (the feedback PDF).

## The ground truth

| Attempt | Task | CWE | Verdict |
|---|---|---|---|
| `6aa46932df3c3e50b8e623a0` | shopops/sqli | CWE-89 | PASS (14/14 at 5/5) |
| `6aa52b72b5404a42e0b59012` | shopops/path-traversal | CWE-22 | PASS (14/14 at 5/5) |
| `6aa56882b52c541c627ec38f` | shopops/mass-assignment | CWE-915 | PASS (14/14 at 5/5) |
| `6aa58cc5246730f172ea4875` | shopops/sqli | CWE-89 | **FAIL** — 2 dimensions at 2/5 |

The two fails, both on the last task:
- **Pass@k Calibration (Genuine Model Fails)** — all 3 models scored 0 but none attempted
  the intended SQLi; they all submitted a mass-assignment decoy value.
- **Difficulty Explanation Accuracy** — two decoy descriptions in `difficulty_explanation`
  no longer match the code.

**Base rate: 54/56 pass (96.4%).** The dominant risk is *false positives*. An auditor that
flags plausible-looking-but-compliant things will be wrong far more often than one that
misses a subtle fail. Both directions are guarded, but weight accordingly.

The feedback PDF covers **14** dimensions. That rubric had **16**; dimensions 15
(Vulnerability Type Correctness) and 16 (Explanations Spam Check) are **uncalibrated** and
their inputs are not in the tarball.

## Dimensions 15 & 16 are not in the bundle

The submission-form fields — "Vulnerability Type" radio, "Vulnerability Explanation",
"Complexity Increase", "Model Failure Reason" — live on the platform, **not** in
`task.tar.gz`. Verified: no bundle contains them. Without `--fields`, report both as
NOT_ASSESSABLE. Do not infer them from `task.toml`.

## Dimension 14 (now dimension 19) — the discriminator that worked

This is the subtlest dimension and the one the failing task actually failed. The rule:

> A **genuine** fail = `reward < 1` **AND** the model attempted *this task's own vulnerability
> class* and could not finish. A model that scored 0 while only working a decoy of a
> **different** class is a **false** fail and does not count.

**SUPERSEDED.** The current rubric reverses this for dimension 19: the decoy pivot now counts
as a fail. The technique-marker machinery below is retained, but it feeds dimensions 20 and 21
(did a win actually use the claimed CWE; is the sink discoverable), never dimension 19.

The extractor implements this by mapping the task's CWE to high-confidence technique markers
and counting them in each trajectory (`strong_intended_hits`):

| CWE | Strong markers |
|---|---|
| 89 (SQLi) | `union_select`, `config_store`, `marker_ref`, `sql_comment_bypass` |
| 22 (Traversal) | `path_traversal` |
| 915 (Mass assignment) | `mass_assign` |
| 918 (SSRF) | `ssrf` |
| 639 / 284 (IDOR) | `idor` |

Note on model names below: the four calibration bundles were shot at different dates, so their
shipped trajectories name whichever panel was current then (`claude-opus-5`, `gpt-5.6-sol` on
the older ones). Per the guidelines change log of Sep 11 2026 the current Pass@1 panel is
**Deepseek v4, Kimi K3, Gemini 3.6 Flash**, and the bar is **at least 1 of 3** genuine fails.
The auditor never hardcodes model names — it reads them from each trial's `result.json` — so a
future panel change needs no code edit.

Measured separation across the 4 tasks — clean, with no overlap:

| Task | Model with reward 0 | strong hits | Genuine? |
|---|---|---|---|
| A (CWE-89) | claude-opus-5 | 6 | yes → 5/5 |
| B (CWE-22) | gemini-3.7-flash | 52 | yes → 5/5 |
| C (CWE-915) | deepseek-v4 | 24 | yes → 5/5 |
| D (CWE-89) | all three | **0, 0, 0** | no → **2/5** |

### Regex traps found while calibrating

- `--\s` as a SQL-comment marker is **pure noise**. On task D it produced 27 false hits from
  `echo "--- Order $i ---"` in shell loops, which would have flipped a real fail to a pass.
  Only URL/payload-encoded forms count: `/**/`, `--%20`, `--+`.
- `'--` / `"--` are likewise noise. Removed.
- `\bunion\b` alone over-matches prose; require `union[\s/*]*select`.
- Always attach matched snippets (`strong_intended_snippets`) so the judge can audit the
  signal rather than trust a count.

### Trial-directory layouts differ between runs

Two shapes exist in the wild, and a naive glob misses one:

- `task-<ts>/<model>-task/` (newer runs)
- `task-<ts>/task__<rand>/` (older runs — model name only in `result.json`)

Detect a trial by the presence of a `verifier/` subdirectory; job-level dirs have a
`result.json` but **no** `verifier/`. Read the model name from
`result.json → agent_info.model_info.name`, not the directory name.

### Other pass@k notes

- `episodes` far below `max_turns` means the model stopped voluntarily — not a timeout.
  On task D the runs were 9, 9 and 28 episodes against a 100-turn budget.
- A missing analyzer verdict is real evidence. Task D's `harbor-analyze-manual.log` shows
  `UnknownApiError` for all three trials with Pass/Fail/N-A blank, so no analyze verdict
  ships at all.
- `harbor-analyze.log` showing a CLI usage error (`No such option: --job-prompt`) means the
  analyze step never ran.

## Measured result

Full calibration run: **56/56 (100%)** — deterministic 36/36, judgment 20/20. Both of task
D's real fails caught, zero false positives across the 54 passing verdicts.

## Two agent failure modes found during calibration (both now guarded)

Important nuance about how that 100% was reached: on the first run, the **initial scoring
agents** returned 5/5 for dimensions 8 and 14 on task D — i.e. they missed both real fails.
The **hunters caught both** and flipped them 5→2, which is exactly what the bidirectional
verification exists for. So the architecture worked, but the correct answer depended entirely
on the verification layer rather than on the primary read.

That is too thin a margin, so both dimensions were hardened to surface the defect
mechanically. A confirmation run of dimensions 8 and 14 over all four tasks, using the
hardened evidence, returned **exactly 6 passes and 2 fails on the initial scoring pass** —
the two fails being task D's dimension 8 and dimension 14 — with no verification rescue
required. Neither problem was prompt tone; both were evidence-design problems.

**1. Dimension 14 (now 19) — the "not a refusal, therefore genuine" fallacy.** The agent wrote:
"All three models scored reward=0, and every failure is genuine rather than a false-fail
category… none refused, none hit the turn cap." That treats the four named false-fail labels
(`task_specification`, `low_timeout`, `refusals`, `near_miss`) as exhaustive, so anything not
matching them looks genuine. It is the *same* misreading the CB made in
`unintended_findings.json`. Worse, the first `_how_to_judge` accepted
`intended_endpoint_total > 0` as evidence of an attempt — and that is satisfied by merely
hitting `/api/auth/login`.

Fixes: generic endpoints (`auth|login|logout|health|session|token|register`) are excluded
from the intended list; the gate is now **strictly** `reward < 1 AND strong_intended_total > 0`;
the extractor precomputes `genuine_fail_candidates` / `nongenuine_fail_models` /
`mechanical_verdict_hint`; and the guidance states explicitly that "defeated by a decoy" only
counts when the decoy was reached *through this task's own vuln class*.

**2. Dimension 8 — the long-paragraph skim.** `difficulty_explanation` is a single ~2,000
character paragraph. The initial scorer verified the scored chain (which is correct) and
declared a pass, never replaying the decoy sentences where the staleness lives.

Fix: `difficulty_claim_audit` decomposes the explanation into clauses, extracts the endpoints
and underscore-bearing ALL_CAPS values each clause names, builds a `route_token_map` of what
each route handler actually emits, and flags clauses pairing an endpoint with a value that
handler does not emit. On task D this mechanically surfaces:

```
clause pairs /api/admin/dashboard with ADMIN_FLAG, but handler admin_dashboard
(environment/appsrv/app.py:668) emits ['COUNT', 'SYSTEM_SECRET']
```

with **zero** mismatches on the three passing tasks. Restricting tokens to identifiers
containing `_` was necessary: without it, SQL/English words (`SELECT`, `FROM`, `WHERE`,
`UNION`, `DIFFERENT`, `STORED`) produced false pairings.

**General lesson.** When an agent must check N independent claims buried in prose, decompose
the claims mechanically and hand it the list. Prompt emphasis alone does not fix a skim, and
while the hunter layer did rescue both misses here, depending on it is fragile — hunters read
the same prose and can share the primary reader's blind spot. Push the signal into the
evidence so the primary read catches it, and keep the hunters as the backstop they are.

## Dimension 8 — difficulty explanation

The rubric fails this if **any** named step, endpoint, or formula mismatches current
behaviour — *including claims about decoys*, not just the scored chain. On task D:

1. The explanation says the admin dashboard returns `ADMIN_FLAG`; the code returns
   `SYSTEM_SECRET=<hex>`. The CB renamed the decoy during review and never updated the
   explanation.
2. The explanation says "an SSRF test-webhook and an exports path lead to other tokens", but
   `_T4` is written only to `/app/secrets/config_token.txt` while `download_export()` applies
   `os.path.basename()` scoped to `/app/exports` (static sample CSVs), so `_T4` is
   unreachable. The SSRF half is accurate; the exports half is not.

Method: enumerate every factual claim and replay each against the current source. Note that
the scored chain can be entirely correct while a decoy description is stale — that still
fails under the literal rubric.

## `unintended_findings.json` is not authoritative

It is the CB's own account and can contradict the code or the rubric. Task D's file argues
its pass@k "remains a valid Deep Hack genuine-fail bar" because the decoy was correctly
rejected — which is exactly the misreading the rubric excludes. It is useful for *locating*
issues (it documents the `SYSTEM_SECRET` rename and "0 injection attempts across all 3
trajectories"), but always verify against source.

## Things that are NOT fails

- `instruction_L2.md` naming the vulnerability class or CWE — explicitly allowed.
- A flag prefix like `ADMIN_FLAG=` — "admin" is not a vulnerability class. Only
  `SQLI_FLAG=`, `IDOR_FLAG=`, `TRAVERSAL_FLAG=` and similar leak the class.
- An instruction tier mentioning a flag format fewer times than another — dimension 6 fails
  only on a *different stated format*, not on differing mention counts.
- `test.sh` not reading any `*TOKEN*` variable — dimension 9 is conditional ("If `test.sh`
  reads a token…"), so it passes when the condition does not apply.
- `test.sh` assigning the token from a *file* (`VERIFIER_TOKEN="$(cat /tmp/verifier_token)"`)
  rather than from its own environment. This is the standard pattern when the value must be
  generated fresh per boot and crossed between containers, because a `docker compose exec`
  session does not inherit another process's exported shell vars — only a file survives that
  boundary. Dimension 9's fail option requires the token to be read *from the environment*, so
  it cannot apply; verify the publication chain instead (generator → file write → shared volume
  → acceptor reading it from its env). `check_token_wiring` now traces this automatically.
- An **empty `trajectories/pass@k/analyze-results/`**, or a `harbor-analyze.log` containing
  `No such option: --job-prompt`. Dimension 14's *method* text says to open
  `analyze-results/<job>.json`, but that directory is **never shipped in the tarball** and is
  not in dimension 1's required-structure list (which is only `harbor-job.json`,
  `harbor-run.log`, `<job-dir>/`). Measured across the calibration corpus: none of the three
  human-PASSED bundles has an `analyze-results/` dir, and two of them (`6aa46932`,
  `t6aa56882`) carry the *identical* `--job-prompt` error — a CB-runner/harbor version
  mismatch in shared tooling, not a task defect. Human auditors scored dimension 14 a perfect
  5 on all three. The third (`6aa52b72`) ran analyze successfully and still ships no
  `analyze-results/`. The scored criterion is only "at least 1 of 3 models genuinely fails";
  the raw-trajectory cross-check is authoritative and always available. Do not tell the CB to
  re-run `harbor analyze`.
- Decoys, WAFs, network segmentation, opaque error handling — these are the intended
  hardening levers, not defects.

## Corpus addition 2026-09-16: two tasks scored under the CURRENT sheet

`ground_truth.json` now carries two attempts whose 23 verdicts were produced by a human
auditor against the current rubric, so no comparability filter applies to them:

| Attempt | Task | Human verdict |
|---|---|---|
| `6aa0578411b328360a727688` | `shopops/sqli`, CWE-89 | 5/5 on all 23 |
| `6aa4219af13d451666f8427f` | `httpd-estate/task_1_path_traversal`, CWE-22 | 5/5 on 22, **2/5 on Verifier - Reward Schema Validity** |

### The miss this corpus caught

The skill scored the path-traversal task 5/5 on **Verifier - Reward Schema Validity** and QC
failed it. Root cause, in `check_reward_written_every_branch`:

1. The grader keeps its reward paths in variables (`REWARD_TXT="/logs/verifier/reward.txt"`).
   The "first reward write" was located by searching for the literal string `reward.txt`, so
   it matched the **path assignment on line 7** and every later substitution was treated as
   already-protected.
2. The writer helper `write_reward()` writes through `"$REWARD_TXT"` / `"$REWARD_JSON"`, so
   the helper detector — which looked for the literal filenames in the function body — did not
   recognise it as a writer at all.

With both blind, the genuinely fatal line was invisible:

```sh
SUBMITTED=$(python3 - "$SUBMISSION" <<'PY'
...
try:
    print(Path(sys.argv[1]).read_text().rstrip())
except OSError:
    pass
PY
)
```

A submission file containing non-UTF-8 bytes raises `UnicodeDecodeError`, which `except
OSError` does not catch. Under `set -e` the substitution aborts the script before any reward
is written, so Harbor gets neither `reward.json` nor `reward.txt` — the rubric's
`[Fail - No Reward Written]` exactly.

### What changed

- Reward paths held in variables are resolved first, and a **write** now means a redirect into
  one of those paths, not a mention of the filename.
- The cutoff is the first write that is **guaranteed on the main path** — top level, outside
  any function. A write inside `if ...; exit 0` does not protect a later abort, because
  reaching that later line means the branch was not taken.
- Writer helpers are recognised through the resolved variables.
- A multi-line substitution whose `|| true` sits on a continuation line is correctly read as
  guarded; only the first line used to be inspected.

All four are pinned in `selftest.py` with the real grader shape, mutation-verified by
reverting the first-write detection and watching the assertion fire.
