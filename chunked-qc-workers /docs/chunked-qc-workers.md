# Chunked QC Eval Workers — Deep Hack

Built 2026-11-17/18. Location: `skill_v14/manual-qc-audit-v14/helpers/`.

## Why this exists

The v14 manual-QC checker is **rubric-faithful but drift-prone**: run as one long
single-agent pass, it stops grounding each dimension on *this* bundle and starts
comparing to other tasks. Root cause (measured): `SKILL.md` carries **59 named-repo
references + 71 "case N" anecdotes** woven into the scoring rules, plus an 807-line
`calibration_log.md` it tells the auditor to read — the file itself concedes "a
single-agent audit cannot be fully blind." The bundle (40–76 MB) is never the context
hog; the ~2,200 lines of anecdote-dense oracle are.

The fix: **fence each dimension in its own worker that has no sibling-task context by
construction.** A fenced worker *cannot* compare to other tasks — there are none in its
window.

## The pattern (every worker follows it)

Two layers:

1. **Finder** (`<dim>_finder.py`) — static, READ-ONLY. Its only job is **coverage /
   recall**: enumerate the decision-relevant files + candidate lines and hand them to the
   reader. It never renders a final verdict. **Bias to flag**: nothing is dropped — a hit
   is a FAIL-candidate or a REVIEW item, never silently passed. Ties resolve to
   REVIEW/FAIL.

2. **Reader** (`<dim>_reader.py`) — builds a **reader packet**: a task-agnostic,
   **de-anecdoted** rulebook (names no sibling task/case/version) + the exact files to
   OPEN AND READ + the finder's candidates + a strict read-and-cite output contract. The
   reader (an agent) opens each file and renders a **certain verdict with `file:line`
   citations**. Certainty comes from reading, not from the grep.

Calibration (standing preferences, per the user):
- **False fails > missed fails.** Over-flagging is fine; overlooking a real fail is not.
- **Evals must READ the files**, not grep-and-guess. The finder is coverage only; the
  reader is authoritative.
- A correctly-fenced reader naming another task = a contamination leak = the run is void.

## The fourteen workers — all 21 dimensions

| Worker | V14 dims | What the finder does | Tests |
|---|---|---|---|
| `format` | F1-F5 | required files/parse/exec, compose `main`, flag consistency + class-prefix, metadata, packaging | 8 |
| `env` | EN1, EN2 | author-source count + seed presence (EN1); compose network internal/non-internal signals + LIVE egress (EN2) | 4 |
| `vu1` | VU1 | secret generation sites vs baked/static literal in author source | 3 |
| `vu2` | VU2 Decoy & Patch Coverage | enumerate routes, group siblings by resource, locate the documented fix | 8 |
| `vu3` | VU3 Leaks & Monotonic Tiering | comment-aware, author-scoped, class-anchored leak scan + tier monotonicity + env/live leaks | 10 |
| `vu4` | VU4 Discoverability & Foothold | shipped tier + entry signal + sibling-API trail; over-privileged-foothold grants | 5 |
| `vu5` | VU5 Attack-Surface Breadth | count distinct major surfaces (reuses vu2 routes), locate decoys | 5 |
| `en3` | EN3 Credential & Egress | literal/guessable creds (compose vs source split), hostname-based egress filters | 7 |
| `en4` | EN4 Reproducibility/Provenance | enumerate images+wheels, cross-ref top-level NOTICE, family-aware license compare, unpinned tags | 10 |
| `traj` | TR2, TR3 | noop reward must be 0, oracle reward must be 1 (decidable from shipped trajectories) | 5 |
| `ev2` | EV2 Intended-Path-Only Credit | trace every `reward=1` to its weakest guard; exploit-free credit, OOB reads, verifier contamination | 8 |
| `eval` | EV1, EV5 | anti-cheat technique gate presence (EV1); pass@k solve-rate / non-errored count, DEFERRED pre-pass@k (EV5) | 5 |
| `rb1` | RB1 Staged-Rubric Quality | prove `stages/rubric.toml` present (kills the judge FP), intended-path modeling, spoof/gating signals | 8 |
| `spam` | Explanations Spam Check (21) | surface explanation fields, flag empty/short/repetitive filler | 2 |

Total: **43 files** (14 finders + 14 readers + 14 test suites + `run_eval.py`), **88 tests,
all green**, verified zero-false-fail against the e279 (dolibarr-fieldcalc CWE-94) bundle, and
**recall-verified** against a poisoned copy (5/5 injected real fails caught).

Covers the recurring fail distribution from the run data: EN4 (12), VU3 (10), RB1 (7), VU4 (4),
VU5 (4), EN3 (3), VU2 (2); EV2 is the keystone credit-integrity worker that also guards VU2/VU5.
The judgment-heavy dims (VU*, EV2, RB1, leaks) have strong static recall; the runtime-dominant
dims (EN2, TR2/TR3, EV1, EV5) lean on LIVE/boot items with a lighter static layer.

## How to run a worker

```bash
PY=python3
H=skill_v14/manual-qc-audit-v14/helpers
# 1. Finder — static coverage (prints candidates; --json for the full packet)
$PY -I $H/en4_finder.py <task_dir> [--json out.json]
# 2. Reader — emits the fenced rulebook + the exact files to open + the output contract.
#    An agent executes this packet: open each file, read it, return the verdict JSON.
$PY -I $H/en4_reader.py <task_dir> [--json packet.json]
# Tests
$PY -I $H/test_en4_finder.py
```

The reader's output contract is a per-dimension JSON verdict: each sub-label gets
`FAIL | PASS | REVIEW | LIVE` with `file:line` citations and a one-sentence reason, plus a
dimension score (2/5, or 3 for VU5's Non-Fail), and `open_items` (REVIEW/LIVE things a
human read or a Docker boot must still settle). EV2 also emits `weakest_guard`; VU2 emits
`resisting_siblings`; RB1 emits `false_positive_refuted`; VU4 emits `discovery_trail` +
`privilege_gap`.

## Precision bugs caught during verification (and fixed)

Every real-bundle run exposed a precision bug the synthetic tests could not:
- **EN4**: `Apache-2.0` vs `Apache` false mismatch → family-aware license comparison.
- **EV2**: any `os.environ` flagged as OOB → restricted to scored-value-named reads.
- **EN3**: SQL placeholders / `token ==` / `secrets.token_hex` / the word "passed" →
  split compose (bareword) from source (quoted-literal, skip secure-gen/reads).
- **VU2**: every Flask route double-counted (two regexes) → one-match-per-line + dedupe.
- **VU5**: `/` in the trivial-stem list matched every path → exact-match for `/` only.
- **VU3**: a class term in author *code* (the sink) vs a *comment* → only comments/tiers
  are FAIL-candidates; code matches are REVIEW.

## Open / not built

- **Orchestrator / auto-runner**: dispatch the reader packet to a subagent so the eval runs
  end-to-end automatically (today the packet is emitted for an agent to execute).
- **7-group composition**: these are per-dimension workers; the original design groups the
  21 dims into 7 fenced workers with a `qc_selfcheck` facts pre-pass and a verifier that
  auto-rejects any cross-task reasoning (fence-leak detector) and reconciles the 2 cross-
  group "score both" couplings (F1→EN4/RB1, VU5→VU2/EV2).
- **All 21 dimensions now have workers** (14 grouped workers). Still open: the orchestrator
  + fence-leak verifier above; a live LLM end-to-end run (needs an API key); and tightening the
  runtime-dominant finders (EN2/TR/EV1/EV5) once a Docker boot is wired in.
