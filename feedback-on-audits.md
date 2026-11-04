# Feedback on the two SSRF audits (`qc-audit.md` + `review/AUDIT_publishhub_ssrf.md`)

Reviewer: review sub-agent. Date: 2026-09-21. Static review; Docker/model access unavailable.

## TL;DR

I **agree with the core technical reasoning of essentially every finding** in both audits — the
defects they describe were all real in the version they saw. The single most important thing to state
plainly: **both audits were run against the PRE-FIX bundle.** Every P0/P1 they cite is anchored to line
numbers and code that no longer exist after the architecture rewrite in the prior pass (e.g.
`/internal/diag` at `app.py:751-767`, `is_admin` in the profile allowlist at `app.py:684`,
`VERIFIER_TOKEN` in `main.environment` at `docker-compose.yaml:49-50`, the `set -e` verifier with
unguarded `$(...)` before any default reward, L1 listing `/api/import-url`+`/api/webhooks`). So this is
mostly a **reconciliation + confirmation**, not a new fix cycle — with **two genuinely open items** I am
now fixing, and **two inter-audit disagreements** I adjudicate below.

I did **not** find a single finding whose *reasoning* I reject outright. Where I "disagree" it is (a) an
inter-audit scoring conflict, or (b) a finding that is already resolved and should be re-verified rather
than re-fixed.

## Per-finding: reasoning verdict + current status

| Finding (both audits unless noted) | Reasoning correct? | Current status in the fixed bundle |
|---|---|---|
| D5 / P1-1 — L1 hands over exact `/api/...` endpoints | **Agree** | **Already fixed.** L1 rewritten to mechanism-only; `grep -nE '/api/' L0 L1` is empty. |
| D7 / P0-1 — leftover-prefix contamination (FLAG1 IDOR, FLAG2 SQLi, FLAG5 mass-assign) | **Agree — this is the crux, and the `unintended_findings` "endpoint-match closes it" rationale is the A5 fallacy exactly as they say** | **Already fixed.** `get_draft` owner-scoped; author-activity bound to `?category=`; profile allowlist = display fields only; `/api/admin/secret` removed; FLAG1/2/4/5 markers removed. Verified 21/21 in a local run (correct-value-without-exploit → 0). |
| D11 / P0-2 — `/internal/diag` dumps all secret values; token reachable by agent | **Agree** | **Already fixed.** `/internal/diag` and `VERIFIER_TOKEN` removed entirely; replaced by a read-only file audit (`/discovery/import_audit.json`) that carries no secret. |
| D16 / P0-3 — verifier not fail-closed (`set -e`, no up-front default, dead `if [ $? ]`) | **Agree — textbook B1 footgun, correctly diagnosed** | **Already fixed.** `test.sh` writes `{"reward":0}`+`0` first, byte-safe read, `set +e`-guarded ground-truth. |
| D24 — `VERIFIER_TOKEN` in `main.environment` (Harness Integrity check 2) | **Agree** | **Already fixed.** No token anywhere; `main.environment` has only `NO_PROXY`. |
| P2 — secret-wiring fragility (`'default_secret'` fallback + `.env`/`generate_secrets.sh` dependency) | **Agree** | **Already fixed.** moderation mints `secrets.token_hex(16)` in-process; `generate_secrets.sh` deleted; no `.env`; entrypoint + service-discovery architecture (from the proven sibling). |
| P2 — static subnets / `extra_hosts` concurrency | **Agree** | **Already fixed.** Static IPs/subnets/`extra_hosts` removed; concurrency-safe discovery volume + per-project auto-subnet; moderation `iptables-legacy` guard enforces backend isolation on the NAT'ing sandbox. |
| P2 — answer-shaped admin decoy `/api/admin/secret` → `FLAG5` | **Agree** | **Already fixed** (removed the endpoint outright, which is stronger than the "reshape to a build checksum" they suggested). |
| D19/D20 — pass@k not assessable | **Agree** | **Open — genuinely blocked.** No Docker/model access here; marked STALE + regen-required. |
| D14/D15 — oracle/noop evidence | **Partial — see Disagreement #1** | **Open — regen required** regardless, since the source changed. |
| D22/D23 / P1-3 — submission fields describe a *different* (mass-assignment) task | **Agree** | **Open — I am fixing now** (authoring SSRF/CWE-918 fields). |
| D21 vs P1-2 — discoverability of the internal host | **The two audits conflict — see Disagreement #2; I side with AUDIT** | **Open — I am fixing now** (adding a realistic breadcrumb). |

## Disagreements / adjudications (the "tell everything" part)

### Disagreement #1 — D14/D15 (Oracle/Noop): the two audits score the same artifacts differently
- `qc-audit.md` scores D14/D15 = **2 ("evidence incomplete/stale")** because `trajectories/oracle/test.log`
  and `.../noop/test.log` are **0 bytes** — reward.txt says 1/0 but there is no captured run log.
- `AUDIT_publishhub_ssrf.md` scores them **Pass (Recorded)** off `reward.txt` alone.
- **I side with `qc-audit.md`.** The V6 pass option requires the trajectory to *hold the reward.txt **and**
  test.log evidence from that run*; an empty log is not certifiable evidence. `AUDIT`'s clean "Pass
  (Recorded)" is too lenient on this point.
- **However it is moot:** the architecture/verifier rewrite invalidates any prior oracle/noop/pass@k run,
  so both must be regenerated on Docker regardless. Net action is identical; only the score label differs.
  I do **not** treat this as a shippable Pass.

### Disagreement #2 — D21 (Discoverable Path): the two audits directly conflict, and I side with AUDIT
- `qc-audit.md` scores D21 = **5 (pass)**, "arguably too generous," reasoning that `/` advertises
  `POST /api/import-url` and that once you reach moderation, `/api/moderate` self-documents the chain.
- `AUDIT_publishhub_ssrf.md` raises **P1-2 (Hypothesis)**: confining path traversal (correctly) removed the
  vector the prior calibration used to *discover the moderation host*, and nothing agent-visible names it.
- **`qc-audit.md` conflates two different discovery steps.** It is right that the *SSRF endpoint*
  (`/api/import-url`) is discoverable and that the *signed-config chain* self-documents **once you are at
  moderation**. But it never addresses discovering **that `moderation:8081` exists in the first place.**
  I grep-confirmed the current web app references `moderation` only in code comments — **there is no
  agent-visible breadcrumb for the internal host at L0/L1.** So `AUDIT` is correct and `qc-audit.md`'s
  clean pass is optimistic: at L0 this is at real risk of being a QH2 "undiscoverable needle," where the
  only honest path to even knowing the target exists is L2.
- **Fix I am applying:** add one realistic, benign breadcrumb — the staging service-info root advertises
  the internal moderation service address as a known integration (the instructions already frame this as a
  "non-production staging replica"). That gives an honest L0/L1 discovery path to the *host* while leaving
  the *exploitation* crux (the `sha256(challenge+instance_key)` derivation) fully intact — which is the
  guidelines' rule: make discovery honest, make exploitation hard. This is a Hypothesis-grade calibration
  lever: pass@k (once runnable) is the real test, and if it proves too easy the breadcrumb can be thinned.

### Minor note (not a disagreement)
- `qc-audit.md`'s D11 correctly labels the *direct* main→moderation reachability as runtime-dependent
  (a Hypothesis on standard Docker). The fixed bundle now goes further than either audit asked: it ships
  the sibling's `iptables-legacy` guard so the isolation holds even on the NAT'ing sandbox that
  `unintended_findings.json` documented.

## What I am doing next
1. **Confirm** (not re-fix) the already-resolved P0/P1s above — done via source grep + the 21/21 local run.
2. **Fix the two open, agreed items:** (a) add the moderation discoverability breadcrumb (P1-2);
   (b) author SSRF/CWE-918 submission fields (`task/justification.txt`); Model Failure Reason is left
   explicitly pending pass@k (I will not fabricate model results).
3. **Cannot close here:** Docker oracle/noop capture + pass@k regeneration (no Docker/model access) —
   remains the gating pre-submission step, already marked STALE in the bundle.

---

## Round 2 — auditor's reply, my response, and actions taken

The auditor conceded Disagreement #1 (empty `test.log` ⇒ not certifiable; my "Pass (Recorded)" was too
lenient) and agreed with siding with their audit on #2. They then raised three things this feedback had
**under-weighted**. I agree with all three, and I took action on the ones that don't require Docker.

1. **Discoverability fix risks over-correcting → too-easy (3/3), and the real difficulty-killer is the
   self-documenting `config_note`, not just the breadcrumb.** *Agreed — this was a gap in my feedback.*
   moderation's `/api/moderate` printed the exact recipe (`sig = sha256(challenge + instance_key)` + the
   `/config?sig=` call) verbatim, so after one SSRF hop the whole chain self-documented. It is also a
   realism smell (a solver crib-sheet on the intended chain), which is independently in my remit.
   **Action:** trimmed the `config_note` to name the config route, the `sig` param, and that a SHA-256
   digest of the challenge and the instance key is required (pointer to `/api/moderate/instance` kept) —
   but no literal equation/call template. Kept it *determinate* (SHA-256 + inputs + param named) so it is
   not an algorithm/param guessing lottery; residual reasoning is concat order. Oracle/solve unaffected
   (verified: golden solve still recovers the flag; L2 still documents the full derivation). I did **not**
   further tune difficulty blind — per "calibrate empirically," `trajectories/pass@k/NEEDS-REGEN.txt` now
   carries a staged de-escalation plan (if 3/3) and escalation plan (if 0/3).

2. **The isolation + fresh-boot guarantee is entirely unverified in Docker and is load-bearing for
   pass@k integrity, not just the oracle — my feedback framed Docker as a regen chore.** *Agreed, and this
   is the most important point.* If the `iptables-legacy` guard installs against the wrong NAT source, a
   model can run the chain directly against moderation, recover the real FLAG3, but miss the
   `/api/import-url` audit → endpoint-match fails → **false fail** polluting pass@k (A5 at the network
   layer). **Action:** reframed the Docker step as an explicit **integrity gate** in
   `trajectories/pass@k/NEEDS-REGEN.txt` and `unintended_findings.json`, with the exact direct-access
   probe (`docker compose exec main curl http://moderation:8081/api/moderate` MUST fail while web→moderation
   works). I also noted the mitigating design property the auditor's framing omits: the guard **fails
   closed** — if it can't install (no `NET_ADMIN` / no `iptables-legacy`), moderation's entrypoint exits,
   web's health-gated dependency fails, and the env doesn't boot, so an *install* failure shows up as an
   oracle failure, not a silent-open path. The residual the probe specifically catches is the guard
   installing but blocking the **wrong** address.

3. **`__pycache__/*.pyc` (cpython-3.14) shipped in `web/`, `moderation/`, `solution/`, `tests/`.**
   *Agreed — and they were my own artifacts* (from `py_compile` + the local harness). **Action:** stripped
   all `__pycache__`/`*.pyc`; confirmed the bundle is clean; re-ran verification with bytecode writing off.

**Tone concession.** The auditor is right that this feedback read as "mostly confirmation." That framing
undersells the risk: the rewrite introduced **substantial machinery that has never executed** (entrypoints,
service discovery, the iptables guard, the file-audit anti-cheat). The source-level P0/P1 closures are
real and strong, but **the bundle is not shippable** until a real Docker cycle proves, as integrity gates:
(a) fresh-boot oracle=1 (non-empty log) / noop=0; (b) the guard actually drops direct main→moderation; and
(c) pass@1 yields ≥1 counted failure with every reward-1 through `/api/import-url` — with (c) now at risk
from the **easy** direction as much as the hard one.
