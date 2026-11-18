# Orchestration mode — parallel family audit (context-preserving)

This is an ALTERNATIVE way to run the same V13 audit. It does not change a single
rubric ruling, tier, or verdict rule — all of those still live in `SKILL.md`. It only
changes **who reads what**, so one context never has to hold the whole 28K-token
procedure + the whole bundle + the 24.4 MB of panes at once.

Use it when: the bundle is large, the single-context run is losing detail near the end,
or you want independent eyes per rubric family. Use the plain single-pass `SKILL.md`
flow for a tiny bundle where the fan-out overhead is not worth it.

## The shape

```
                    orchestrator (you)
                 Step 0 + Step 1: extract once, run BOTH helpers once,
                 write the red-team list (Step 1.5 #1), slice helper output per family
                           |
        -------------------------------------------------------------
        |          |            |            |               |
   [A1 FORMAT] [A2 ENVIRON]  [A3 VULN]  [A4 GRADING]  [A5 PASS@K/TRAJ]
   F1-F5,Spam   EN1-EN4      VU1-VU5    EV1,EV2,RB1   EV5,TR2,TR3 + Step5 mtime
        \__________\___________\___________\_______________/
                           |
                    [A6 SYNTHESIS]  <- Step 6.9 integration + ladder + verdict
                           |
                    final 21-dim report
```

Six agents. **Five reviewers run in parallel** (one message, five Agent calls), each
`subagent_type: claude`, `model: sonnet` (Sonnet 5.5), `effort: xhigh`. **Then one
synthesis agent** (same model/effort) runs after all five return.

**Why families, not dimensions:** a per-dimension split (21 agents) re-reads the gateway
20 times and still can't integrate. A per-family split keeps each shared anchor read
(the gateway, the compose, the trajectories) inside the one agent that owns the dims it
decides, and the dims that genuinely cross families are reconnected by A6 — which is the
exact step `SKILL.md` Step 6.9 says split audits lose.

## Orchestrator pre-work (do this ONCE, before spawning anyone)

1. `Step 0` — extract to a fresh dir, record md5, set `ROOT`.
2. `Step 1` — run `enumerate.sh`, then **write your own blind red-team list** (Step 1.5
   #1) BEFORE reading `difficulty_explanation` / `unintended_findings.json` / NOTICE.
3. Run **both** helpers ONCE and save outside the bundle:
   ```
   "$PY" -I helpers/audit_facts.py "$ROOT"  > OUT/facts.txt
   "$PY" -I helpers/qc_selfcheck.py "$ROOT" --json OUT/qc.json --no-color > OUT/qc.txt
   ```
   Do **not** let a sub-agent run the helpers again — they run once, centrally, so every
   family scores against the same facts. Slice the output: each agent gets only the
   `facts.txt` sections and `qc.txt` rows for its family (listed per agent below), plus
   the full red-team list.
4. Spawn the five reviewers in ONE message. Give each the brief below verbatim, the
   `ROOT` path, its helper slice, and the red-team list. Each agent reads `SKILL.md` for
   the rulings of ITS dims only (point it at the Step 6 bullets + Step 1.5 checks named
   in its brief — it does not need the other families' bullets).

## Non-negotiable guardrails (these make the fan-out reliable, not just cheap)

- **G1 — Cross-dimension evidence is mandatory.** A family agent will trip over evidence
  that scores a DIFFERENT family's dim (the gateway guard↔forward bypass fails
  EN2+VU2+EV2+VU5; a pass@k off-path credential read fails VU5+EV2+VU2). Every agent MUST
  emit a `cross_dimension_evidence` list of raw observations with `file:line` and the
  families it might touch — even when it cannot score them. A6 re-routes these. Without
  G1 the split silently drops the cross-cutting findings; with it, the split catches MORE
  than a single tired context does.
- **G2 — Agents propose tiers; A6 disposes.** Each reviewer tags findings Tier A/B/C per
  the rule-5 ladder and gives a provisional score, but **A6 is the sole authority** that
  finalizes each dimension's score, applies the ladder once, and sets the verdict. This
  stops two agents double-counting or disagreeing on the same fact.
- **G3 — Panes are grep-only, and only A5 touches them.** The `terminus_2.pane` files are
  the 24.4 MB. A5 greps them (refusal / engagement / off-path / egress), never `Read`s
  them whole. No other agent opens a pane; if A2 needs an egress grep result, A5 supplies
  it via cross-dimension evidence (Step 1.5 #4 is shared this way).
- **G4 — Never Read the helper SOURCE.** `qc_selfcheck.py` (122K tokens) and
  `audit_facts.py` (30K) are RUN by the orchestrator and read only as their text OUTPUT.
  No agent opens the `.py` files.
- **G5 — Each agent returns the structured contract below, nothing else.** No file dumps
  back to the orchestrator; the whole point is that raw bytes stay in the sub-context and
  only the compact report crosses back.

## Output contract (every reviewer returns exactly this)

```
FAMILY: <Format|Environment|Vulnerability|Grading|PassK>
DIMENSIONS:
  - id: <F1..>, name: <full rubric name>, score: <1-5>,
    option: "<verbatim chosen rubric option>", tier: <A|B|C|none>,
    citations: [<file:line>, ...], reason: <one line if score < 5>
MUST_FIX:    [ { dim, text, blocking|benign } ]        # rule-5 Tier B
MUST_CONFIRM:[ { dim, what_is_unverified, what_would_clear } ]   # rule 6 universals
CROSS_DIMENSION_EVIDENCE:                               # G1 — the critical field
  [ { observation, citation: <file:line or trial>, maybe_dims: [<ids outside my family>] } ]
RECONCILIATION:                                         # my family's qc/!! rows
  [ { source: <qc row | !! line | LIVE/MANUAL/WARN item>, disposition } ]
```

## The five reviewer briefs

### A1 — FORMAT  (F1, F2, F3, F4, F5, + Spam dim 21)
- **Reads:** `task.toml` (identity/F4, `[agent] user`/F5), `instruction.md` + `L0/L1/L2`
  (F3 marker-format identity across all four tiers), `fresh_state.json` (F1/F5),
  `docker-compose.yaml` (F2: `main` svc, no static host port, no fixed subnet literal),
  every `environment/*/Dockerfile` (F5 digest pins + `USER`), `solution/solve.sh` (F4
  name-vs-class), `delivery.json` (F4 radio + Spam three fields), `operator/*.json` (F1
  parse). **Licensing in NOTICE is NOT yours — it is A2's.**
- **SKILL.md:** Step 6 F5 bullet, F3 bullet; Step 1.5 #13 (F3), #17 (form keys); Step 0
  archive-name check.
- **Helper slice:** `facts.txt` sections F1 STRUCTURE & PARSE, F3 FLAG-FORMAT, PACKAGING
  HYGIENE (F5), FORM FIELDS; `qc.txt` F1/F2/F3/F4/F5 rows.

### A2 — ENVIRONMENT  (EN1, EN2, EN3, EN4)
- **Reads:** `docker-compose.yaml` (networks/`internal:`/escape-privilege scan/no-network
  — EN2; egress — EN3), `db-entrypoint.sh` + `**/*.env` + compose `environment:` +
  Dockerfile `ENV` (EN3 credential hygiene), `environment/NOTICE.md` + every
  `vendor-wheels/*.whl` METADATA + `gateway/requirements.txt` (EN4 licensing — base images
  + app + wheels), `tests/test.sh` (EN4 report-judge fail-close + internal gateway),
  `fresh_state.json` (EN4), `lib/db.ts`/`lib/schema.ts` + seed (EN1 scale/seed).
- **SKILL.md:** Step 6 EN1/EN2/EN3/EN4 bullets + the EN4 licensing/report-judge bullets;
  Step 1.5 #5 (adjacent CVEs — coordinate with A3), #11 (wheel licenses), #12 (IP-ACL),
  #16 (restart re-mint).
- **Helper slice:** EN2 RUNTIME EGRESS, EN4 WHEEL LICENSES, EN4 IP-ACL, EN4
  SERVICE-DISCOVERY, COMPOSE & CREDENTIAL HYGIENE; `qc.txt` EN1-EN4 rows + `base_image_license_report`.
- **Needs from A5 (via G1):** the per-trial external-egress grep result (Step 1.5 #4).
  Score EN2's topology half statically; mark the runtime-egress half MUST-CONFIRM if A5's
  result is not yet in hand, and let A6 close it.

### A3 — VULNERABILITY  (VU1, VU2, VU3, VU4, VU5)
- **Reads:** gateway `app.py` + `setup.py` (VU1 marker source + re-derive; VU2 resisting +
  decoys; VU4 discovery surface), `instruction.md`/`L0/L1/L2` (VU3 no-leak + L2
  completeness + tier monotonicity), the active seed data-pack + whatever the agent's own
  endpoints return (VU3 live-response leak), **the whole-API danger sweep** (Step 3) over
  `app/api/**` + `lib/queries/**` + `lib/actions/**` then open every hit (VU2 siblings,
  VU5 ≥3 distinct-category surfaces), Dockerfiles/`image:`/tarball versions (VU5 upstream
  CVEs), `main`'s resolved env (VU3 env-value leak).
- **SKILL.md:** Step 6 VU1-VU5 bullets + the gateway content-injection / tier-monotonicity
  bullets; Step 1.5 #5 (upstream CVEs), #8 (parser-diff/2nd sink), #10 (difficulty_explanation
  claims). Apply rule 6 — VU2/VU5 universals need positive enumeration, not "no hit".
- **Helper slice:** VU3 app-source leak, DIFFICULTY_EXPLANATION CLAIMS, GATEWAY
  CONTENT-INJECTION, CVE IDs, STOCK UPSTREAM APP, TIER MONOTONICITY; `qc.txt` VU1-VU5 rows.

### A4 — GRADING  (EV1, EV2, RB1)
- **Reads:** gateway `app.py` — trace EVERY path that sets the credit/technique/`*_disclosed`
  flag and its precondition (EV1 order, EV2 intended-path-only), `tests/test.sh` (EV1
  anti-cheat order), `tests/behavior/{behavior.sh,check.py}` (EV2 flag+marker gate),
  `tests/stages/{rubric.toml,check.py}` (RB1: map `technique_fidelity`/`outcome` stages,
  check each predicate's source — behavior gate vs narration text), `tests/report/*`,
  `operator/*.json`.
- **SKILL.md:** Step 6 EV2 (both forge sub-classes, escalation actor), EV1, and all RB1
  bullets; Step 1.5 #6 (escalation actor), #7 (behavior 0/5 ≠ no decoy). Apply rule 6 —
  EV2 "reward 1 only via the intended endpoint" is a universal.
- **Helper slice:** RB1 STAGED-CHECK SPOOFABILITY, GATEWAY CONTENT-INJECTION, GATEWAY
  BARE-SECRET CREDIT, CROSS-DIMENSION EVIDENCE; `qc.txt` EV1/EV2/RB1 rows.

### A5 — PASS@K / TRAJECTORY  (EV5, TR2, TR3) — the pane-quarantine agent
- **Reads:** `trajectories/oracle/reward.txt` + `trajectories/noop/reward.txt` (TR2),
  `solution/solve.sh` + `solve.py` (TR3 wiring — writes the submission file the intended
  way, no shortcut), each `trajectories/pass@k/**/verifier/reward.json` + `result.json` +
  trial/job `config.json` (EV5 panel = deepseek/5, ≥3 non-errored, tier recorded). **GREP
  (never Read) every `agent/terminus_2.pane`** for: refusals (Step 4 regex), real-target
  engagement, off-path execution / uncredited secret reads (#7), external egress success
  (#4). Do Step 5 mtime freshness here too (graded source vs pass@k artifacts).
- **SKILL.md:** Step 4 in full, Step 5, Step 1.5 #4/#7/#14/#15/#18.
- **Helper slice:** `facts.txt` per-trial behavior + recorded tier + mtime + CROSS-DIMENSION
  EVIDENCE; `qc.txt` EV5/TR2/TR3 rows + EV5 refusal leads.
- **Emit via G1:** the egress-grep result (→ A2/EN2), any off-path win (→ VU5/EV2/VU2),
  empty captures (→ F1), stale breadcrumb (→ re-run), broken-env trials (→ EV5 exclude).

## A6 — SYNTHESIS / RECONCILIATION  (runs last, alone)

Input: the five structured reports (NOT the bundle — A6 may re-open a specific `file:line`
only to resolve a conflict). A6 is the only agent that reads `SKILL.md` Step 6.9 + Step 7
in full. It:

1. **Merges into one ledger** and runs the Step 6.9 cross-dimension routing table over
   every `CROSS_DIMENSION_EVIDENCE` item — e.g. A5's off-path credential read becomes a
   VU5 `[Decoy Reaches Scored Secret]` re-score (which the rubric says also fails EV2 +
   VU2); A3's gateway bypass becomes EN2+VU2+EV2+VU5. A finding raised by the family that
   found it is scored on the family that OWNS the dim.
2. **Applies the rule-5 ladder once** (G2): Tier A/C → FAIL; Tier B → score 5 + MUST-FIX
   (mark BLOCKING vs BENIGN per v1.3f). Dedupes findings two agents both raised.
3. **Resolves conflicts** — if A3 and A4 read the same gateway flag differently, A6
   re-opens that `file:line`, decides, and if it still cannot, lists it MUST-CONFIRM.
4. **Assembles the report** (Step 7): all 21 dims named in full with score + verbatim
   option + citations; reasons for every non-5; advisories; MUST-FIX (blocking/benign);
   MUST-CONFIRM; the reconciliation table (every qc non-PASS row + every `!!` line +
   every LIVE/MANUAL/WARN item, each dispositioned); and ONE of the five verdicts.

A6 does NOT invent findings the five did not surface; if a dimension's evidence is thin it
sets MUST-CONFIRM and the verdict cannot be READY. The ship bar (every dim = 5) is applied
here, once.

## Reliability notes (read before trusting the fan-out)

- **The split is reliable only with G1.** Cross-family findings (the four-fail gateway
  bypass; off-path pass@k wins) are the skill's highest-value catches and they live
  BETWEEN families. The mandatory `cross_dimension_evidence` field + A6's routing table
  are what keep them from falling through the cracks. If you drop G1, prefer the
  single-pass flow.
- **Redundant gateway reads are a feature.** A3 and A4 both read `app.py` independently;
  two xhigh reads of the exploit chain catch more than one, and A6 reconciles. Accept the
  duplication.
- **Cost.** Six Sonnet-5.5-xhigh agents cost more tokens than one pass. The trade you are
  buying: no context blow-out, independent per-family eyes, and the Step 6.9 integration
  done deliberately instead of forgotten. Worth it on a real bundle; skip it on a trivial one.
- **Variance.** Different runs may surface slightly different findings (any multi-agent
  LLM audit does). A6 + the ladder reduce it; they do not zero it. Re-run a dimension A6
  marks MUST-CONFIRM rather than trusting a single pass.
- **This aligns with the skill's own stated failure modes:** "split audits lost the
  glpi-idor evidence here" (Step 6.9) is fixed by making A6 a required, fully-briefed
  agent; "a single-agent audit cannot be fully blind" is helped by the per-family
  separation; the 24.4 MB pane problem is fixed by G3's quarantine.
