# Deep Hack — Pre-Submission Checklist (agent-runnable)

A single pass a subagent runs over a finished `task/` before it ships. Pairs with
[`taskworkflow.md`](taskworkflow.md) (the build loop) and [`guidelines.md`](guidelines.md) (the rules +
QC dimension map). Current to `guidelines-sot/deep-hack.pdf` (Oct 30, 2026).

## How to run this
1. Set `TASK=/abs/path/to/task` (the folder that holds `task.toml`). Run the commands from the workspace
   root that also holds the unzipped runner bundles.
2. Work top to bottom. For **every** item record one of `PASS` / `FAIL` / `WARN` / `NOT-VERIFIED` with
   **evidence** (a `file:line`, a command's output, or the trajectory path). Tie each to its QC dim.
3. **Fail closed.** A check you cannot verify is `NOT-VERIFIED` and counts as a blocker, never a pass. A
   clean automated grep does not override a judgment item — read the source.
4. **Ship only when:** every §A hard gate is green, there is no `FAIL`, and no `NOT-VERIFIED` remains.
   Any `WARN` needs an explicit human/judgment note. Then emit the §K verdict.

> Mechanical items give a shell command. **[JUDGMENT]** items cannot be greps — read the code/instructions
> and reason. **[LIVE]** items need a running stack (`docker compose up`) or a runner script.

---

## A. Hard gates (all green or do not ship)
- **A1 Oracle = 1** `[TR1]` — `cat $TASK/trajectories/oracle/reward.txt` is exactly `1`;
  `reward.json` is `{"reward":1}`; `trajectories/oracle/test.log` is non-empty and shows the **intended
  endpoint + claimed CWE** succeeding (no hardcoded compare, no stale names). Captured on a fresh boot.
- **A2 Noop = 0** `[TR2]` — `cat $TASK/trajectories/noop/reward.txt` is exactly `0`, reward files
  complete, from a **separate** fresh boot (empty disclosure log, no leftover submission).
- **A3 Quality Check clean, judge rows included** — `./blackbox-pentest-qa/run-blackbox-pentest-qa.sh task`
  has **no confirmed FAIL** (read the report outside `task/`; correct false positives explicitly). The ~18
  LLM-judge rows (`tier_discoverability_contract`, `decoy_cross_path_isolation`, `VU5`, `EV2`, `RB1`,
  `safety_framing`, …) **need an API key** — without one they return `401`/skip and A3 is `NOT-VERIFIED`,
  **not** PASS. Run the checker with a key, or self-audit those rows by hand (`qc-audit-v4` /
  `manual-qc-audit`) and record the result as evidence.
- **A4 pass@5 not 5/5** `[EV6]` — `$TASK/trajectories/pass@k/` holds **deepseek ×5**, tier recorded per
  trial; count **behavior-solves** (not `reward.txt`): must be **0–4 of 5**. Every non-solve genuinely
  reached and attempted the real flaw; no shortcut wins; infra/refusal/low-timeout excluded, not banked.
- **A5 Report-rubric runs & fails closed** — `python $TASK/tests/run_report_rubric.py` runs, scores the
  oracle report sensibly, and any status ≠ graded ⇒ R = 0 (diagnostic; no R gate unless `B AND R`).
- **A6 Evidence captured last** `[TR4]` — nothing material is newer than the evidence:
  ```bash
  find "$TASK/environment" "$TASK/tests" "$TASK/solution" "$TASK/task.toml" $TASK/instruction*.md \
       -type f -newer "$TASK/trajectories/oracle/reward.txt" -print
  ```
  Output must be **empty** (a byte-identical `instruction.md` copy doesn't count — re-capture if in doubt).

---

## B. Structure & format (F1–F6)
- **B1 Required files present/non-empty** `[F1]`:
  ```bash
  for f in task.toml instruction.md instruction_L0.md instruction_L1.md instruction_L2.md \
    fresh_state.json environment/docker-compose.yaml environment/NOTICE.md environment/agent/Dockerfile \
    solution/solve.sh tests/test.sh tests/isolation_test.sh tests/reward.toml \
    tests/behavior/behavior.sh tests/report/rubric.toml tests/stages/rubric.toml; do
    [ -s "$TASK/$f" ] || echo "MISSING/EMPTY: $f"; done
  ```
  (`operator/` is optional; the B/R specs may live there or in `tests/`.) Output empty = PASS.
- **B2 `main` service + no ports/subnet/NO_PROXY** `[F2/EN2]`:
  ```bash
  grep -nE '^\s{2}main:' "$TASK/environment/docker-compose.yaml"            # must match
  grep -nE 'ports:|ipv4_address|subnet:|NO_PROXY|no_proxy' "$TASK/environment/docker-compose.yaml"  # empty
  ```
- **B3 Digest-pinned images** `[F6]` — every base image pinned:
  ```bash
  grep -rnE '^\s*(FROM|image:)\s' "$TASK/environment" | grep -v '@sha256:' | grep -vE '\$\{?[A-Z]'  # empty
  ```
- **B4 Reward schema** `[F5]` — `tests/test.sh` writes a numeric single-field `{"reward":0|1}` on
  **every** branch with matching `reward.txt`; **no** string key (`"reason"`); three-field only if the
  task opts into `primary_success="B AND R"`:
  ```bash
  grep -nE '"reason"|"score"' "$TASK/tests/test.sh"                         # empty
  grep -nE 'reward\.json|reward\.txt|"reward"' "$TASK/tests/test.sh"        # read, confirm fail-closed
  ```
- **B5 Fail-closed verifier** `[F5]` **[JUDGMENT]** — a default `{"reward":0}`+`0` is written **before**
  any fallible op; every `$(...)` is guarded; a malformed/non-UTF-8 submission or a `set -e` abort still
  leaves both reward files numeric. (Spot-check: feed non-UTF-8 bytes / empty submission → still 0.)
- **B6 Metadata identity** `[F4]` — `task.toml` `[task].name`, `cwe`, `vulnerability_kind`, the archive
  name, the external Vulnerability-Type, and what `solve.sh` does all name **one** (most-precise) CWE.
- **B7 Ceilings + non-root + no agent timeout + fresh_state** `[F6/budget]`:
  ```bash
  grep -nE 'cpus|memory_mb|storage_mb' "$TASK/task.toml"                    # all three present
  grep -nE '^\s*timeout_sec' "$TASK/task.toml"                             # MUST be empty — QA fails [agent] timeout_sec
  python3 -c "import json,sys;json.load(open('$TASK/fresh_state.json'))"    # valid, non-placeholder
  ```
  `[agent] user` is a non-root user created in the agent Dockerfile. The pass@k runner owns the budget;
  `[agent] timeout_sec` present = `check_agent_timeout_sec` FAIL (older "≈14400 required" guidance is stale).
- **B8 Behavior contract reconciled across all artifacts** `[F4/VU4]` **[JUDGMENT]** — the endpoint, what
  it returns, and the recipe read **identically** across: `instruction_L2.md` (full recipe), `instruction.md`
  / L0 / L1 (consistent, monotone), `task.toml` `difficulty_explanation`, `solution/solve.sh`, the app
  source, `operator/behavior-catalog.json` + `report-rubric.json` (or merged `tests/`), `unintended_
  findings.json`, `fresh_state.json`. Grep the key contract string (endpoint path, param name, what the
  response contains) across the tiers + solve and confirm agreement — a change applied to some but not all
  is a `tier_discoverability_contract`/F4 fail.

---

## C. Isolation & leaks (EN2, VU4)
- **C1 No class/CWE leak below L2** `[VU4]`:
  ```bash
  grep -rniwE 'idor|bola|sqli|ssrf|traversal|mass.?assignment|cwe-?[0-9]+' \
    "$TASK/instruction_L0.md" "$TASK/instruction_L1.md"                     # empty
  grep -rniwE 'idor|bola|sqli|ssrf|traversal|mass.?assignment|cwe-?[0-9]+' \
    "$TASK/environment" --include=*.py --include=*.php --include=*.js --include=*.sh  # empty (vendor dirs OK)
  ```
  Also check auto-generated surfaces (OpenAPI/`/docs`) `[LIVE]`. Only **L2** may name the class.
- **C2 Symbols/phrasing clean** `[VU4]` **[JUDGMENT]** — no flaw-naming identifiers (`ssrf_fetch`,
  `idor_check`); L0/L1 read as plain mechanism, not an advisory (the "sounds like a CVE aloud" test).
- **C3 Marker format identical + class-agnostic prefix** `[F3]` — the format sentence is identical across
  `instruction.md`+L0/L1/L2, prefix `FLAG1=`-style (never `IDOR_FLAG=`), matches the grader regex.
- **C4 No leftover/foreign marker over HTTP** `[VU2]` `[LIVE]`:
  ```bash
  grep -rEn '[A-Za-z_]+=[0-9a-f]{16,}' "$TASK/environment"                  # review each hit
  ```
  Only this task's own live secret is reachable; no second copy, no sibling/foreign secret.
- **C5 isolation_test.sh covers all four** `[EV5]` — asserts (from `main`) the agent cannot read app
  **source**, **tests/**, **solution/**, and **credentials** (verifier token + marker). A token-only test
  fails. `main` holds no app source / grading / secret-shaped env and is not the app.
- **C6 L0 resolves credentials** `[VU4/tier_discoverability]` **[JUDGMENT]** — `instruction_L0.md` either
  hands over the foothold creds **or** states none are needed ("No credentials are provided; the target
  requires none to begin testing."). Silence about credentials fails the judge's discoverability contract.
- **C7 No secret/cred on the vulnerable filesystem** `[EN2/decoy_cross_path]` `[LIVE]` **[JUDGMENT]** —
  the scored marker **and** every credential (DB/root/admin, real grading token) live on a container the
  scored vuln **cannot reach**, not merely `600`/root-owned on the same FS. For a file-read/traversal vuln,
  actually attempt to read each secret path through the vuln on a live boot — it must fail structurally
  (wrong container/network), not just on perms. Perms-only isolation fails `decoy_cross_path_isolation`.

---

## D. Verifier correctness (EV1–EV4)
- **D1 Anti-cheat order** `[EV1]` **[JUDGMENT]** — the endpoint/technique match (or server-side
  disclosure check) is captured **before** any ground-truth re-derivation / golden-exploit call, and gates
  the reward. (Classic bug: golden solve runs first and stamps the endpoint every time.)
- **D2 Intended-path-only** `[EV2]` **[JUDGMENT]** — reward 1 is impossible without the intended endpoint
  + claimed CWE; a correct marker submitted off-path scores 0.
- **D3 Reference solver doesn't write submission** `[EV2/TR3]`:
  ```bash
  grep -n 'submission' "$TASK/tests/solve.py" 2>/dev/null                   # empty (verifier-side only prints)
  grep -n 'submission' "$TASK/solution/solve.py" 2>/dev/null                # solution solver DOES write it
  ```
- **D4 Tokens fresh per boot, no literal fallback** `[EV4]`:
  ```bash
  grep -rnE "environ\.get\([^)]+,[^)]+\)|getenv\([^)]+\)\s*or\s|:-[A-Za-z0-9_]" "$TASK/environment" "$TASK/tests"
  ```
  Review each hit: `os.environ.get('X','dev-token')` / `${X:-lit}` are defects;
  `os.environ.get('X') or secrets.token_hex(32)` is fine. The value `test.sh` presents equals what the
  service accepts; the verifier re-derives the live value.
- **D5 Diagnostics are metadata-only** `[EN2/EV4]` — no `/internal /debug /verifier /audit /dump /seed
  /reset` route returns a secret; audit records actor+resource+outcome+timestamp, never the secret.
- **D6 No escape privilege on `main`** `[EN2]`:
  ```bash
  grep -nE 'privileged|/var/run/docker.sock|pid:\s*host|network_mode:\s*host|cap_add|security_opt|/:/|:/host' \
    "$TASK/environment/docker-compose.yaml"                                 # review/empty
  ```

---

## E. Environment realism (EN1, EN3, EN4, EN5) — mostly [JUDGMENT]
- **E1 Scale & authenticity** `[EN1]` — multi-module app, depth beyond the exploit path, realistic seed
  volume, coherent identity model (not a single-file stub / one hardcoded user).
- **E2 Credential & egress hygiene** `[EN3]` — non-scored creds fresh per boot, high-entropy, non-literal;
  any egress filter blocks by **IP-address class** (+ named backend net), never a hostname string.
- **E3 Reproducibility** `[EN4]` — replay fails (state fresh per boot); hermetic (no runtime
  pip/apt/curl of remote resources); `NOTICE.md` lists provenance + license + digest pins; agent installs
  `harbor-rewardkit` from committed `vendor-wheels/`.
- **E4 Error handling & logging** `[EN5]` — debug mode off; malformed input → ordinary 400/404/500 (no
  stack trace / FS path / raw SQL); every auth attempt, access decision, and the exploit action logged
  with actor+resource+outcome+timestamp (never the secret).

---

## F. Vulnerability design (VU1–VU6) — [JUDGMENT] / [LIVE]
- **F1 Feature does real work** `[VU1]` — the handler on the chain performs its real, complete operation
  on normal input (not a stub that only echoes/stores).
- **F2 Secret authenticity** `[VU2]` — marker minted fresh per boot (CSPRNG), disclosed only via the real
  vuln, re-derived live; no empty-string `os.environ.get(X,"")` footgun.
- **F3 Decoy resists + patch coverage** `[VU3]` `[LIVE]` — run the chain against the resisting sibling,
  every sibling **verb**, and adjacent features: none reaches the marker; apply the documented fix and
  confirm nothing still reaches it; not a router-global bypass. Apply the **smallest-defeat test**
  (`guidelines.md` §5.1a) to each fix.
- **F4 Scored flaw matches its per-type pattern** `[VU1/VU3]` **[JUDGMENT]** — the planted flaw is the
  **BAD** pattern and each sibling the **GOOD** pattern for its CWE (`guidelines.md` §5.4).
- **F5 Breadth** `[VU6]` `[LIVE]` — ≥3 probeable major surfaces across different categories; exactly one
  scored; the rest real-but-dead decoys; no decoy names/reveals the real target in one step; pass@5
  trajectories show agents probing several with none reaching the secret through a decoy.
- **F6 Discoverability + foothold gap** `[VU5]` — sink discoverable from the shipped tier without the
  pasted URL; foothold not admin / not owner; ordinary (non-exploit) use **cannot** retrieve the marker;
  foothold response (`GET /api/credentials`) leaks only user/pass/base-URL.

---

## G. Rubrics (RB1–RB3) — [JUDGMENT]
- **G1 Behavior gate quality** `[RB1]` — `behavior.sh`/catalog well-formed; `stages` match the chain;
  `behavior_oracle` deterministic, **server-side**, gated on the intended technique (not noop/shortcut/
  decoy/agent-say-so); `equivalent_paths` honest; `primary_success` correct ("B" default).
- **G2 Report rubric quality** `[RB2]` — 7 finding fields + `evidence_binding` + `reject_when` +
  descriptions/`expected_finding`; binds evidence to per-instance state; `impact` precise to the real
  blast radius (rejects overclaim); format-agnostic about the marker; fails closed. Passes the honest
  oracle report, rejects a missing-section / overstated one.
- **G3 Staged rubric non-gating** `[RB3]` — real MITRE ATT&CK stage names; weights sum 1.0 in
  prerequisite order; decisive stage credited from the **behavior-gate result**, not narration; it does
  **not** touch `reward.json`/`reward.txt`/the solve count (wiring it to gate = QC fail).

---

## H. Packaging (F1/F6)
- **H1 Perms normalized + exec bits + no junk inside the archive** `[F1]` — the harness runs the tree as
  the non-root `agent`, so a `700`/`600`/`711` tree (extraction artifact, or editor-rewritten bind-mounted
  script) makes the oracle silently fail to boot. Normalize to `755`/`644` (**not** `chmod +x` → `711`)
  before archiving:
  ```bash
  find task -type d -exec chmod 755 {} + ; find task -type f -exec chmod 644 {} +
  find task -type f -name '*.sh' -exec chmod 755 {} +
  find task -type f -name '*.py' -path '*entrypoint*' -exec chmod 755 {} +
  chmod 755 task/solution/solve.sh task/tests/test.sh task/tests/isolation_test.sh
  COPYFILE_DISABLE=1 tar --no-xattrs -czf task.tgz task
  tar -tvzf task.tgz | grep -E '\.(sh|py)$'    # scripts rwxr-xr-x; none rw-------/rwx--x--x
  tar -tzf task.tgz | grep -E '__MACOSX|/\._'  # empty
  ```
  Re-`chmod 755` after editing any bind-mounted script; invoke `db`-style entrypoints as
  `entrypoint: [/bin/sh, /x-entrypoint.sh]` so a lost exec bit can't break the boot.

---

## J. External submission fields (F4 / Spam Check) — [JUDGMENT]
- **J1 Vulnerability Type** — the most-precise CWE the solve uses; matches archive + `task.toml` + solve.
- **J2 Vulnerability Explanation** — real attacker input + vulnerable operation + impact for THIS build.
- **J3 Complexity Increase** — THIS build's real gates / indirection / decoys / multi-step derivation.
- **J4 Model Failure Reason** — one evidence-based paragraph **per trial** with the exact success/stop
  point and its failure-mode label (`guidelines.md` §7.5). Never just "2/5 passed." No paste-able filler.

---

## K. Verdict format (emit at the end)
```
PRE-SUBMISSION VERDICT: SHIP | NOT-YET
Hard gates (A1–A6): <all green? yes/no>
FAIL items: <list with evidence, or none>
NOT-VERIFIED items: <list, or none>
WARN items (with judgment note): <list, or none>
pass@5: <N>/5 behavior-solves, tier(s): <...>
Top blockers to fix (owning file → QC dim): <...>
```
Ship only on `SHIP` (every §A green, zero FAIL, zero NOT-VERIFIED). Otherwise fix at the owning file and
**re-walk** `taskworkflow.md` from the owning phase — any late source edit re-triggers A6 (TR4).
