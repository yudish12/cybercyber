# Deep Hack — Task Workflow (agent flow + line-by-line audit)

The order you apply the rules in. Pairs with [`guidelines.md`](guidelines.md) (the rules + why + the QC
dimension map). Current to `guidelines-sot/deep-hack.pdf` (change log through **Oct 30, 2026**).

**Memorize before you start** (full detail in `guidelines.md` §1):
- **Reward = Behavior gate (B) only** by default → `reward.json = {"reward":0|1}`. Report is diagnostic.
  Three-field only if `primary_success = "B AND R"`.
- **Difficulty = pass@5 on deepseek-v4p1-flash**, run on the platform and delivered under
  `trajectories/pass@k/`. **Too easy only if all 5 behavior-solve; 0–4 of 5 clears.** You run a *local*
  pass@5 only to confirm a hardening fix.
- **`main` = `network_mode: no-network`** — no proxy, no `NO_PROXY`. Budget **200 steps / 4 h**;
  `[agent] timeout_sec ≈ 14400` is **required**.
- **Grading lives under `tests/`:** `behavior/`, `report/`, `stages/`, `reward.toml`. `operator/` optional.
- **Golden rule of the loop:** when anything is wrong, go back to the phase that **owns that fact**, fix
  it there, then **re-walk the gates forward** — any change to exploitability / agent-visible behavior /
  verifier / scoring invalidates downstream evidence, so regenerate it (stale evidence = TR4 fail).

---

## 1. The master loop

```
P0 Orient + boot
      │
      ▼
P1 AUDIT the task folder (file-by-file, line-by-line)  ── found a defect? ─► fix at the owning file ──┐
      │ clean                                                                                          │
      ▼                                                                                                │
P2 Oracle + Noop     (./blackbox-pentest-checks/run-blackbox-pentest-checks.sh task)                   │
      ├─ Oracle ≠ 1  ──────────────────────────► fix solve/env/test  (TR1/TR3/F1) ───────────────────►│
      ├─ Noop  ≠ 0   ──────────────────────────► fix anti-cheat/isolation (EV1/EV2/EN2/VU2) ─────────►│
      │ both pass                                                                                       │
      ▼                                                                                                │
P3 Quality Check     (./blackbox-pentest-qa/run-blackbox-pentest-qa.sh task)                           │   back to P1:
      ├─ any confirmed FAIL ───────────────────► fix (map to its QC dim) ──────────────────────────────►│   re-audit any
      │ clean (WARN = judgment)                                                                          │   file you
      ▼                                                                                                │   touched, then
P4 Report-rubric check  (python tests/run_report_rubric.py — diagnostic, confirm it fails closed)      │   re-walk the
      │ runs, fails closed, sane signal                                                                 │   gates forward
      ▼                                                                                                │   (late source
P5 Pass@5 gate (EV6)  read trajectories/pass@k/ (deepseek ×5); count BEHAVIOR-solves                   │    edit ⇒ stale
      ├─ 5 of 5 solve ───► too easy ─► HARDEN (gl §5.1) ─► local pass@5 ─► regenerate evidence ────────►│    = TR4 fail)
      ├─ 0–4/5 but a non-solve never reached the vuln / stalled on infra ─► setup defect ─► fix ───────►│
      │ 0–4 of 5 solve, every non-solve genuinely attempted, each classified (TR5)                      │
      ▼                                                                                                │
P6 External fields + package + ship ───────────────── any dim < 5 / box unticked? ────────────────────┘
      │ all green
      ▼
    DONE
```

---

## 2. P0 — Orient + boot
1. Confirm the three runner bundles are unzipped beside `task/`: `blackbox-pentest-checks/`,
   `blackbox-pentest-qa/`, `blackbox-pentest-pass1/`. Run everything from the **workspace root** that
   contains `task/`.
2. Read any notes as **claims to verify**, not truth: `design_note.md`, `unintended_findings.json`,
   `operator/*`.
3. Boot only for debugging/probes (the runners boot for you):
   ```
   cd task/environment && docker compose down -v && docker compose up -d --build && docker compose ps
   ```
   Every healthchecked service must read **healthy**, not `starting`/`running`.
4. **If** a service never goes healthy or the app returns empty / won't resolve → §8 Troubleshooting.
   `main` is `network_mode: no-network`, so there is no proxy to fix; the usual cause is probing early or
   discovery not yet converged.

---

## 3. P1 — Line-by-line audit of the task folder

Read in **this order**. For each file read **every line**, trace each value/endpoint to where it is
produced and consumed, and tie each finding to its QC dimension (`guidelines.md` §10). Do not trust
comments or notes — trace the code. A fail usually cross-fails another dimension (↔) — fix both.

**First, presence/parse/exec (F1).** Confirm every required file exists, is non-empty, parses, and
(scripts) is executable:
`task.toml`, `instruction.md` + `instruction_L0/L1/L2.md`, `fresh_state.json`,
`environment/{docker-compose.yaml, NOTICE.md, agent/Dockerfile, agent/vendor-wheels/, web/Dockerfile,
<app-service>/, <sibling>/(opt)}`, `solution/solve.sh` (+ `solve.py` opt),
`tests/{test.sh, isolation_test.sh, reward.toml, behavior/{behavior.sh, check.py},
report/{rubric.toml, judge_prompt.md}, stages/{rubric.toml, check.py},
run_report_rubric.py (+ .sh)}`, `trajectories/{oracle,noop,pass@k}/`. `operator/{behavior-catalog.json,
report-rubric.json}` is optional (the B/R specs may live there **or** in the merged `tests/` form).
Missing/empty/unparsable = **F1 fail**.

### 3.1 `task.toml` → F4, F6, EN4, VU4, budget
- `[task].name`, `[metadata].cwe`, `vulnerability_kind`, the archive filename, the external
  Vulnerability-Type radio, and what `solve.sh` actually does all name the **same** skill; use the
  **most precise** CWE (right-family-but-imprecise = deduction). → **F4**
- `[environment]` declares `cpus`, `memory_mb`, **and** `storage_mb`; `[agent] user` is a **non-root**
  identity created in the agent Dockerfile. → **F6 / EN4**
- `[agent] timeout_sec` is **present** and ≈ `max_turns × 120` (≈ 14400s for 200 steps) — not removed,
  not below that floor. → **budget**
- `difficulty_explanation` replays step-for-step against the current `solve.sh`/env (no stale
  description; re-synced after any hardening or endpoint change). → **VU4**

### 3.2 `instruction.md` + `instruction_L0/L1/L2.md` (strict supersets) → F1, F3, VU4
- `instruction.md` is **REQUIRED** — a copy (or superset) of the delivered tier; it asks the agent to
  write `/logs/verifier/report.md` with the 7 sections. → **F1**
- **L0** = target + credentials only (authorized/defensive framing); **no** mechanism/class/endpoint.
- **L1** = L0 + mechanism in plain words; **no** exact `/api/...` path, **no** class/CWE. → **VU4**
  (fail an L1 that hands over an endpoint)
- **L2** = L1 + exact URL **and** full recipe **and** explicit class/CWE named (all three). → **VU4**
- **Flag format** identical across `instruction.md` + L0/L1/L2, prefix **class-agnostic** (`FLAG1=<hex>`,
  never `IDOR_FLAG=`), matching the grader regex. → **F3**
- **Leak grep** (word-boundary) across L0, L1 **and all app/env source** for the class name, CWE id, and
  acronym (`idor|bola|sqli|ssrf|traversal|mass-assign`) — source may never name the class at any tier;
  only L2 may. Check auto-generated surfaces (`/docs`, OpenAPI) too. → **VU4**

### 3.3 `environment/` (read every source file copied into the app image) → F2, F6, EN1–EN5, VU1–VU6
- `docker-compose.yaml`:
  - A service named **exactly `main`** = the agent sandbox, running `network_mode: no-network`; internal
    siblings on an `internal: true` backend, `main` **not** attached to it; verify unreachable by a live
    probe. → **F2 / EN2**
  - **No** `ports:` on any service; **no** `ipv4_address` / pinned `subnet` (Docker auto-allocates,
    per-boot-unique). → **F2**
  - **No `NO_PROXY`/`no_proxy`** anywhere (no proxy exists; a value naming internal hosts is a recon
    leak). → **EN2/VU5**
  - `main` has **no escape-grade privilege**: no `/var/run/docker.sock`, `privileged`, `pid: host`,
    `network_mode: host`, host-path binds, shared IPC/PID/net, confinement-disabling `security_opt`, or
    unjustified `cap_add` (`SYS_ADMIN`/`SYS_PTRACE`/`SYS_MODULE`/`NET_ADMIN`/`DAC_READ_SEARCH`). → **EN2**
  - Base images **digest-pinned** (`@sha256:`); every `build: ./x` dir ships. → **F6 / EN4**
  - Verifier/diagnostic/grading tokens **fresh per boot, no literal fallback**
    (`os.environ.get("X","lit")` / `${X:-lit}` fail); the value `test.sh` presents equals what the
    service accepts. → **EV4**
  - Non-scored privileged creds (admin/DB/API/session) fresh per boot, high-entropy, **not literals** in
    compose/`.env`/source. → **EN3**
  - `main`'s `environment:` contains **no** secret-shaped var and **no** internal-target hint. → **EN2**
- App source (`web/`, `<app>/`, custom API) — the single scored flaw lives here:
  - **Scale/authenticity:** multi-module, depth beyond the exploit path, realistic seed volume, coherent
    identity model. → **EN1**
  - **Vulnerable feature does real work** on normal input (export writes a file; create persists + is
    retrievable), not a stub. → **VU1**
  - **Exactly one** live vulnerable surface; every **other** planted vuln is **closed** (ownership /
    allowlist / canonicalization / SSRF host-reject by IP class), not renamed. → **VU2/VU3**
  - **≥3 genuinely probeable major surfaces** across different categories; exactly one scored; the rest
    real-but-dead decoys; no decoy names/reveals the real target in one step. → **VU6**
  - A **resisting sibling endpoint** on the same resource (verified by attempting the chain); sibling
    verbs/adjacent features carry no identical hole; nothing survives the documented fix; not a
    router-global bypass. → **VU3**
  - Marker minted fresh per boot (CSPRNG; no empty-string `os.environ.get(X,"")` footgun), disclosed only
    via the real vuln, re-derived live; no leftover/foreign `NAME=<hex>` reachable over HTTP. → **VU2**
  - No `/internal` `/debug` `/verifier` `/audit` `/dump` `/seed` `/reset` route returns any secret —
    audit routes return **metadata only**, recording **actor + resource + outcome + timestamp**, never
    the secret. → **EN2/EV4**
  - Malformed input → ordinary app error (no stack trace / FS path / raw SQL; debug mode off). Security
    events logged with the four fields. → **EN5**
  - Any egress filter blocks by **IP-address class**, not a hostname. → **EN3**
  - Foothold: ordinary (non-exploit) use **cannot** retrieve the marker; the foothold response (e.g.
    `GET /api/credentials`) discloses only user/pass/base-URL. → **VU5**
  - For file-read tasks: exposed source contains **no** token literal that unlocks a protected route. →
    **EV4/EN2**
- `environment/agent/`: Dockerfile installs `harbor-rewardkit` from the committed `vendor-wheels/` (no
  build network); creates the non-root user and `USER`s to it. → **F6/F1**
- `NOTICE.md`: provenance + license + base-image digest pins for every third-party component. → **EN4**
- Hermetic + deterministic: no runtime `pip`/`apt`/`curl`/`wget` of remote resources; same behavior every
  boot. → **EN4**
- Exploit narration / hint comments live **outside** the agent-readable tree. → **F6**

### 3.4 `solution/solve.sh` (+ optional `solve.py`) → TR3, F1
- Writes the recovered marker to the **exact** submission path `test.sh` reads
  (`/logs/verifier/submission.txt`) — a file write, not stdout. → **TR3**
- Recovers the secret through the **intended CWE path** (no shortcut: no config/env/seed read, no
  leftover copy, no side route). → **TR3**
- Also writes a sample `report.md` for the oracle's report side. Has the exec bit. → **F1**

### 3.5 `tests/` → F5, EV1–EV5, RB1, RB2, RB3
- `tests/test.sh` **fail-closed**: writes a default reward **before** any fallible op; no `set -e`
  footgun (guard every `$(...)`); malformed/non-UTF-8 submission ⇒ caught ⇒ reward 0, never a crash.
  **Every** branch writes **both** reward files. → **F5**
- `reward.json` = **single-field numeric** `{"reward": 0|1}` by default (three-field `{behavior,
  report_rubric, reward}` only under `primary_success = "B AND R"`); `reward.txt` agrees; **no string
  key**. `tests/reward.toml` is the definition. → **F5**
- **Endpoint/technique match gates the reward and runs BEFORE** ground-truth re-derivation and before the
  golden exploit is invoked. → **EV1**
- Reward 1 is impossible without the intended endpoint + claimed CWE (static + in every shipped reward-1
  trial); a correct marker off-path scores 0. → **EV2**
- A verifier-side `solve.py` (if used) only re-derives for comparison — never writes submission
  (`grep -n submission tests/solve.py` is empty). → **EV2 / TR3**
- `tests/behavior/behavior.sh` (+ `check.py`): reads `/internal/diag/audit` (verifier-token only),
  confirms disclosure **through the intended technique** and marker == live ground truth. → **RB1**
- `tests/report/{rubric.toml, judge_prompt.md}`: diagnostic; 7 finding fields + `evidence_binding` +
  `reject_when`; format-agnostic about the marker; LLM judge via internal gateway, fails closed to 0. →
  **RB2**
- `tests/stages/{rubric.toml, check.py}`: real MITRE ATT&CK stage names, weights sum 1.0 in prerequisite
  order, decisive stage credited from the **behavior-gate result**; **non-gating** (wiring it to gate =
  QC fail). → **RB3**
- `tests/isolation_test.sh` ships, runs standalone, and **fails** if the agent can read source, `tests/`,
  `solution/`, or credentials (all four); `main` holds no app source/grading/secret-shaped env. → **EV5**

### 3.6 `trajectories/` (evidence — current only) → TR1, TR2, TR4, TR5, EV6
- `oracle/` → `reward.txt` = `1`, `reward.json = {"reward":1}`, `test.log` shows the intended
  endpoint/CWE succeeding (no hardcoded compare, no stale names). → **TR1**
- `noop/` → fresh clean-boot garbage submission scores exactly `0`. → **TR2**
- `pass@k/` → **deepseek ×5**, tier recorded on each; read per-trial **behavior** result; **too easy only
  at 5/5, 0–4 of 5 clears**. Classify each genuine non-solve with exactly one taxonomy mode. → **EV6 /
  TR5**
- **All evidence postdates the last material source edit** — stale evidence **fails** the task (not
  re-captured). → **TR4**

### 3.7 `fresh_state.json`, `unintended_findings.json` → F6, F1
- `fresh_state.json` valid non-empty JSON at task root (per-boot reset contract: what regenerates, what
  stays stable). → **F6/F1**
- `unintended_findings.json` optional; verify every claim against live code.

**End of P1:** fix any confirmed defect at its owning file and re-audit that file before entering P2.

---

## 4. P2 — Oracle + Noop
```
./blackbox-pentest-checks/run-blackbox-pentest-checks.sh task      # two fresh boots
```
- **Oracle:** `solve.sh → submission.txt → test.sh` scores **exactly 1**; reward files + verifier output
  complete; `reward.json = {"reward":1}` (behavior-only).
- **Noop:** garbage submission on a **fresh** boot scores **exactly 0**; reward files complete.
- Capture `test.sh` output in **one** invocation (re-running mutates audit state).

**If Oracle ≠ 1** → fix solve/env/`test.sh` (§3.3–3.5; TR1/TR3), rerun. Never hardcode or loosen the
check to force a pass.
**If Noop ≠ 0** → a side-door scored for free → fix anti-cheat order / isolation (EV1/EV2/EN2/VU2),
rerun.
**Else** → P3.

---

## 5. P3 — Quality Check
```
./blackbox-pentest-qa/run-blackbox-pentest-qa.sh task
```
Read the report written **outside** `task/`. A clean automated report does **not** replace manual review.
**If confirmed FAIL** → fix (map to its QC dim in `guidelines.md` §10), rerun until clean.
**If WARN** → reviewer judgment; correct checker false positives explicitly.
**Else** → P4.

---

## 6. P4 — Report-rubric check (diagnostic)
```
python tests/run_report_rubric.py      # via run_report_rubric.sh, against the oracle report + trajectories
```
The report rubric is **diagnostic — there is no R gate to clear** (unless the task set
`primary_success = "B AND R"`). Confirm it **runs**, **fails closed** (any status ≠ graded ⇒ R = 0), and
gives **sensible signal**: a deliberately bad report (missing a section / overstated impact) is rejected;
the honest oracle report passes. Confirm `tests/` is not agent-readable.
**Else** → P5.

---

## 7. P5 — Pass@5 difficulty gate (EV6)

The official pass@5 (deepseek ×5, 200 steps / 4 h each) is run on the platform and delivered under
`trajectories/pass@k/`. Read the **per-trial behavior result** (not `reward.txt`) and count
behavior-solves.

| Behavior-solves / 5 | Rate | Clears? |
|---|---|---|
| 0–4 | < 100% | **Yes — accepted complexity** |
| 5 | 100% | **No → too easy, harden** |

- A **solve** = behavior gate alone confirms the intended exploit via the **intended endpoint + claimed
  CWE**.
- **Counted non-solve** (clears the gate): intended-attempt-but-stuck, decoy/other-path pivot,
  no-attempt, or exhausting the 200-step budget while genuinely engaged.
- **Excluded** (not a difficulty signal, not a solve): refusal, `broken/task_specification`,
  infrastructure/proxy failure, `low_timeout` (cut short below the budget).
- **`shortcut_win`** (reward 1 off the intended endpoint+CWE) is **not** a solve and is a contamination/
  anti-cheat bug → fix the leak (A1/A2/EV1/EV2), don't bank it.
- Every trial must **record its tier**; panel must be exactly **deepseek ×5**. A failed/missing analyzer
  = **NO VERDICT** → raw `trajectory.json` is authoritative (budget, turns, verifier reason, submission,
  commands).
- Each genuine non-solve gets **exactly one** failure mode (`guidelines.md` §7.5), trajectory-supported,
  at the blocking stage. → **TR5**

**If 5 of 5 solve** → too easy → HARDEN (`guidelines.md` §5.1; add a service only if it keeps the same
CWE), run a **local** pass@5 (`./blackbox-pentest-pass1/run-blackbox-pentest-pass1.sh task`) to confirm,
**re-walk from P1** (regenerate all evidence, else TR4 stale-fail); the platform re-runs the official
pass@5.
**If 0–4/5 but a non-solve never reached the vuln, stalled on infra/timeout, or all pivoted to a decoy**
→ setup defect (discoverability / contamination / too-hard QH2) → fix at the owning file, re-walk.
**Else (0–4 of 5, every non-solve genuinely attempted, each classified)** → P6.

---

## 8. P6 — External fields + packaging + ship

**External submission fields** (not in the archive; required for QC — F4 + Spam Check):
- **Vulnerability Type** = the **most precise** CWE class the solve uses (not generic "Broken Access
  Control"), matching archive name + `task.toml` `cwe`/`vulnerability_kind` + the golden solve. → **F4**
- **Vulnerability Explanation** — the real attacker input + vulnerable operation + impact for this build.
- **Complexity Increase** — this build's real gates/indirection/decoys/multi-step derivation.
- **Model Failure Reason** — one evidence-based paragraph **per trial** with the exact success/stop point
  and the TR5 failure mode (never just "2/5 passed"). → **Spam Check / TR5**

**Packaging** (verify **inside the final archive**, not the working folder):
- Digest-pin every base image; `task.toml` ceilings + non-root agent; valid `fresh_state.json`; agent
  installs from `vendor-wheels/`; `NOTICE.md` complete. → **F6/EN4**
- `main` has no escape-grade privilege; no `ports:` / static subnet; no `NO_PROXY`. → **F2/EN2**
- **Evidence captured last:** nothing under `environment/`, `tests/`, `solution/`, `task.toml`,
  `instruction*.md` is newer than `trajectories/`. → **TR4**
- Exec bits set inside the archive; no `__MACOSX/` / `._*` (archive from the shell, never Finder):
  ```
  chmod +x task/solution/solve.sh task/tests/test.sh task/tests/isolation_test.sh task/environment/*/entrypoint.sh
  COPYFILE_DISABLE=1 tar --no-xattrs -czf task.tgz task
  tar -tvzf task.tgz | grep -E '(solve|test|isolation_test|entrypoint)\.sh$'
  ```

**Final ship checklist (ship bar = every QC dimension passes; `guidelines.md` §10):**
- [ ] Everything for grading lives under `task/`; `instruction.md`, `fresh_state.json`, `isolation_test.sh`,
  `NOTICE.md`, `tests/{behavior,report,stages}/`, `tests/reward.toml` all present. → **F1**
- [ ] `trajectories/oracle/reward.txt` = `1`, `noop/reward.txt` = `0` on fresh boots; all evidence
  postdates the last source edit. → **TR1/TR2/TR4**
- [ ] `trajectories/pass@k/` = deepseek ×5, tier recorded, **not 5/5** (0–4 of 5), every non-solve
  genuinely attempted and classified, shortcut wins excluded. → **EV6/TR5**
- [ ] `reward.json` numeric (single-field by default); fail-closed; verifier/diagnostic tokens fresh per
  boot, no literal fallback. → **F5/EV3/EV4**
- [ ] L0/L1 + source no class/CWE leak (incl. flag format and `/docs`); L2 has URL + recipe + explicit
  class/CWE; flag format identical across tiers. → **VU4/F3**
- [ ] B gate deterministic/server-side/intended-technique-gated; report rubric format-agnostic + fails
  closed; staged rubric non-gating. → **RB1/RB2/RB3**
- [ ] ≥3 probeable surfaces, exactly one scored, decoys resist; diagnostics metadata-only; normal
  workflow works; app multi-module/realistic; foothold has a privilege gap. → **VU1/VU3/VU5/VU6/EN1/EN5**
- [ ] `main` named exactly `main`, `network_mode: no-network`, no escape privilege, no `ports:`/static
  subnet/`NO_PROXY`. → **F2/EN2**
- [ ] External Vulnerability Type + all three explanation fields complete and task-specific. → **F4/Spam**

---

## 9. Troubleshooting (sandbox gotchas)
- **Empty response / `web` won't resolve:** probed before services healthy, or discovery not converged.
  `main` is `network_mode: no-network` — no proxy to fix. Give the verifier + golden solver a
  discovery/wait budget **at least** the agent's (`resolve_web.sh` is one valid pattern). Never name
  internal hosts in the environment.
- **Report judge can't reach the model:** route through the **internal gateway** only; **fail-close to 0**
  on any error; never the public internet.
- **"port already allocated" / "pool overlaps":** a static host port or pinned subnet/`ipv4_address` —
  remove it; let Docker auto-assign (per-boot-unique). Remove stale committed `.env`.

---

## 10. Revisit map (which symptom sends you back where)

| Symptom | Owning phase/file | QC dim |
|---|---|---|
| Noop scores 1 / free marker | §3.3 app source, §3.5 `test.sh` order | EV1, EV2, EN2, VU2 |
| Oracle scores 0 | §3.4 solve, §3.3 env, §3.5 `test.sh` | TR1, TR3, F1 |
| No reward written / grader crashes / wrong shape / string key | §3.5 `test.sh` + `reward.toml` | F5 |
| Report not fail-closed / wrong primary_success | §3.5 report | EV3, RB2 |
| L1 leaks path/class; source names class; `/docs` leaks | §3.2 instructions, §3.3 source | VU4 |
| 5/5 solve (too easy) | `guidelines.md` §5.1 → harden | EV6 |
| 0 solve, no discovery path / over-privileged foothold | §3.2 / §3.3 | VU5 |
| All non-solves pivoted to a decoy | §3.3 decoys/contamination | VU2/VU3/VU6 |
| Non-solve mislabeled / unlabeled | §3.6 trajectories | TR5 |
| Stale evidence (older than a source edit) | §3.6 / §8 packaging | TR4 |
| Thin/stub app; vulnerable feature does nothing | §3.3 | EN1, VU1 |
| Decoy is a look-alike value, not a resisting endpoint | §3.3 | VU3 |
| Stack trace / incomplete audit log | §3.3 | EN5, EV4 |
| Static privileged cred / hostname-only egress filter | §3.3 | EN3 |
| Verifier/diagnostic token literal or with a fallback | §3.3 / §3.5 | EV4 |
| `main` escape privilege / ships `NO_PROXY` / ports / static subnet | §3.3 compose | EN2, F2 |
| Unpinned image / no ceiling / narration in agent tree / no vendor wheels | §3.1 / §3.3 | F6, EN4 |
| Staged rubric wired to gate reward | §3.5 stages | RB3 |
| Blank marker per boot | §3.3 secret wiring | VU2 |
| Wrong external type / spam explanations | §8 | F4, Spam |
| `__MACOSX` / missing exec bit / late source edit | §8 packaging | F1, TR4 |

---

## 11. Five that keep biting (one-screen reminder)
1. **Rename is not a fix** — close the endpoint, don't rebrand the value.
2. **One live surface** — every other vuln provably inert; ≥3 surfaces, exactly one scored.
3. **Fail closed** — write a default reward before anything can abort.
4. **Trace, don't trust** — read the source, not the note.
5. **Capture evidence last, package from the shell** — any late source edit invalidates every trajectory.
