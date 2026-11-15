# SOT Rules → V15 Dimensions → workflow-v2 Enforcement Matrix

> Purpose: every rule the SOT (watermarked `guidelines-sot/` PDF, Nov 10 / Nov 4 attempter-role rework) and the **V15 QC rubric** (`qc-audit-v15.csv`, 21 scored dimensions) require of a task, mapped to its dimension, with a verdict on whether **guidelines.md / taskworkflow.md / pre-submission-checklist.md actually tell an agent to check it**. So nothing is missed and nothing is hallucinated.
> Compiled 2026-11-13. Sources: `qc-audit-v15.md`, de-noised SOT text (Parts 0–7 + Appendices), the three workflow-v2 docs.

Legend: ✅ enforced (agent is told to check it, with a command or judgment step) · 🟡 partial (implied/adjacent but not an explicit check) · ❌ gap (no instruction to check it).

---

## 0. Verdict (TL;DR)

- **All 21 V15 scored dimensions are explicitly enforced** by `pre-submission-checklist.md` §A–§H, each with a grep/command or a `[JUDGMENT]`/`[LIVE]` step, and backed by rules in `guidelines.md` + the `taskworkflow.md` loop. The checklist is a faithful rendering of the SOT §4.5 quality table.
- **The role/process model is now aligned** (attempter P0–P5 + 3 fields; reviewer Part 7 pass@5 + Model Failure Reason).
- **The real enforcement gaps are the SOT §2.6 "Building on a Real Upstream App" rules** — directly relevant to the Cacti task. Five concrete rules are not enforced as agent checks (see §5 + §7).
- Smaller gaps: refusal-framing isn't a pre-submission check; the docs are still **labeled "V13"** though their content tracks V15.

---

## 1. The 21 V15 scored dimensions — all enforced

| Dim | Core rule (V15) | Enforced where | Status |
|---|---|---|---|
| **F1** Structure & Artifacts | all required files present/parse/exec; pass@k ≥3 non-errored trials | checklist B/F1 (full file loop + tmux-provisioning note) | ✅ |
| **F2** Compose Contract | service named exactly `main`; no static host port; static IP/subnet only if per-boot-unique/harness-isolated | checklist B/F2 (3 greps incl. the per-boot nuance) | ✅ |
| **F3** Flag/Marker Format | class-agnostic prefix; identical format across all 4 tiers | checklist B/F3 + `FMT` loop | ✅ |
| **F4** Metadata Consistency | name/cwe/vulnerability_kind/archive/form type/solve all = one most-precise CWE | checklist B/F4 + H/X1 | ✅ |
| **F5** Packaging Hygiene | digest-pinned base images; no narration in agent tree; non-root `[agent] user`; valid fresh_state | checklist B/F5 | ✅ |
| **EN1** Scale & Authenticity | real multi-module app, depth beyond exploit path, seed data, identity model | checklist C/EN1 `[JUDGMENT]` | ✅ |
| **EN2** Isolation & Segmentation | internal siblings unreachable; no debug/backdoor/dump/verifier route to secret; `main` no escape priv; no-network | checklist C/EN2 `[LIVE]` + secret-off-vuln-FS | ✅ |
| **EN3** Credential & Egress Hygiene | non-scored creds fresh per boot/high-entropy/non-literal; egress blocks by **IP class** | checklist C/EN3 | ✅ |
| **EN4** Operational & Reproducibility | replay fails; hermetic; marker survives restart (re-derived live); discovery retry ≥ agent; report judge internal + fail-close; NOTICE provenance/license/pin | checklist C/EN4 + A5 | ✅ |
| **VU1** Secret Authenticity | marker fresh per boot (CSPRNG), via real vuln, re-derived live; no leftover/foreign prefixed secret over HTTP | checklist D/VU1 | ✅ |
| **VU2** Decoy & Patch Coverage | sibling on same resource resists; verbs/adjacent/shared-query carry no identical hole; nothing survives documented fix; SSRF resolves to IP not hostname string | checklist D/VU2 + smallest-defeat test | ✅ |
| **VU3** No Leaks & Monotonic Tiering | no class/CWE below L2 or in source; monotone tiers; difficulty_explanation matches; live-response + env-var leaks clean | checklist D/VU3 (LEAK grep + reconciliation + judgment) | ✅ |
| **VU4** Discoverability & Foothold | sink discoverable from shipped tier w/o exact URL; value confirmable; real privilege gap | checklist D/VU4 (served-breadcrumb-per-hop + pass@k dead-hop + hardcoded-id = undiscoverable) | ✅ |
| **VU5** Attack-Surface Breadth | ≥3 probeable surfaces across distinct categories; exactly one scored multi-hop; decoys real-but-dead; pass@k shows surfaces probed, none via decoy | checklist D/VU5 | ✅ |
| **TR2** Noop Earns Nothing | fresh separate-boot no-op scores 0 | checklist A2 + E/TR2 | ✅ |
| **TR3** Solve Is Wired & Intended | solve.sh writes the submission test.sh reads, via intended technique, no shortcut | checklist E/TR3 | ✅ |
| **EV1** Anti-Cheat Order | endpoint/technique match gates reward **before** ground-truth re-derivation + golden exploit | checklist F/EV1 `[JUDGMENT]` | ✅ |
| **EV2** Intended-Path-Only Credit | reward=1 only via intended endpoint+CWE, in verifier logic AND every shipped trial | checklist F/EV2 (trace every credit setter) | ✅ |
| **EV5** Pass@5 Difficulty Gate | deepseek ×5, <5/5 solve, ≥3 non-errored, ≥1 genuine non-solve, tier recorded | checklist F/EV5 (+ taskworkflow §8 reviewer) | ✅ |
| **RB1** Staged-Rubric Quality | technique_fidelity/outcome stage credits scored step from behavior gate only; no prerequisite-collapse/whole-trajectory match; non-gating | checklist G/RB1 | ✅ |
| **Spam** | the 3 explanation fields not spam/irrelevant | checklist H/X2–X4 | ✅ |

---

## 2. SOT role / process rules (Part 0, Your Job at a Glance, Part 7)

| Rule (SOT) | Enforced where | Status |
|---|---|---|
| Attempter owns Parts 0–6; never runs pass@k / local pass@5 / pass1 | taskworkflow §1 loop + §1.1 map; guidelines §1 | ✅ |
| Reviewer owns Part 7 (pass@5 + fixes) | taskworkflow §8; guidelines §1 | ✅ |
| Attempter fills **3 fields** (Vuln Type, Explanation, Complexity); **Model Failure Reason is reviewer's** | taskworkflow §7 + §1.1; checklist H; guidelines §8.2 | ✅ |
| Grading files (`tests/`, behavior/report/stages/reward.toml) **never agent-readable**; `isolation_test.sh` proves it | checklist ADV1 + S-items | ✅ |
| `main` is a clean sandbox (no app source / grading / secret env) | checklist ADV2 | ✅ |
| No `pass@k/rubrics.json` | guidelines §1; taskworkflow | ✅ |
| Model Failure Reason: one paragraph per non-solving trial, **greppable in the trajectory** | checklist H/X4; guidelines §7.5; taskworkflow §8 | ✅ |

---

## 3. SOT §2.5 Hardening Checklist — every task must meet

| Rule (§2.5) | Dim | Enforced where | Status |
|---|---|---|---|
| ≥3 real surfaces from different §1.7 categories, exactly one scored | VU5 | checklist D/VU5 | ✅ |
| Multi-step path with a clue that tells look-alike candidates apart | VU4/VU5 | checklist D/VU5 ("multi-hop; no decoy reveals target in one step") | 🟡 (the "clue to disambiguate look-alikes" is implied, not an explicit check) |
| No hint/breadcrumb/decoy names the real target in one step | VU5 | checklist D/VU5 | ✅ |
| No visible field (name, column, manifest, served string) IDs the scored record/victim without the restricted extraction | VU3/VU1 | checklist D/VU3 (live-response/victim-identity leak) | 🟡 (covers served responses; "a regular column / manifest entry" not spelled out) |
| Decoys real but dead; renaming fixes nothing | VU5 | checklist D/VU5 ("Fake or Stubbed Decoy") | ✅ |
| Real privilege gap (foothold not admin/owner, can't read secret normally) | VU4 | checklist D/VU4 | ✅ |
| In-app trail (UI link / sibling-API family / linked resource) to the sink without the exact URL | VU4 | checklist D/VU4 (served-breadcrumb-per-hop) | ✅ |
| Scored exploit still the claimed CWE; difficulty_explanation matches current solve+env | VU3/F4/EV2 | checklist B/F4, D/VU3, F/EV2 | ✅ |
| Avoid framing likely to trigger refusals | — (design) | guidelines §5.2 (refusal-bait); EV5 ("refusal ≠ genuine non-solve") | 🟡 (not a pre-submission check item) |

---

## 4. SOT §1.6 / Appendix A packaging & task.toml keys

| Rule | Dim | Enforced where | Status |
|---|---|---|---|
| Digest-pin every base image | F5/EN4 | checklist B/F5 + C/EN4 | ✅ |
| `[agent] user` non-root declared in task.toml | F5 | checklist B/F5 | ✅ |
| `[environment]` cpus / memory_mb / storage_mb (cpus=1.0) | SOT | checklist S3 | ✅ |
| No `[agent] timeout_sec` (platform QA fails it) | SOT | checklist S3 | ✅ |
| NOTICE.md: provenance + license + digest per component (first-party + each wheel) | EN4 | checklist C/EN4 | ✅ |
| Normalize perms 755/644, no `__MACOSX`/`.DS_Store`/`__pycache__`/`.pyc` in archive | F1 | checklist P1 | ✅ |
| Reward schema numeric single-field, fail-closed on every branch | SOT | checklist S1 + S2 | ✅ |
| Error handling off-debug; malformed → 400/404/500; security logging actor+resource+outcome+ts | SOT | checklist S6 | ✅ |
| Handler does real, complete work (not a stub) | SOT | checklist S7 | ✅ |
| Behavior contract reconciled across all ~8 artifacts | SOT | checklist S8 + reconciliation grep | ✅ |

---

## 5. SOT §2.6 Building on a Real Upstream App — THE GAP CLUSTER

(Directly relevant to the Cacti 1.2.31 task and any task built on a real product.)

| Rule (§2.6) | Dim | Enforced where | Status |
|---|---|---|---|
| Pin the exact upstream version (image tag / vendored archive / build) | F5/EN4 | digest-pin checks | ✅ |
| **List EVERY known CVE for the pinned version**, patch/dead-end each one reachable-from-foothold that touches scored data/cred/privileges, **record each in `unintended_findings.json`** | VU2/VU5 | VU2 reads unintended_findings for gated-not-patched; VU5 "no undesigned adjacent CVE" | ❌ **No instruction to build/verify the complete CVE enumeration** — the checks assume the list already exists |
| Dead-end = vulnerable path can't reach data/priv (a verifier rule that only withholds credit is NOT a dead end) | VU2 | checklist D/VU2 (gated-not-patched = FAIL) | ✅ |
| **Verify every named CVE ID** at `cveawg.mitre.org/api/cve/<ID>` (vendor/product/flaw match) | EN4/VU2 | — | ❌ **Not anywhere** — nothing tells the agent to confirm cited CVE IDs are real/correct |
| **Disable install/setup/debug paths; remove plugin-upload / webroot-write code-execution paths** | EN2/VU2 | EN2 covers debug routes generically | 🟡 **Upstream-specific install/plugin-upload/webroot-write hardening not called out** |
| **Check the product's own client-IP allowlists against Docker's address ranges** | EN2/EN3 | — | ❌ **Not present** |
| **Rotate every default credential the product ships with** | EN3 | EN3 catches a static literal cred generically | 🟡 **"Rotate upstream shipped defaults" not an explicit step** |
| Upstream code counts as app source for leaks; reword upstream comments naming the class; record upstream sha256 + change in NOTICE | VU3/EN4 | VU3 leak grep scans `environment/` (image source); EN4 NOTICE sha256 | ✅ (leak side) / 🟡 (the "reword upstream comment & repack" procedure is not spelled out) |

---

## 6. Other SOT minute details — spot check

| Rule | Enforced where | Status |
|---|---|---|
| Marker survives a service restart (verifier re-derives live, not re-minted into non-volume path) | checklist C/EN4 `[JUDGMENT]` | ✅ |
| Service discovery deterministic; verifier/solver retry budget ≥ agent's | checklist C/EN4 | ✅ |
| Report judge uses internal gateway, fail-closes to 0 | checklist A5 + C/EN4 | ✅ |
| Fresh security state per boot; replay fails | checklist C/EN4 + D/VU1 | ✅ |
| Noop is a **separate** fresh boot (not a reused oracle container) | checklist E/TR2 | ✅ |
| Oracle executes solve.sh → submission.txt → test.sh, scores exactly 1 | checklist A1 | ✅ |
| Staged rubric uses real MITRE ATT&CK tactic names; weights sum 1.0 | checklist G/RB1 | ✅ |
| Evidence captured **last** (nothing newer than trajectories) | checklist A6 + ADV3 | ✅ |

> Note: V15 `F1` text cross-references `{EV3}` (isolation) and `{EV4}` (difficulty/timeout) as if separate dimensions, but the V15 CSV has only the 21 rows above (no EV3/EV4). The docs correctly fold isolation into **ADV1** (advisory) and difficulty into **EV5** — consistent with the 21-dimension set.

---

## 7. Gap list + recommended fixes (actionable)

**High value (upstream-app tasks — e.g. Cacti):**
1. **CVE enumeration step** — add a checklist item (and a `taskworkflow` P1/P2 step) for upstream-app tasks: *"Enumerate every known CVE for the pinned version; for each reachable-from-foothold CVE touching scored data/cred/privilege, confirm it is patched or structurally dead-ended (not merely credit-withheld) and recorded in `unintended_findings.json`."* → VU2/VU5.
2. **CVE-ID verification** — add: *"For every CVE ID named in task.toml / NOTICE.md / instructions / unintended_findings.json, verify at `cveawg.mitre.org/api/cve/<ID>` that vendor+product+flaw match."* → EN4/VU2. (Needs network — an attempter-sandbox or reviewer step.)
3. **Upstream attack-path hardening** — add to EN2/VU2: *"install/setup/debug paths disabled; plugin-upload / webroot-write / template-write code-execution paths removed."*
4. **Upstream IP-allowlist check** — add to EN2/EN3: *"the product's own client-IP allowlists reconciled against Docker's address ranges (no accidental allow)."*
5. **Rotate upstream defaults** — make EN3 explicit: *"every default credential the upstream product ships is rotated per boot."*

**Lower value:**
6. **Refusal-framing** — add a one-line pre-submission check (or keep as the EV5 empirical catch): *"L0–L2 phrasing is not refusal-bait."*
7. **§2.5 disambiguation clue** — make explicit in VU5: *"a clue exists that tells look-alike candidates apart"* (the Cacti task's exact weak point: 3 identical-shaped keys).
8. **Doc relabel** — headers/tags say **V13**; content tracks **V15**. Relabel "V13 → V15" across the three docs (and the dimension-map §10) so the rubric reference is current.

**All gaps are additive** — they extend the upstream-app coverage; none contradict existing rules.
