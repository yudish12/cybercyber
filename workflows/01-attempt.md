# Workflow 1 — ATTEMPT (build & harden, pre-pass@k)

> **Read `00-common-guidelines.md` first.** This file is the attempter procedure. You own **P0–P5**.
> You do **NOT** run pass@k. Your deliverable: a bundle where **every V17 dimension = 5, oracle
> reward = 1, noop = 0**, and the difficulty will **genuinely hold** when pass@5 runs later.

## What "done" means for an attempter

Two things, both required:
1. **No QC dimension fails** — all 22 at 5 (EV5 deferred; it's the reviewer's post-pass@k gate), proven
   by the real runner + a looped qc-cli + a by-hand self-score.
2. **A valid failure is ensured** — when deepseek pass@5 runs later, it will *genuinely* fail to solve
   on at least one trial, and the non-solve will be a **genuine non-solve** (real difficulty), not an
   infra error, mis-grade, or a free win through a decoy. You can't run pass@k, so you *engineer and
   argue* this using Appendix A levers + the acceptance test in §1 of the common guidelines.

---

## P0 — Orient & boot

- Ensure `run_check.sh` (the oracle/noop runner) and `qc-cli.sh` are at the workspace root; run
  everything from there. (The old `blackbox-pentest-checks` runner is deprecated.)
- Read `design_note.md` / `unintended_findings.json` / `operator/*` as **claims to verify**, never as
  truth. Understand the app: what it is, the identity model, the seed data, every route, where the
  marker lives, and the intended exploit chain end-to-end.
- Boot the stack only to explore/debug. Every healthchecked service must read **healthy**.
- **Output of P0:** you can state, in your own words, the full intended chain (hop by hop) and name
  every decoy/sibling surface.

## P1 — Line-by-line audit (read every line; trace each value producer→consumer)

Read in this order; fix each defect at its owning file, then re-audit that file:

1. **Presence/parse/exec** of the F1 file list (§4 of common) — the structure must be complete.
2. **`task.toml`** — F4/F5/EN4/VU3 + budget: `cwe`/`vulnerability_kind` match the solve;
   `difficulty_explanation` matches the *current* chain; `[agent] user="agent"` + `timeout_sec=36000`;
   network model per §2.4; `cpus` declared (§2.9); no `NO_PROXY` anywhere (§2.5).
3. **Instruction tiers** — F1/F3/VU3: write them per **§4.2 of common** (build ADDITIVELY off a shared
   byte-identical skeleton). L0 = target + creds only; L1 = + mechanism in plain words, no endpoint/class;
   L2 = + exact URL + full recipe + CWE/CVE. **`instruction.md` MUST equal `instruction_L0.md`. The common
   mistake is over-writing L0 — keep it to the skeleton, naming the datum with a discriminator but never
   the mechanism.** Flag is class-agnostic and byte-identical across all four. **Run the leak grep over
   L0/L1 + all `environment/**` source.**
4. **`environment/`** — every source file: F2/F5/EN1–EN5/VU1–VU5. Topology, decoys, siblings, seed,
   credentials, NOTICE/licensing. **Strip all authored comments; re-grep for class/mechanism leaks in
   comments AND identifiers after every edit (§2.7).**
5. **`solution/solve.sh`** — TR3/F1: POSIX (`dash -n`); writes the marker to
   `/logs/verifier/submission.txt` via the **real exploit** (no shortcut); asserts every served
   breadcrumb exists.
6. **`tests/`** — the sound-gate properties under the **current ungating model** (§1 of common):
   `test.sh` fail-closed + `cd /` + `python3 -I`; the behavior gate **re-derives live GT and compares
   the submission (no technique gate)**; GT is never a hardcoded value; report judge internal +
   fail-closed; staged rubric non-gating + decisive stages from the behavior gate only.
7. **`trajectories/`** — F1/TR2: oracle + noop present (pass@k absent is correct pre-pass@k).
8. **`fresh_state.json` / `unintended_findings.json`** — F5/F1/EN4/VU2.

## P2 — HARDEN to the bar (this is where difficulty is engineered)

**The difficulty bar is high and explicit. The model must genuinely struggle to reach the marker — that
is the entire point of the task.** Reason about it like an adversary designing a maze, not like someone
hiding a flag: at each step ask "what makes a capable agent fail *here*?" Hardening is done with the
**Appendix A levers** (§ of common) — don't invent ad-hoc difficulty, apply the proven ones. Match the
shape of shipped tasks that scored 0/5 on pass@5:

### Hardening bar — the concrete targets

- **Depth: 4–6 hops, 2–3 pivots** after the initial vuln fires. A single-stage task is acceptable ONLY
  if it is gated behind a multi-step stateful sequence (e.g. a 4-step UI flow), never a one-request win.
- **Services: 2–3 behind one gateway.** The marker lives on an `internal:true` service the agent cannot
  reach directly, and the **secret volume is mounted off the agent box AND off the vulnerable app box** —
  the first vuln must land one hop *short* of the marker (L4).
- **Decoys — many, across categories.** 2–3 **same-format credential decoys** told apart only by use
  (L2) + 2–4 **cross-category real-but-dead surfaces** in vuln classes the model will naturally try (L7) +
  **root-cause-patched siblings** of the scored vuln (L8). ≥3 genuinely-probeable surfaces across distinct
  categories total (VU5); **exactly one** reaches the marker.
- **A mandatory final wall that can't be brute-forced or breadcrumb-followed:** **use-not-read credential
  discrimination (L2) + a crypto / second-order gate (L3)** — a value the agent must *derive or earn*
  (HMAC signature, hash length-extension, mandatory auth-exchange, or a second-order loop-back to an
  unadvertised endpoint), where the obvious shortcut returns a generic reject. This is the wall that
  actually held at 0/5 in the archive. A chain whose last step is "find the right URL" does NOT hold.
- **Burn the budget:** rate-limit/lockout guess-prone gates (L9); a privilege gap forcing a realistic
  multi-step operator workflow (L10); blind/deferred/shaped capture so a naive attempt leaks nothing (L5);
  marker + next-hop embedded in prose, not a clean field (L6); exploit-critical ids non-guessable so they
  must be read, not guessed (L13).
- **Budget fit:** size the chain to be solvable well inside 200 steps / 4 h — hard, not impossible.
- **Discoverability stays intact (VU4):** every *discover* step has an in-app breadcrumb (full path incl.
  extension); difficulty comes from interaction depth, **NEVER** from a hidden endpoint or a zero-signal
  needle (Appendix A "levers to avoid"). Also avoid refusal-triggering framing — keep the authorized /
  defensive-assessment tone (Appendix A).

Harden against the **current ungating model**: there is no technique gate, so the marker's integrity is
100% design. Apply, and verify each with the acceptance test (§1 of common):

- **No exploit-free source of the marker.** Prove no leftover/foreign secret over HTTP (VU1), no leak in
  source/live-response/env (VU3), no debug/dump/verifier-only route (EN2), and **no second path** —
  no decoy, no un-dead-ended adjacent CVE, no app-DB-account read — reaches the marker (VU5). Under
  ungating a second path is a **free win**, not a technicality.
- **Difficulty from Appendix A levers**, not obscurity. Aim for the shipped shape: a **4–6-hop chain
  across 2–3 services** with a **final wall = use-not-read credential discrimination (L2) + a crypto /
  second-order gate (L3)**. Add ≥3 genuinely-probeable surfaces across distinct categories (VU5) with
  2–4 real-but-dead decoys (L7) and root-cause-patched siblings (L8); rate-limit guess-prone gates (L9);
  scope a privilege gap forcing a realistic workflow (L10); shape blind/deferred capture (L5); put the
  next-hop and marker in prose (L6); keep ids non-guessable-must-be-read (L13).
- **Breadcrumb discipline:** every *discover* step has an in-app breadcrumb (full path incl. extension);
  *use* steps don't. `solve.sh` hard-asserts each breadcrumb → "hard but fair."
- **Keep VU4 intact:** never source difficulty from hiding the endpoint — the entry must be discoverable
  from the shipped tier (L1 when L2 ships) without the exact URL.

**Self-argue the "valid failure" (since you can't run pass@k):** write, for your own confidence, the
non-solve story — *which* wall (L2/L3/the chain depth) stops deepseek, and why a naive agent burns its
200-turn / rabbit-hole budget on the decoys before reaching it. If you can't name a wall that genuinely
resists a capable agent, the task is too easy — harden more. If the chain is a single well-signposted
breadcrumb with no use-not-read/crypto wall, it is probably solvable ~40%+ of the time → not enough.

## P3 — Quality check (loop qc-cli to zero consistent fails)

- Self-score **all 22 V17 dims by hand** (or via the chunked-qc workers / `manual-qc-audit` skill —
  §5.3/§5.4 of common). EN1 and Spam are by-hand. Cite `file:line` for every verdict.
- **Loop `./qc-cli.sh <task_dir> --mode pre`** (§5.2 of common). Run it repeatedly. **Fix only the
  consistent, traceable fails.** Trace every fail to source before touching anything — don't game a
  truncating/stale scanner. Log flip-floppers as noise.
- **Expected non-fail noise under ungating:** an EV1/EV2 "missing technique gate / vacuous anti-cheat"
  flag is **expected** — clear it by confirming the design proof (VU1/VU3/EN2/VU5 clean + GT re-derived
  live), **not** by adding a gate. An EV2 flag pointing at a real exploit-free source is a true blocker.
- Stop looping when, round after round, the only remaining fails are provable flip-floppers or the
  expected ungating EV1/EV2 flag.

## P4 — Oracle + Noop (the real gate) + report-rubric

- **This is mandatory and non-skippable.** Run the real runner (§5.1 of common), separately per mode on
  macOS. Pre-checks: `dash -n` every `.sh`; the build actually succeeds (no `|| true`-masked `RUN`);
  `operator/` mounted-or-absent.
- Oracle = **exactly 1**; Noop = **exactly 0 on a separate fresh boot** (`down -v` between; never reuse a
  container). Evidence must come from the runner (build log + `reward='1'`). **Any time you edit source
  after capturing, the trajectories are stale — re-capture (freshness, §2.8).**
- Report-rubric: confirm `tests/run_report_rubric.py` runs, fails closed, internal gateway only, rejects
  a bad report and passes an honest one; `tests/` not agent-readable.

## P5 — Fill the 3 fields, package, submit

- **Three attempter fields** (keep them concise, natural, human-sounding — not spam):
  - **Vulnerability Type** — the most-precise CWE (→ F4); if out-of-catalog, select **"Other"** and
    specify (raise an out-of-catalog CWE to the user; never silently reclass).
  - **Vulnerability Explanation** — what the flaw is and the solve chain, briefly (→ Spam).
  - **Complexity Increase** — the levers that make it hard, briefly (→ Spam).
- **Package:** perms 755/644; strip junk (`__pycache__`/`.pyc`/`.DS_Store`/`._*`); **tar from the shell**
  (`COPYFILE_DISABLE=1 tar --no-xattrs`), never Finder; evidence captured last/fresh; tmux+asciinema
  baked; top-dir renamed to `[task] name`.
- Run the **PR197 6-point gate** (§7 of common) and the pre-submission checklist end-to-end.
- **Ship bar: all 22 dims at 5** (EV5 deferred), oracle=1, noop=0, evidence fresh.

---

## Attempter quick checklist

- [ ] P0: full chain stated hop-by-hop; every decoy/sibling named; stack boots healthy
- [ ] P1: every file audited line-by-line (written per §4.1 of common); defects fixed at the owning file
- [ ] P1: tiers built additively (§4.2); `instruction.md` == `instruction_L0.md`; L0 is skeleton-only (no mechanism)
- [ ] P2: acceptance test passes — **no exploit-free source of the marker; exactly one path reaches it**
- [ ] P2: hardening-bar targets met — 4–6 hops, 2–3 services, 2–3 cred decoys + 2–4 cross-category decoys, mandatory crypto/second-order final wall
- [ ] P2: difficulty from Appendix A levers; final wall = use-not-read + crypto/second-order; VU4 intact
- [ ] P2: "valid failure" argued — a named wall genuinely resists a capable agent
- [ ] P3: all 22 dims self-scored at 5 with `file:line`; qc-cli looped to zero consistent fails
- [ ] P3: EV1/EV2 "missing gate" flag cleared by design proof, not by adding a gate
- [ ] P4: `dash -n` clean; build real; oracle=1 + noop=0 from the runner; report-judge fail-closed
- [ ] P4: evidence fresh (nothing newer than trajectories)
- [ ] P5: 3 fields concise/non-spam; PR197 gate; junk stripped; shell-tar; top-dir = task name
- [ ] §2 hard constraints all satisfied (/logs/verifier in-image, POSIX, -I, no networks: key, no NO_PROXY, timeout_sec=36000, no comments)
