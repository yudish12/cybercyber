# Workflow 2 — L0 REVIEW (pre-pass@k audit of a previous attempter's bundle)

> **Read `00-common-guidelines.md` first.** You are reviewing a bundle a **previous attempter**
> submitted, **before pass@k runs**. Assume they made mistakes. You **fix by hand, never send back,
> never let the sandbox Claude edit the task**, and **never run pass@k** (it runs automatically after).
> **EV5 is deferred on this review** (not scored, not failed).
>
> Your deliverable: (a) a 22-dimension check with `file:line` citations, (b) an **Overall Quality 1–5
> as-received** score + Failure Reason, (c) a **fixed task** with every dimension (except EV5) at 5 and
> evidence re-verified, and (d) a short review log. Above all: when pass@5 runs on your fixed version,
> **it must produce fair, clean trials with no TR / infra failures and a meaningful difficulty result.**

---

## R1 — FIRST, judge the hardening bar & levers (difficulty reasoning, before QC)

Before any dimension-by-dimension checking, **reason about whether this task can actually fail a capable
agent.** Walk the intended path end-to-end and answer, in writing:

- **How many hops, across how many services?** (Target shape: 4–6 hops, 2–3 services. A 1–2 hop,
  single-well-signposted-breadcrumb chain is solvable ~40%+ — too easy.)
- **What is the final wall, and does it genuinely resist?** Map it to Appendix A. The reliable walls are
  **L2 use-not-read credential discrimination** and **L3 crypto / second-order gates** — a value the
  agent must *derive or earn*, not read or guess, where the obvious shortcut returns a generic reject.
  If the "wall" is just "find the right URL," it does not hold.
- **Are the levers actually applied, or cosmetic?** Check each claimed decoy is *genuinely probeable and
  hardened* (not an instant-404 stub — a stub is VU5 Non-Fail=3), siblings are root-cause-patched (L8),
  guess-prone gates are rate-limited (L9), the privilege gap forces a real workflow (L10), blind/deferred
  capture must be shaped (L5).
- **Will a naive agent burn its budget before the marker?** Enough cross-category decoys (L7) in
  categories the agent will naturally try, so the 200-turn budget is spent on dead ends.
- **Under ungating (§1 of common): is there exactly ONE path to the marker?** Any second path — a decoy
  that reaches it, an un-dead-ended adjacent CVE, the app's own DB account reading the scored table — is
  now a **free win that collapses difficulty to 5/5.** This is the single most important difficulty check.
- **VU4 intact?** Difficulty must come from interaction depth, not a hidden endpoint.

**Verdict of R1:** either "difficulty holds — a named wall genuinely resists" (with the wall named), or
"too easy — harden X" (and you fix it, by hand, applying Appendix A). Do not proceed to R3 believing a
task is hard that isn't.

## R2 — Context, no-vuln-change, and realism guards

- **Agent is loaded with correct context.** The foothold the agent starts with resolves (L0 creds work),
  the goal is stated, the flag format is class-agnostic and identical across tiers, and the live foothold
  response (e.g. `GET /api/credentials`) discloses **nothing beyond the shipped tier** — no class, no
  mechanism, no exact endpoint, no victim identity (VU3 live-response leak). The tiers are monotonic.
- **Tiers built correctly (§4.2 of common).** Confirm `instruction.md` is byte-identical to
  `instruction_L0.md` (a shipped task once leaked by shipping `instruction.md` == L1), **L0 is skeleton-only
  with no mechanism**, L1 adds only a mechanism paragraph (no endpoint/class), and L2 adds the recipe +
  CWE/CVE. An over-written L0 is a real VU3 defect — fix it by trimming L0 back to the skeleton.
- **Do NOT change the vulnerability.** The assigned vuln class / CWE is fixed. You harden, reshape decoys,
  fix the verifier, deepen the chain — but you **never swap the planted flaw for a different one.** If the
  CWE is wrong/out-of-catalog, that's an F4 finding to **raise**, not a license to reclass the exploit.
- **Realism (EN1).** The substrate must be a real, substantial multi-module app with structural depth
  beyond the exploit path, realistic seed data, and a coherent identity model — judge the *substrate*, not
  the planted vuln or the grader. A thin single-file app fails even with a perfect exploit.

## R3 — Audit every V17 dimension (manual, `file:line`) + loop qc-cli

**Ensure each and every one of the 22 rubric dimensions** (`qc-spec-v17.md` / the source CSV). Read the
decision-relevant files **line by line**; cite `file:line`; fail closed on anything not positively proven.

- Static read order (fixed): `task.toml` → `instruction.md`/L0/L1/L2 → `solve.sh` →
  `test.sh`/behavior/stages/isolation → `docker-compose.yaml` → env + sibling source → `trajectories/` →
  the Outlier form. Audit each file against the **§4.1** "how to write each file right" conventions and the
  tiers against **§4.2**. Run the three greps: class-term leak (over L0/L1 + **all** `environment/**` incl.
  identifiers), prefixed-secret-over-HTTP, and `find <task> -newer trajectories/oracle/reward.txt`.
- Use the **chunked-qc workers** (§5.3 of common) for fenced per-dimension coverage, and **loop
  `./qc-cli.sh <task_dir> --mode pre`** (§5.2): run repeatedly, fix only consistent traceable fails, log
  flip-floppers as noise, trace every judge fail to source before touching anything.
- **Apply the ungating reinterpretation (§1 of common) on EV1/EV2/behavior/RB1/EV5.** An EV1/EV2 "missing
  technique gate" flag is **expected** — clear it with the design proof (VU1/VU3/EN2/VU5 clean + GT
  re-derived live), not by adding a gate. An EV2 flag at a real exploit-free source is a **true blocker**.
- Each dimension: **PASS (5) / FAIL (2)** (F4 and VU5 can also be **3**, which still blocks ship). List
  every error category a finding hits. Fix each defect **at its owning file, by hand**, then re-audit that
  file. Remember the behavior-change ripple: an endpoint/recipe change touches all 3 tiers + task.toml +
  solve.sh + app source + operator catalog/report-rubric + unintended_findings + fresh_state — reconcile
  all in one pass.

## R4 — Re-run oracle + noop (accept only from the real runner)

- Re-run both via `./run_check.sh <task_dir> --mode oracle|noop` (§5.1 of common), separately
  per mode on macOS, each on its own fresh boot with `down -v` between; never reuse a container.
- **Accept a shipped oracle only if** all five conditions hold **and** the log proves it came from the
  real runner (build log + `reward='1' (expected '1')`). A hand-written `reward.txt`, a 0-byte `test.log`,
  or a non-building image = **fabricated = Overall Quality 1.** Pre-checks: `dash -n` all scripts; build
  truly succeeds; `operator/` mounted-or-absent.
- Oracle = exactly 1, Noop = exactly 0. Any source edit you made in R1–R3 **invalidates the shipped
  evidence → re-capture it** (freshness, §2.8).

## R5 — Guarantee the pass@k run will be fair & clean (no TR / infra failures)

This is the point of a pre-pass@k review: when pass@5 runs automatically on your fixed version, it must
produce **fair trials and a meaningful result**, not infra noise or mis-grades. Confirm:

- **Infra will not error every trial (PR197 6-point gate, §7 of common):** `main` has no `networks:` key
  and uses allowlist+allowed_hosts; **tmux AND asciinema** are baked (else every trial aborts before turn
  1); the web-IP discovery loop requires `curl` exit 0; DB entrypoint is `[/bin/sh, …]`; rewardkit wheels
  shipped; `cpus` declared and sane for the host.
- **TR2 holds:** a fresh no-op boot scores exactly 0 (separate boot, empty disclosure log).
- **TR3 holds:** `solve.sh` recovers the marker via the **real exploit** and writes the file `test.sh`
  reads — POSIX-clean (`dash -n`), no shortcut. This is what makes a *solve* trial legible.
- **No mis-grade:** the verifier is sound under ungating — re-derives live GT, compares the submission,
  fail-closed, retry budget ≥ agent, marker survives a restart. A gate that would under-credit a genuine
  solve (over-specific binding) is a defect to fix now, so EV5 isn't polluted by false non-solves.
- **Determinism & freshness:** fresh security-relevant state per boot (replay fails); nothing newer than
  the trajectories.

If any of these is off, the pass@k trials would be unfair or uninterpretable — **fix it before the task
goes forward.**

## R6 — Score, fix-loop, log, sign off

- **Overall Quality (as-received), decision order:** check for **1** first (fabricated/non-building oracle,
  or a validity hole making the task unsound); else any failing criterion → **2**; else an F4/VU5 at 3 or
  a substantive edit needed → **3**; else cosmetic-only → **4**; else **5**.
- **Fix loop:** find → fix **by hand** → re-verify (re-run the owning check / re-capture evidence) → log.
  Repeat until every dimension except EV5 is at 5.
- **Review log (4 lines per fix):** Where / Which check / Before→After / Re-verified.
- **Sign-off:** all 22 (minus EV5) at 5; oracle=1 + noop=0 from the runner; evidence fresh; PR197 gate
  confirmed; difficulty verdict from R1 recorded. EV5 + the Model Failure Reason are the post-pass@k job.

---

## L0 reviewer quick checklist

- [ ] R1: chain walked hop-by-hop; final wall named (L2/L3) and genuinely resists; difficulty verdict written
- [ ] R1: **exactly one path to the marker** — no decoy / adjacent CVE / app-DB-account second path (free win)
- [ ] R2: agent context correct (creds resolve, tiers monotonic, no live-response leak); vuln class unchanged; EN1 realism holds
- [ ] R3: all 22 dims audited `file:line`; qc-cli looped; EV1/EV2 "missing gate" cleared by design proof
- [ ] R3: fixes made by hand at the owning file; behavior-change ripple reconciled across all ~8 artifacts
- [ ] R4: oracle=1 + noop=0 re-run from the real runner; evidence re-captured after your edits (fresh)
- [ ] R5: PR197 gate green; TR2=0, TR3 real+POSIX; verifier sound (no mis-grade); deterministic
- [ ] R6: Overall Quality scored as-received; fix-loop closed; review log written; EV5 deferred
