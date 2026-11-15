# PR #197 Retrospective — why each item was missed, and the step-wise check that now catches it

**Written for:** the red-team (and the boss who handed down PR #197). This is the "why did we miss it"
post-mortem for `cacti/automation-tree-rule-sqli`, mapped point-by-point to the workflow-v2 gap that let it
through, with the concrete check now wired into [`guidelines.md`](guidelines.md),
[`taskworkflow.md`](taskworkflow.md) and [`pre-submission-checklist.md`](pre-submission-checklist.md).

## The meta-lesson (the root cause behind all of it)

Our workflow was built to score the **V13 QC rubric** (21 dimensions). PR #197 is a **different failure
axis**: Harbor / Lighthouse / **Scale Sandbox infra compatibility**. These failures **pass every local run
and every rubric check, then break on the review platform** — so nothing in a rubric-shaped workflow was ever
going to catch them. We had *zero* gate for "will this actually boot on Scale Sandbox," and two of our open
"blockers" turned out to be exactly that.

Fix applied: PR #197 is now a **first-class hard gate (A7 → §N)** in the pre-submission checklist, mirrored
into the build rules (guidelines §1/§8.1) and the apply-order (taskworkflow §1/§3.3/§7 + revisit map). It is
run on **every multi-container task**, not just batch_01.

## Verdict summary

| PR197 § | Applies? | Task status | Workflow gap that let it through | Task action |
|---|---|---|---|---|
| **§1 network vs sidecar** | YES | **❌ non-compliant** | Workflow actively taught the *wrong* model (no-network + `main` on an internal bridge) | **Rewrite** compose + task.toml (needs sandbox verify) |
| **§2 tmux + asciinema** | YES | **❌ non-compliant** | Workflow said "tmux" only; never knew asciinema is co-required | **Add `asciinema`** to agent Dockerfile (safe) |
| §3 web-IP loop | NO | n/a | — | none (no candidate-IP loop) |
| §4 db entrypoint | NO | n/a | — | none (no mounted entrypoint) |
| §5 wheels fallback | NO | n/a | — | none (wheels shipped) |
| **§6 cpus** | YES | **⚠ discrepancy** | Workflow hard-coded `cpus=1.0`; §6 convention is `cpus=2` | **Confirm host** with batch owner |

---

## §1 — Network isolation vs Harbor's egress sidecar  ❌ (the big one)

**Finding.** The task would hit `docker compose up failed: service main declares mutually exclusive
network_mode and networks` on Scale Sandbox (or, under `no-network`, `main` simply cannot reach the gateway).

**Task state.**
- `environment/docker-compose.yaml`: `main` declares `networks: frontend` (:78–79); `gateway` on
  `frontend`+`backend`; both bridges `internal: true`.
- `task.toml`: `network_mode = "no-network"` in `[environment]` (:56) and `[agent]` (:70).

**Why it was missed (root cause).** This is the whole **F2/EN2 flip-flop saga** in miniature. We spent three
turns arguing the network model and *still* landed on the wrong one — because the workflow's mental model was
wrong at the source:

1. The workflow's EN2 rule said "internal siblings on `internal: true`, `main` **off** them." Correct
   instinct — but it gave **no mechanism** for how `main` then reaches the gateway it must talk to.
2. To make `main` reach the gateway we put `main` **on** the `frontend` internal net — directly contradicting
   our own EN2 rule — and rationalized it with "Harbor's no-network sidecar skips services that declare their
   own `networks:`, so `internal: true` stops NAT-out." That reasoning is about a sidecar that **skips**
   `main`; PR #197 documents the real behavior: the sidecar **attaches to** `main` (`network_mode:
   service:<sidecar>`), which a `networks:` key then **conflicts** with.
3. Our only test was the **local** sandbox, which doesn't apply the egress sidecar the way Scale Sandbox
   does — so it passed locally and we banked a false "resolved."

In short: **we were reverse-engineering Harbor's networking from behavior instead of from a spec, and our
spec (the workflow) encoded a guess that happened to work locally.** PR #197 *is* that missing spec.

**New step-wise check** (`pre-submission-checklist.md` §N1, built into guidelines §1 + taskworkflow §3.3):
1. `awk` asserts `main` has **no `networks:` key** at all.
2. Grep confirms the gateway/web sits on `default` (+ its internal backend).
3. Grep confirms `[environment]` **and** `[agent]` are `network_mode = "allowlist"` with `allowed_hosts`
   naming **only** the in-compose gateway (never an external host).
4. `[LIVE]` on a sidecar-applying boot: `main` reaches the gateway and **nothing external** (EN2 holds).
5. Single-container exception is explicit: `no-network` is allowed only when `main` needs no sibling.

**Task remediation (recommended — needs one live sandbox confirmation of `allowed_hosts` semantics):**
```yaml
# docker-compose.yaml
  gateway:
    networks:
      default:          # was: frontend
      backend:
  main:
    # DELETE the `networks:` key entirely (remove `networks: frontend`)
networks:
  backend:
    driver: bridge
    internal: true
  # DELETE the frontend bridge (now unused)
```
```toml
# task.toml
[environment]
network_mode = "allowlist"
allowed_hosts = ["gateway"]
[agent]
network_mode = "allowlist"
allowed_hosts = ["gateway"]
```
> **Open item to verify on the sandbox before committing:** whether the in-compose gateway must be listed in
> `allowed_hosts` or is reached via the shared sidecar netns on `default` regardless, and that no external
> egress opens up (re-run the EN2 litellm/DNS-fails-externally probe). This reverses the earlier
> `internal:true` + `no-network` decision — which is *correct*, because PR #197 postdates and overrides it.

---

## §2 — tmux + asciinema in the agent image  ❌ (this is why pass@5 never produced trials)

**Finding.** The agent Dockerfile installs `tmux` but **not `asciinema`**. terminus-2 records the tmux
session with asciinema; without it every pass@k trial errors before turn 1 — which we had been reading as
"pass@5 is the remaining blocker / trajectories absent." The trajectories were absent **because of this.**

**Task state.** `environment/agent/Dockerfile:5`: `curl dnsutils jq tmux procps ca-certificates` — no
`asciinema` anywhere in the task.

**Why it was missed (root cause).** The workflow knew **half** the requirement. guidelines §9 and the F1 note
both said *"missing `tmux` → every pass@k trial errors before turn 1"* — correct symptom, **incomplete
cause**. We treated `tmux` as the whole story, so a tmux-present image looked compliant while asciinema (the
*recorder* terminus-2 invokes) was silently absent. We never live-verified `which asciinema` in the built
image, only `which tmux`.

**New step-wise check** (`pre-submission-checklist.md` §N2, guidelines §9/§2.2, taskworkflow §7):
1. `grep -c tmux` and `grep -c asciinema` the agent Dockerfile — **both** ≥ 1.
2. `[LIVE]` `docker compose run --rm main sh -lc 'which tmux && which asciinema'`.
3. The F1 "0 pass@k trials" note now names **both** tmux and asciinema as the provisioning cause.

**Task remediation (safe, unambiguous):**
```dockerfile
# environment/agent/Dockerfile:5
    curl dnsutils jq tmux asciinema procps ca-certificates && \
```
(Build-time apt has network, so this resolves cleanly on bookworm; for a `network: none` build, vendor the
`asciinema` + `python3-pkg-resources` `.deb`s and `dpkg -i`.)

---

## §6 — cpus declared  ⚠ (a genuine conflict, not a clean miss)

**Finding.** `task.toml` declares `cpus = 1.0`. PR #197 §6 names `cpus = 2` the batch_01 convention.

**Task state.** `task.toml:59` `cpus = 1.0` (declared — the hard requirement "don't omit it" **is** met).

**Why it's not a simple miss.** Two authoritative sources genuinely disagree, and only the batch owner knows
which host is authoritative for this task:
- **PR #197 §6:** `cpus = 2` (Lighthouse pre-flight convention).
- **Our live finding (2026-11-05):** `cpus = 2.0` killed **all 5** trials on a 1-CPU sandbox
  (`range of CPUs is from 0.01 to 1.00`); `cpus = 1.0` boots anywhere.

The workflow previously hard-coded `cpus = 1.0` as settled truth, which would now silently violate the §6
convention; PR #197 would have us set `2`, which our own live evidence says breaks a 1-CPU host.

**New step-wise check** (`pre-submission-checklist.md` §N6, guidelines §8.1): `cpus` must be **present**; the
**value is flagged as a decision requiring the batch owner's confirmation of the target host's CPU count** —
the workflow no longer asserts either value as correct. Plus: a `main` compose `cpus:`/`mem_limit:`/
`pids_limit:` shorthand must equal Harbor's injected `deploy.resources.limits.*` or be removed.

**Task action:** **confirm with the batch owner** whether this task runs on a ≥2-CPU host (→ `cpus = 2`) or
can land on a 1-CPU sandbox (→ keep `1.0`). Do not change blindly.

---

## §3 / §4 / §5 — confirmed not applicable (recorded so the next audit can skip fast)

- **§3 web-IP loop** — n/a: `main`'s compose command curls `gateway` by **hostname**; there is no
  candidate-IP picking loop (`grep -E 'WEB_IP|for ip in|/vchan/.*_ip'` empty).
- **§4 db entrypoint exec bit** — n/a: no service mounts a custom bare-path entrypoint script
  (`grep entrypoint:` empty); `cacti`/`canary-init` build their own, `operator-init` uses `command:`.
- **§5 rewardkit wheels fallback** — n/a: `environment/agent/vendor-wheels/*.whl` ship in the bundle, so the
  classic-builder empty-`COPY` failure can't occur.

---

## What to do next (task-side)

1. **Apply §2 asciinema** — safe, and it unblocks pass@5. (One-line Dockerfile edit above.)
2. **Decide §1** — apply the network rewrite above, then **re-run oracle/noop on the sandbox** to confirm
   `allowed_hosts` semantics and that EN2 still holds (no external egress). This is the one that needs a live
   check, not a dev-box check.
3. **Confirm §6 cpus** with the batch owner (1.0 vs 2), then set accordingly.
4. Re-run the full `pre-submission-checklist.md` — **A7/§N is now part of it** — and only then re-attempt
   pass@5.
