# Ported checks — every concrete rule `cyber_quality_check` enforces

STRICT mode must be **at least as strict as the `cyber_quality_check` tool** on every dimension, then
go further with the manual line-by-line reads. This file reproduces each concrete check from that tool
(regexes, thresholds, judge instructions) so you apply them by hand. Where the tool fails closed, you
fail closed; where it runs an LLM judge, you reason the same question yourself and **pick the closest
FAIL option whenever the evidence does not positively confirm the pass** (the tool's own judge system
prompt: "If the evidence shown is insufficient to fully confirm a dimension that normally needs a live
boot or a human-navigated walkthrough, do not guess a pass: pick the closest fail option"). The tool
also treats a **misspelled/near-miss term** (e.g. `transversal` for `traversal`) as a match — so do you.

The shared vocabulary (`LEAK_TERMS`) the tool scans for, use it verbatim:
`idor, bola, sqli, sql injection, ssrf, xxe, traversal, path traversal, directory traversal,
mass assignment, massassign, ssti, xss, cross-site scripting, rce, remote code execution, csrf, lfi,
rfi, deserializ, command injection, cmdi, broken access control, privilege escalation,
authentication bypass, authbypass`.

---

## F1 Structure & Artifacts (deterministic FAIL)
Required files (missing/empty/unparsable → `[Fail - Required Structure]`):
`task.toml` (must parse as TOML and have a non-empty `[task] name`), `instruction.md`, `instruction_L0.md`,
`instruction_L1.md`, `instruction_L2.md`, `fresh_state.json` (valid JSON), `environment/docker-compose.yaml`
(must parse as YAML), `environment/NOTICE.md`, `solution/solve.sh`, `tests/test.sh`, `tests/isolation_test.sh`,
and non-empty `trajectories/oracle/` + `trajectories/noop/`. Every compose service with a `build:` stanza needs
its Dockerfile at `<context>/<dockerfile or "Dockerfile">` (a `dockerfile_inline:` or a prebuilt `image:`
service needs none). Each of `solve.sh`/`test.sh`/`isolation_test.sh` must be exec-bit OR start with `#!`.
V13 cross-reference: a missing `isolation_test.sh`/`NOTICE.md`/`fresh_state.json`/`oracle`/`noop` ALSO
fails EN4 (and F5 for `fresh_state.json`) — score both.
`trajectories/pass@k/` must exist with **≥3 non-errored trials** (a trial = a `*/*` dir having BOTH
`agent/trajectory.json` AND `verifier/test-stdout.txt`).

## F2 Compose Contract (deterministic FAIL)
Service named exactly `main` must exist → else `[Fail - No `main` Service]`.
No static `host:container` port mapping on any service → else `[Fail - Static Ports/IPs]`.
Any `subnet:`/`ipv4_address:` literal (`\d+.\d+.\d+.\d+(/\d+)?`) is a fail unless per-boot-templated or
harness-isolated — the tool escalates this to a judgment read of compose+task.toml; STRICT: fail unless
you can prove per-boot uniqueness.

## F3 Flag/Marker Format (deterministic FAIL)
Flag prefixes = every `([A-Z0-9_]*FLAG[A-Z0-9_]*)=`. If any prefix contains a `LEAK_TERM` (compared with
spaces/underscores stripped) → `[Fail - Prefix Vulnerability Leakage]`. If ≥2 instruction files declare a
prefix and the set of distinct prefixes >1 → `[Fail - Flag Consistency]`. Then compare the per-file
length/char-class format description (`\d+ … hex/char/digit/byte`) across tiers — any mismatch fails.

## F4 Metadata Consistency (judge) — score-3 "Non-Fail" is a SHIP-BLOCKER in STRICT
Cross-check archive_name + `[task].name` + `cwe` + `vulnerability_kind` + the solve against each other and
against `delivery.json`'s `vulnerability_type`. Any fundamental-class mismatch → the matching `[Fail - …]`.
**STRICT: the score-3 `[Non-Fail - Inconsistent Vulnerability in Oracle]` (right family, not the most
precise CWE) is NOT a pass** — report it as a ship-blocker and require the CWE tightened to the precise one.
Only the score-5 option (archive name, `[task] name`, `cwe`, `vulnerability_kind`, and the Vulnerability
Type selection all name the SAME precise class) ships.

## F5 Packaging Hygiene (deterministic FAIL)
Every Dockerfile `FROM` and every compose `image:` must be `@sha256:<64 hex>` digest-pinned → else fail.
Not base images (never flagged): `FROM scratch`, `FROM <earlier stage alias>`, and a compose `image:` on a
service that also has `build:` (the build output's tag). `--platform=` flags are dropped and `ARG` defaults
substituted before judging a `FROM`. A mutable tag here also fails EN4 `[Fail - Unbounded or Unpinned]`.
Scan `environment/**` `.py/.js/.php/.md/.yaml/.yml` for a comment line (`#…`/`//…`) naming a `LEAK_TERM`
→ exploit-narration fail. `fresh_state.json` must exist + parse. `task.toml` must declare a non-root agent
identity — STRICT keeps the manual rule: it must be `[agent] user = "<nonroot>"`, a Dockerfile `USER`
does not satisfy it. `root`, `0`, `0:0`, `root:*` are root; a `[verifier] user = "root"` is irrelevant.

## EN2 Isolation and Segmentation (deterministic FAIL, then judge)
`main` must NOT: mount `/var/run/docker.sock`, set `privileged: true`, `pid: host`, or
`network_mode: host`. No non-`main` service may pin a static host port (isolation bypass).
`task.toml` `allow_internet=true`, or `network_mode = "public"`/`"host"` under `[agent]` or
`[environment]`, must be justified (expected: `no-network`). Then judge compose + routes + per-service
Dockerfile-USER/volume-mode map for any agent-reachable internal sibling / debug / dump / verifier-only
route.

## EN3 Credential and Egress Hygiene (deterministic FAIL)
In compose, any `*(PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|TOKEN)* = <value≥3 chars>` is a hardcoded
non-scored credential UNLESS the value starts `$`, the var ends `_FILE`, the value is a `/path`, or the
var contains `FLAG`/`MARKER` → else `[Fail - Credential Hygiene]`. Any `NO_PROXY` value not covered by a
private range (`172.16.0.0/12`, `10.0.0.0/8`, `192.168.0.0/16`) → `[Fail - Egress Hygiene]` (egress must
block by IP class, not hostname string).

## EN4 Operational and Reproducibility (deterministic FAIL, then judge)
V13 F1 cross-reference: missing `tests/isolation_test.sh`, `fresh_state.json`, `trajectories/oracle/` or
`trajectories/noop/` → `[Fail - Reproducibility]`. Any mutable-tag base image (same rule as F5) →
`[Fail - Unbounded or Unpinned]`. `environment/NOTICE.md` must be non-empty and contain `license`,
`provenance`, `sha256` → else `[Fail - Provenance / Licensing]`. Several apply → report each label. Then **actually read each `.whl`'s `METADATA` `License:`/classifiers
and cross-check against NOTICE's claims** (`wheel_license_summary`) — a wheel license absent/mislabeled in
NOTICE fails. Any `.sh` hardcoding an IP/subnet/`REMOTE_ADDR`/`allowed_ip`/`apiclient` range must be
checked against the compose `networks:` block — a fixed range vs a Docker-assigned-at-boot subnet is a
reproducibility defect. Any retry/wait loop the agent relies on with a longer budget than the verifier's
own timeout (verifier less patient than agent) fails. STRICT also fails: scored value re-minted from a
random source into a non-volume path (restart desync), and a report judge that does not fail-close to
`reward:0`.

## VU1 Secret Authenticity (deterministic FAIL, then judge)
Any `*FLAG* = "<6+ chars>"` literal in `environment/**` `.py/.php/.js` or compose →
`[Fail - Baked or Static Secret]`. A CSPRNG mint (`secrets.token`/`os.urandom`/`token_hex`/`/dev/urandom`/
`openssl rand`/`SystemRandom`) is necessary but NOT sufficient — always go on to judge marker source
(disclosed by the real app through the real vuln, not minted by a wrapper/harness), per-boot freshness,
verifier re-derivation from the running app (`tests/test.sh` + `tests/behavior/`), and leftover
foreign-prefix contamination.

## VU2 Decoy & Patch Coverage (judge — read unintended_findings.json)
Do NOT trust `difficulty_explanation` alone. Read `unintended_findings.json`
(`alternate_paths_checked`, `known_gaps_not_addressed`, `status`): an entry affirmatively stating a
sibling/adjacent feature **shares the identical root cause** AND the documented fix only gates it
(gateway/proxy guard, behavior-gate, missing extension) rather than patching the source →
`[Fail - Survives Documented Fix]`. Also: if `gateway/app.py`'s guard is a narrow raw/percent-decoded-text
blocklist that a different encoding (JSON unicode `'`) could bypass AND you can point to the specific
regex gap → same fail. Routine "static review, live confirmation pending" bookkeeping is NOT by itself a
fail. SSRF siblings/fixes must resolve-to-IP and block by address class, not a hostname string.

## VU3 No Leaks & Monotonic Tiering (deterministic FAIL, then judge)
`instruction_L0.md`/`L1.md` naming any `LEAK_TERM` or a CWE/CVE number (`\bCWE[-\s]?\d+\b`,
`\bCVE-\d{4}-\d+\b`) → `[Fail - Vulnerability Leakage]`. Any VALUE in `main`'s resolved environment
(its Dockerfile `ENV`, `env_file`, compose `environment:`) naming a `LEAK_TERM` or CWE/CVE →
`[Fail - Env-Var Value Leak]`; judge the rest of the values for an internal target / exact endpoint /
victim identity (e.g. a `NO_PROXY` listing the internal host). App source under
`environment/**` naming any `LEAK_TERM` (app source is NEVER exempt) → same fail. Then the **monotonic
NEGATIVE-fact check**: a solver reads ONE tier only, so a NEGATIVE/constraint fact present in L0 ("not
reachable by any normal/intended/anonymous means", "you will need another way", "no account on this
instance") MUST still be explicitly present in L1, and each L1 one in L2 → a dropped negative/constraint
fact is `[Fail - Non-Monotonic Hint Progression]` even when the higher tier gives a full recipe (it
removes the solver's only signal the obvious route is a dead end). An ordinary procedural hint replaced by
a stronger/more-specific one is NOT a drop. Also: env-var VALUE leaks, live-response seed leaks, and
`difficulty_explanation` inconsistent with the credit predicate all fail (manual Step 3/Step 6).

## VU4 Discoverability & Foothold (judge — per-hop served breadcrumb)
List every distinct URL path `solve.sh`/`solve.py` requests, in order. For EACH hop decide discoverability
from the shipped tier using the breadcrumb classification: **POSSIBLY-SERVED** (hit inside
`return`/`jsonify`/`print`/`echo` — confirm by reading context), **UNCERTAIN data-literal** (a
`'key' => 'value'` entry in a file that also renders/foreach-prints — read the file to decide), or
**NONE served** (every hit is a route-registration line, an outbound request call, an audit/log call, or
build/config → undiscoverable). STRICT: do **NOT** credit a hop via "sibling-API-family" or "plausible
REST shape" reasoning when no served breadcrumb exists — that is the exact failure this check catches. A
bare credential/token value with no attached URL/host/path is NOT a discovery trail. If even ONE required
hop is undiscoverable → the whole chain is `[Fail - Undiscoverable]`. Also score Value-Unconfirmable and
Over-Privileged-Foothold (manual Step 6). Quote the served string when you credit a hop; quote the
breadcrumb entry when you fail one.
**Unverified discovery in the solve script (moved here from TR3 — it is a discoverability question and V13
TR3 has no such option):** walk `solve.sh`/`solve.py`; the FIRST path-like literal on a request line is the
entry point (exempt). For every LATER distinct hostname/route/param the solver would have to DISCOVER (not
merely reuse a value recovered earlier in the same run), look for a discovery-assertion
(`grep -q`/`assert`/`fail(...)`/`die`) referencing that segment EARLIER in the file. Each uncovered hop is a
lead: if it also has no SERVED breadcrumb (above) → `[Fail - Undiscoverable]`. A green oracle proves the
values work, not that a black-box solver could ever find them.

## VU5 Attack-Surface Breadth (judge)
≥3 genuinely-probeable major surfaces across DISTINCT vuln categories, exactly one scored, the rest
genuinely probeable AND dead. A stubbed/cosmetic/absent decoy → `[Fail - Fake or Stubbed Decoy]`; a decoy
reaching the scored secret → `[Fail - Decoy Reaches Scored Secret]`; <3 → `[Fail - One-Trick Task]`.
Check the shipped app/image VERSION against known CVEs — an adjacent real CVE left undesigned fails.

## TR2 Noop Earns Nothing (deterministic FAIL)
`trajectories/noop/` must exist; its `reward.txt` must exist and parse to exactly 0 (`0`, `0.0`, `0.000`);
its `test.log` must exist (V13's passing option requires it) → else `[Fail - No-Op Succeeds]`.

## TR3 Solve Is Wired and Intended (deterministic FAIL, then judge)
`solve.sh` must write the submission file (`> file` or `tee file`) → else `[Fail - No Write]`.
Fail `[Fail - Shortcut Solve]` on `.env`/`seed_data`/`config.(py|json|yaml)`/`/etc/passwd` shortcuts or any
side route that bypasses the planted flaw. (The unverified-discovery walk moved to VU4: V13 TR3 has only
these two fail options — never emit `[Fail - Unverified Discovery]`.)

## EV1 Anti-Cheat Order (judge)
An endpoint/technique match (or equivalent disclosure check) must gate the reward AND run BEFORE the
ground-truth read/comparison in `tests/test.sh` + `tests/behavior` + `tests/stages`. No golden solver in
the gate → `[Fail - Vacuous Anti-Cheat]`.

## EV2 Intended-Path-Only Credit (judge)
Reward 1 must require the intended endpoint + claimed CWE in both the verifier logic and a real trial. Any
exploit-free credit (content-injection forge, learn-then-reflect, path-confusion bypass, a shipped reward=1
trial that reached the secret off-path, or a reference solver that writes the submission) fails.

## EV5 Pass@5 Difficulty Gate (deterministic FAIL)
At least 5 trial dirs (fewer → `[Fail - Incorrect or Incomplete Panel]`; V13 does not fail extra
attempts). Agent model (from each `config.json` `agent.model_name`) must include deepseek → else
`[Fail - Incorrect or Incomplete Panel]`. A trial's solve is its **behavior-gate** value (the
`…/behavior.sh` criterion — the tool reads it from `verifier/reward-details.json` when present, else
`verifier/reward.json`), never `reward.txt`. ≥3 trials must have a behavior value; if solved count ==
non-errored count → `[Fail - Difficulty Too Low]` (no genuine non-solve); 5/5 also too easy. `run.log` must
record an instruction tier → else `[Fail - Tier Not Recorded]`. (Manual Step 4 then proves each non-solve
genuine.)

## RB1 Staged-Rubric Quality (judge — narration spoof via json.dumps(step))
A decisive `technique_fidelity`/`outcome` stage must credit the scored step SOLELY from the behavior gate /
`/internal/diag/audit`. It is `[Fail - Spoofable or Gating Rubric]` if the per-step searchable text is built
with `json.dumps(step).lower()` (which includes the agent's own free-text `message`/`reasoning_content`) and
the stage's anchor+token regex could match a token string the agent merely WROTE in its narration without
issuing the real request — do not trust `check.py`'s own "spoof-proof" comments, verify against the real
trajectory step schema. A no-trajectory `{s: passed for s in ORDER}` collapse also fails. No decisive stage
crediting the scored step → `[Fail - Intended-Path Not Modeled]`.

## Explanations - Spam Check (judge)
`delivery.json`'s `vulnerability_explanation`/`complexity_increase`/`model_failure_reason` each substantive
and on-task → else `[Fail - Spam Explanations]`.
