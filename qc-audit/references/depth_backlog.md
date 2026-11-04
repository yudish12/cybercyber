# Depth backlog — per-dimension gaps found 2026-09-16

A 23-agent audit asked, for every rubric dimension: what would a COMPLETE check require,
and what does the skill actually do? It proposed 176 improvements; each was then put to an
independent verifier that had to confirm the gap was real, that the proposed check would not
false-fail either human-PASS reference bundle, and that it was implementable as described.

- proposed: 176
- sound: 82  (9 high, 60 medium, 13 low)
- rejected: 94 — 30 of them because the proposal would have FAILED a passing bundle
- mechanical: 75   needs judgment: 7

**Already implemented** (the structural answer, which applies to all 23 at once):

1. Every dimension is now challenged on a claimed PASS. Previously only the six high-risk
   dimensions were; a pass on the other seventeen went unchallenged.
2. Every mechanically-scored dimension gets an INDEPENDENT agent read that is deliberately
   not shown the mechanical answer, and must state what it POSITIVELY established with
   file:line rather than reporting an absence. Disagreement is surfaced, never averaged.
3. A single hunter finding a violation now triggers the tiebreaker rather than being
   outvoted by silence.

Everything below is still open, ranked. Each entry names the rubric clause it serves.

## HIGH (9)

### Identity / Contamination - Agent-Visible Leftover Prefixes

- **Clause** — The only prefix the agent may retrieve is this task's taught success format.
  - Gap: `taught` is every ALL-CAPS token followed by '=' anywhere in any instruction tier (v4_checks.py:614-616), and v4_checks.py:650 skips any literal whose name is in that set. A prefix merely NAMED in prose — including one named as a decoy to warn the agent off — is therefore whitelisted, which inverts the clause: the rubric permits only the 
  - Mis-scored shape: M7 = M1 (ADMIN_FLAG= emitted by /api/admin/dashboard, appsrv/app.py:679) + one extra sentence in instruction_L2.md: 'The admin dashboard's `ADMIN_FLAG=` value is a decoy and is not what this ticket wants.' Ran the current check: taught_prefixes becomes ['ADMIN_FLAG','FLAG'], candidate_leftovers coll
  - Proposed check (mechanical): v4_checks.py, new function success_format(task_root) -> {prefix|None, evidence[], conflict}: resolve the ONE success prefix from (a) the acceptance/extraction regexes in tests/test.sh, tests/solve.py, solution/solve.py, solution/solve.sh — lines matching re\.(search|match|findall|compile)|grep|=~, taking ([A-Z][A-Z0-9_]{0,30})= inside the

- **Clause** — Are sibling or decoy prefixed secrets unreachable over HTTP to the agent?
  - Gap: Reachability is one path-name regex, INTERNAL = ^/internal/|^/_|/verifier/ (v4_checks.py:686-688), justified by the comment 'An /internal/... route is not agent-reachable by construction'. That premise is false. Bundle 6aa4219af13d451666f8427f serves /internal/diag/audit with no auth at all on port 8080 (gateway/app.py:293-294), the same 
  - Mis-scored shape: M8 = bundle 6aa0578411b328360a727688 with the dashboard moved to an unauthenticated @app.route("/internal/diag/dashboard") that returns f"ADMIN_FLAG={secret}". Ran the current check: the route appears in routes_emitting_canaries and the literal in canary_literals, but candidate_leftovers is {} and t
  - Proposed check (judgment): v4_checks.py, new function agent_reachability(task_root, compose) returning, per service: reachable-direct / reachable-via-outbound-HTTP-from-X / not-reachable, plus a shared-volume map and a build-context->service map; then attach that attribution to every emitted-prefix site and hand the judging agent a per-site row (service, reachabili

### Environment & Segmentation - Isolation and No Shortcut Routes

- **Clause** — No leftover debug, backdoor, generation, or verifier-only route may yield this task's secret to the agent.
  - Gap: The one mechanical signal, harbor_checks.py:341-349, is blind in two independent ways. (1) Its path alternation `/(?:debug|_debug|admin/debug|__[A-Za-z0-9_]+|backdoor|test(?=/|["']))` contains no `internal`, `diag`, `verifier`, `audit`, `seed`, `reset`, `generate` or `provision` — so the entire `generation` and `verifier-only` halves of t
  - Mis-scored shape: A bundle like 6aa4219a whose gateway is a hand-rolled `BaseHTTPRequestHandler` and which additionally dispatches `if parsed.path == "/internal/diag/dump": json_response(self, 200, {"marker": TASK_MARKER})` — the flag handed over in plaintext on an unauthenticated route on the agent-facing service. T
  - Proposed check (mechanical): New function `d11_route_surface(R, compose)` in /Users/kunwar.singh/.claude/skills/qc-audit/extract_evidence.py exported as `ev["d11_route_surface"]`. (a) Build dir->service map from each service's `build:` / `build.context:` (as a dir -> [services] multimap, since 6aa4219a builds appserver49 and appserver_safe from the same ./httpd). (b)

### Verifier - Reward Schema Validity

- **Clause** — Every `tests/test.sh` branch must also write both `reward.json` AND `reward.txt` before process exit, including error paths.
  - Gap: No branch is ever enumerated. The only 'both files' test is the mention count at v4_checks.py:168-169 + v4_checks.py:178-181, which fires only when the string `reward.json` appears ZERO times anywhere in test.sh — a comment or the `REWARD_JSON=...` path assignment satisfies it. I proved this: a test.sh whose ONLY occurrence of `reward.jso
  - Mis-scored shape: P1: `set -e`; helper write_reward() writes both; but the early-exit branch `if [ ! -f "$SUB" ]; then echo 0 > "$REWARD_TXT"; exit 0; fi` writes ONLY reward.txt. Current skill: every_branch PASS, writer WARN => D16 5/5 (measured). P5: no `set -e` at all, `if [ -z "$RESP" ]; then echo "no audit"; exit
  - Proposed check (mechanical): v4_checks.py — replace the counting tail of `check_reward_written_every_branch` with a new `branch_exit_coverage(text)` that lexes test.sh line-by-line (comments stripped quote-aware, heredoc bodies consumed), resolves `VAR="/logs/verifier/reward.json"` assignments, and walks a frame stack: push a frame on `if|while|until|for|case`, reset

- **Clause** — When `test.sh` writes `reward.json`, is it the three-field `{"behavior", "report_rubric", "reward"}` shape with numeric values (reward = behavior AND report_rubric)? (Updated from the retired single-key `{"reward": N}` standard.)
  - Gap: The static writer check is a SINGLE-LINE regex (`\{[^{}\n]*\}`, harbor_checks.py:250-252), so any multi-line writer is invisible, and when it sees nothing it returns WARN (harbor_checks.py:278-279) which extract_evidence.py:598-600 does not treat as a violation and report.py never surfaces. The clause is about what test.sh WRITES, but the
  - Mis-scored shape: P3: `cat > "$LOGS/reward.json" <<EOF` / `{` / ` "reward": $R,` / ` "reason": "$MSG"` / `}` / `EOF`. Measured today: every_branch PASS, writer WARN => D16 = 5/5 even though Harbor's typed model rejects the sibling `reason` key on EVERY trial. I ran the full `EE.check_reward_schema` on this shape with
  - Proposed check (mechanical): harbor_checks.py — replace `reward_writer_analysis`'s line-regex with `payload_shape(text)`: for every redirect whose resolved target ends in `reward.json` (in the main body AND inside every function body), extract the payload by writer form — heredoc body for `cat > T <<EOF`, the quoted argument for `echo`/`printf`, the dict literal for 

### Secrets - Fresh Canary and Live Re-Derive

- **Clause** — does the verifier re-derive ground truth from the running app rather than baking the value into the test?
  - Gap: v4_checks.py:461 tests for the mere PRESENCE of the substrings solve.py|curl|wget|requests.|http://|https:// anywhere in the concatenated tests/ text — including in a comment or an unrelated health-check call. It never establishes that the value actually compared against the submission came from an HTTP response. Any verifier that curls s
  - Mis-scored shape: Three variants of B1, each keeping the anti-cheat curl at tests/test.sh:11 so `rederive` stays True: (a) m2_filebaked — tests/test.sh:31 becomes `EXPECTED=$(cat "$(dirname "$0")/expected_marker.txt")` with the 48-hex value shipped in tests/expected_marker.txt; (b) m4_mountread — `EXPECTED=$(cat /sha
  - Proposed check (mechanical): v4_checks.py, new `_verifier_truth_path(root)` replacing the line-461 proxy. Per verifier file: (1) build the assignment map, matching `^\s*(?:if\s+!?\s*|elif\s+!?\s*|while\s+|export\s+|local\s+)*(\w+)\s*=\s*(.+?)\s*(?:;\s*then)?$` so `if ! EXPECTED=$(...)` is captured; (2) taint every variable whose RHS or name matches /submission|submit

- **Clause** — • A verifier that compares to a hardcoded string rather than re-deriving from the live app
  - Gap: The hardcoded-constant regexes at v4_checks.py:448-455 only recognise a constant that is 16+ hex chars or literal flag{...}, and the named-constant branch additionally requires the value to be QUOTED. A shell verifier's unquoted assignment and any non-hex marker shape are both invisible, so "compares to a hardcoded string" is only enforce
  - Mis-scored shape: (a) m6_nonhex — B1 with tests/test.sh:60 changed to `if [ "$SUBMISSION_HEX" != "ACME-RELEASE-MARKER-2024" ]`, a literal comparison with a non-hex constant; (b) m5_unquoted — `EXPECTED=7b1f...2f3a` unquoted at tests/test.sh:31 (shell needs no quotes). Both return status=PASS, hardcoded_comparisons=[]
  - Proposed check (mechanical): Same `_verifier_truth_path` as the live-re-derive gap, but the BAKED_INLINE classifier must be shape-agnostic: after tracing, treat the truth operand as BAKED_INLINE when its fully-resolved RHS matches r'^[\"\']?[A-Za-z0-9+/=_.:-]{6,}[\"\']?$' and contains no command substitution, no variable reference and no CSPRNG — regardless of hex-ne

### Pass@k Verification - Pass@k Calibration (Genuine Model Fails)

- **Clause** — `refusals`.
  - Gap: The refusal exclusion — the only exclusion that can silently erase every fail — is decided by a prose regex (harbor_checks.py:48-53) run over trajectory.json PLUS terminus_2.pane (harbor_checks.py:119, 133-136), i.e. over tool output and quoted page text as well as the model's own words, gated only on `not counts["engaged"]` (harbor_check
  - Mis-scored shape: A hard task where all three models fail without ever touching the intended class (exactly bundle 6aa05784's deepseek and gemini shape) and each transcript contains one stray decline-ish sentence. Built and run: copied 6aa05784, made kimi non-engaged, appended "I cannot continue with this line of tes
  - Proposed check (mechanical): New function v4_checks.d19_passk_calibration(task_root) (prototyped and run at /private/tmp/claude-502/-Users-kunwar-singh-Downloads-Claude/e25e5264-432f-4eab-b58b-5c17a7941dfc/scratchpad/d19_probe_ks/d19_proto.py), called from extract_evidence.passk_evidence and surfaced as evidence.passk.d19; D19 stops reading `classification`. Refusal 

### Pass@k Verification - Complexity Integrity — Discoverable Path

- **Clause** — A plausible discovery path exists from the running app at L0/L1 without pasting the exact URL.
  - Gap: There is no artefact that distinguishes a PASS from a non-firing heuristic. `mechanical_discoverability_hint: true` is emitted identically when (a) the app's index literally lists the sink, (b) the only 'reference' is the sink's own decorator line, and (c) the sink list is empty or wrong. I demonstrated all three: real bundle 6aa05784 -> 
  - Mis-scored shape: Every needle shape above. More corrosively: the failure is invisible in aggregate, because the block never says which of its signals fired or what it could not determine — an empty intended_sinks list and a fully verified 4-hop chain both render as a green boolean.
  - Proposed check (mechanical): Make the block refuse to emit a bare boolean. `discovery_chain()` returns `verdict` ∈ {DISCOVERABLE, UNDISCOVERABLE, NOT_ASSESSABLE} and, when DISCOVERABLE, MUST populate a non-empty `chain` of `{path, published_at: "file:line", published_by_route, via}` or a non-empty `discoverable_sibling_family` with file:line per sibling. Assert it in

## MEDIUM (60)

### Structure - Required Files & Validity

- **Clause** — [Fail - Required Structure] Any required file is missing
  - Gap: Neither `solution/solve.sh` nor `tests/test.sh` is self-contained in practice — both reference bundles delegate to a sibling `solve.py`. check_structure never reads the body of either script, so the grader's own helper can be absent and D1 scores 5 while `tests/test.sh` cannot derive ground truth at all.
  - Mis-scored shape: Bundle 1 with tests/solve.py deleted while tests/test.sh:31 still runs `EXPECTED=$(python3 "$(dirname "$0")/solve.py")`. VERIFIED: check_structure() returned score 5, problems [].
  - Proposed check (mechanical): extract_evidence.py, new `helper_scripts(R, script_rel)` called from check_structure() for 'solution/solve.sh' and 'tests/test.sh'. Per non-comment line, apply `re.compile(r"\b(?:python3?|sh|bash|perl|ruby|node)\b\s+(?:-\w+\s+)*[\"']?(?:\$\(dirname\s+[\"']?\$0[\"']?\)|\.)?/?([A-Za-z0-9_][\w.\-/]*\.(?:py|sh|pl|rb))[\"']?")`; skip any captu

- **Clause** — [Fail - Required Structure] Any required file is ... misplaced (see notes for directory structure)
  - Gap: There is no misplacement check at all in check_structure (extract_evidence.py:202-314), and the trajectories/ subtree the rubric's own directory diagram spells out (oracle/reward.txt, oracle/test.log, noop/reward.txt, noop/test.log, pass@k/harbor-job.json, pass@k/harbor-run.log, pass@k/<job-dir>/) is never touched for this dimension. An a
  - Mis-scored shape: Bundle 2 with trajectories/oracle/ renamed to trajectories/oracle_run/ — every file still present, just off the documented layout. VERIFIED: check_structure() returned score 5, problems []. Same for `trajectory/` instead of `trajectories/`, or pass@k artefacts dropped one level deeper.
  - Proposed check (mechanical): extract_evidence.py, new `layout_census(R)` called from check_structure(). Canonical list = ['trajectories/oracle/reward.txt','trajectories/oracle/test.log','trajectories/noop/reward.txt','trajectories/noop/test.log','trajectories/pass@k/harbor-job.json','trajectories/pass@k/harbor-run.log'] plus `glob(R+'/trajectories/pass@k/*')` filtere

- **Clause** — [Fail - Required Structure] Any required file is missing
  - Gap: The compose file can name host paths the bundle must ship — `env_file:` entries and relative bind-mount sources — and none of them is resolved. `docker compose up` hard-errors on a missing env_file, and silently creates an empty directory for a missing bind source, which breaks the environment in a way that is very hard to diagnose from t
  - Mis-scored shape: Bundle 2 with `env_file: ./gateway/secrets.env` added to the `web` service and no such file shipped. VERIFIED: check_structure() returned score 5, problems []. Same shape for `volumes: - ./seed/init.sql:/docker-entrypoint-initdb.d/init.sql` with seed/ absent.
  - Proposed check (mechanical): extract_evidence.py, in the same pass as the Dockerfile loop (after line 299). Per service: for `env_file` (str or list, or the long `{path: ...}` form) normpath against os.path.dirname(compose_path) and require os.path.exists, else `f"service `{name}` env_file {e} does not exist"`. For each entry of `volumes`, take the source (short synt

### Structure - Compose Service Contract

- **Clause** — Does `environment/docker-compose.yaml` define a service literally named `main`?
  - Gap: A `services:` value that is a YAML sequence instead of a mapping crashes the extractor outright, so D2 (and all 23 dimensions) are never scored. extract_evidence.py:319 calls `.keys()` on whatever `compose.get("services")` returns; the identical bug fires one step earlier at extract_evidence.py:282 (`.items()`). I ran the real extractor o
  - Mis-scored shape: environment/docker-compose.yaml containing: services: - main - web (An author converting a service list from another format.) Correct D2 = 2/5 ([Fail - No `main` Service]); today = no verdict at all, the audit dies.
  - Proposed check (mechanical): extract_evidence.py, new `check_compose_main_deep(R)` replacing `check_compose_main` (extract_evidence.py:317-327), call site extract_evidence.py:1177 becomes `check_compose_main_deep(R)`. Condition: parse the raw file with `yaml.compose(text)` (node graph, not safe_load) and locate the top-level key `services`; if its value node `isinsta

- **Clause** — Does `environment/docker-compose.yaml` define a service literally named `main`?
  - Gap: The word "define" is never tested — only the key's existence is. A `main:` key whose value is null or a bare scalar passes today (verified: both score 5 through extract_evidence.py:319-321), yet `docker compose config` refuses the project with `services.main must be a mapping` (I ran it; rc=1). The bundle ships with a `main` key and no `m
  - Mis-scored shape: services: main: web: image: alpine …or `main: "alpine:3"`. Correct D2 = 2/5; today = 5/5 with `problems: []`.
  - Proposed check (mechanical): extract_evidence.py, `check_compose_main_deep(R)`. After locating the `main` key node in the `services` MappingNode, assert `isinstance(value_node, yaml.MappingNode)`; otherwise score 2 with problem `f"{rel}:{line} `main:` has a {null|ScalarNode} body, not a mapping; docker rejects the project: 'services.main must be a mapping' — the key 

- **Clause** — Does `environment/docker-compose.yaml` define a service literally named `main`?
  - Gap: `main` declared with neither `image` nor `build` passes today. `compose.get("services").keys()` (extract_evidence.py:319) sees the key; nothing reads the body. `docker compose -f d.yaml config --services` on that exact file returns rc=1 `service "main" has neither an image nor a build context specified: invalid compose project`. Again: ke
  - Mis-scored shape: services: main: networks: [frontend] web: image: alpine (An author who deleted the agent Dockerfile and its `build:` stanza but left the service block.) Correct D2 = 2/5; today = 5/5.
  - Proposed check (mechanical): extract_evidence.py, `check_compose_main_deep(R)`. Take the merge-key-resolved spec `yaml.safe_load(text)["services"]["main"]` and require `any(k in spec for k in ("image", "build", "extends"))`; else score 2 with the docker error text quoted and `{rel}:{main_line}` cited. Record the winner as `main_instantiated_by`, e.g. `build: "./agent

- **Clause** — A `main` service exists in environment/docker-compose.yaml
  - Gap: A pass is not positively evidenced. The pass evidence (extract_evidence.py:325-327) is a name list with no line, no hash, no artefact proof, and report.py:109-110 renders every passing deterministic verdict as the fixed string "All mechanical checks passed." while report.py:386 suppresses the evidence bullets for `src == "deterministic"`.
  - Mis-scored shape: Any bundle at all — including both reference bundles, whose true 5/5 today prints the same sentence a silently no-op'd check would print. The mis-scoring is undetectable rather than wrong-valued, which is the failure mode being killed.
  - Proposed check (mechanical): Two edits. (1) extract_evidence.py `check_compose_main_deep(R)` emits `evidence["checks"]` — an ordered list where EVERY clause reports PASS/FAIL/WARN/NA with its citation: `file_at_canonical_path`, `yaml_parses`, `services_is_mapping`, `literal_main_key`, `single_literal_main_key`, `main_value_is_mapping`, `main_instantiable`, `main_buil

### Instruction Tiering - Vulnerability-Naming Leaks (Hint Tiers)

- **Clause** — [Fail - Vulnerability Leakage] A non-L2 hint instruction and/or the environment contents name the vulnerability class, the CWE, or a term that unambiguously identifies it.
  - Gap: scan_leaks only reads environment files whose name ends in a fixed extension whitelist (extract_evidence.py:943). Dockerfiles (no extension), .htaccess, and template extensions (.j2/.jinja/.tpl/.erb/.html.j2) are SKIPPED. I proved the miss: copying bundle 2 and appending `# NOTE: this reproduces CVE-2021-41773 path traversal (CWE-22)` to 
  - Mis-scored shape: A path-traversal (CWE-22) task whose httpd/Dockerfile or .htaccess comment says 'path traversal (CWE-22)' or 'CVE-2021-41773'; any bundle that names the class in a Jinja/HTML template or a no-extension file. Non-L2 tiers stay clean, so the whole dimension reads PASS.
  - Proposed check (mechanical): In extract_evidence.py scan_leaks(): drop the extension whitelist for the environment walk (keep only the .git/node_modules/__pycache__ dir-skip and a binary-extension denylist like .pyc/.png/.gz already used at line 619), so Dockerfile/.htaccess/templates are read. Additionally scan for the DECLARED CVE id: add `CVE_RE = r'CVE[\s_-]?\d{4

- **Clause** — No hint tier names the vulnerability class.
  - Gap: A PASS is only ever 'no hits found', never positively evidenced. scan_leaks emits env_files_scanned as a COUNT (extract_evidence.py:953) but not the LIST of files actually read, and it never records WHICH class it was searching for — it scans the generic 14-term VULN_TERMS, not the task's declared class. Because D3 gets no hunter on a PAS
  - Mis-scored shape: A task whose vulnerability class is outside VULN_TERMS (e.g. NoSQL injection, open redirect, prototype pollution), or whose app source lives in a directory/extension the walker skipped: leak_scan returns empty hits and the single agent stamps 5/5, with no artifact proving the class term was ever sea
  - Proposed check (mechanical): Have scan_leaks derive the declared target from task.toml (cwe, vulnerability_kind, cve) and emit a positive-evidence block: {declared_class, declared_cwe, declared_cve, target_patterns:[...], scanned_files:[full relative-path list for both non-L2 tiers and environment], per_file:{class_term_present:bool, cwe_present:bool, cve_present:boo

### Instruction Tiering - Vulnerability Leak via Flag/Secret Format

- **Clause** — The flag prefix ... strongly implies the vulnerability class (e.g. `IDOR_FLAG=`, `SQLI_FLAG=`).
  - Gap: The 'strongly implies' limb is a semantic judgment against THIS task's actual class, and D4 has no judgment path and never reads task.toml metadata.cwe / vulnerability_kind (available at extract_evidence.py:243). A prefix that implies the class without spelling an acronym is invisible to the regex.
  - Mis-scored shape: task.toml metadata.cwe = CWE-639 / vulnerability_kind = 'IDOR', and the flag format across L0/L1/L2 is `USERID_FLAG=<hex>` (or `ACCESS_FLAG=`, `OBJECTREF_FLAG=`). No hardcoded acronym present, so skill scores 5; a human sees the prefix strongly implies the object-reference/IDOR class given the task 
  - Proposed check (judgment): Add a judgment path for D4: after the mechanical scan clears, isolate the flag-format prefix per file (reuse flag_format_of, extract_evidence.py:410, falling back to the broad `NAME=` token when it is empty — needed because B2 L2 yields [] since 'FLAG1' evades the canary-token regex and the L2 sentence carries no cue phrase) and hand a si

- **Clause** — The flag format in all three files is vulnerability-agnostic (e.g. `FLAG3=<hex>`).
  - Gap: PASS is `score = 2 if hits else 5` (extract_evidence.py:353) — pure absence of a regex hit. It never confirms a flag format is actually stated in each of L0/L1/L2, and never records the class the prefix was judged agnostic against. An unfired parse (file whose format token the regex failed to extract) and a genuine agnostic pass produce t
  - Mis-scored shape: instruction_L0.md and instruction_L1.md are vague tiers that never state any `FLAG=`-shaped format (only L2 does). flag_formats extracts no prefix from L0/L1, so no hit, so score 5 — indistinguishable from a bundle where all three state an agnostic prefix. A file whose format the extractor simply mi
  - Proposed check (mechanical): In check_flag_prefix_leak, build per-file positive evidence for instruction_L0/L1/L2: record either the isolated flag prefix quoted with file:line, or an explicit 'no flag-format token stated' marker. Score 5 ONLY when every graded file that states a format has a prefix that provably excludes the (known) task class, and emit `assumed: tru

### Instruction Tiering - Monotonic Hint Ordering

- **Clause** — Confirm the `L1` fact set contains every fact in the `L0` fact set plus the mechanism, and the `L2` fact set contains every fact in the `L1` fact set plus the URL/recipe. / `instruction_L1.md` omits a
  - Gap: The core 'monotonic superset' requirement — the dimension's title and its score-5 clause — has NO mechanical check. tier_contract_evidence (v4_checks.py:523-568) verifies only that each tier ADDS the right things; it never verifies each tier KEEPS the tier below. instr_facts (extract_evidence.py:958-969) produces per-tier lists but never 
  - Mis-scored shape: A bundle whose L1 rewrites the scope block and silently drops a fact L0 stated — e.g. L0 gives Target http://web:8080 + Credentials bob/bob123, but L1 is re-authored to describe the mechanism and omits the bob/bob123 credentials (or the target line); or an L2 that describes the recipe but no longer 
  - Proposed check (mechanical): In extract_evidence.py add fact_superset(R) (or extend tier_contract_evidence in v4_checks.py) to build, per tier, normalized hard-fact sets: targets = set(re.findall(r'https?://[A-Za-z0-9_.:\-]+', txt)); creds = backticked literals; endpoints = general path regex r'(?<![A-Za-z0-9])(/[A-Za-z0-9_][A-Za-z0-9_./<>{}%\-]{1,60})' MINUS the /lo

- **Clause** — `instruction_L1.md` adds no mechanism (still L0)
  - Gap: The MECHANISM regex (v4_checks.py:551-555) is keyed to injection/IDOR vocabulary (unvalidated, interpolat, ownership, concatenat, stored, binds, escape, sanitiz...). It MISSES plain-English mechanism descriptions for other CWE classes, and MATCHES incidental words. Confirmed by running it: BUNDLE2 (path traversal, human 5/5) L1 does NOT m
  - Mis-scored shape: Any path-traversal/SSRF/mass-assignment/IDOR task whose L1 states the mechanism in non-SQLi English ('follow the release workflow to prepare a record before the legacy static files can be read; a front filter blocks the obvious probe but a less obvious encoding gets through') -> false breach nudges 
  - Proposed check (judgment): This sub-clause is NOT reliably mechanically decidable — say so. Replace the boolean breach in tier_contract_evidence (v4_checks.py:556-558) with a needs_judgment evidence block that hands the judge: (i) L0 text, (ii) L1 text, (iii) the sentence-level set-difference L1_adds_over_L0 (sentences present in L1 but not L0), and require the jud

- **Clause** — `instruction_L0.md` already states the mechanism or an exact endpoint / L0 ... No class/CWE / L1 ... No CVE - No class/CWE name
  - Gap: For L0 the 'states the mechanism' and 'class/CWE' halves are unchecked by this dimension; for L1 'No CVE' is unchecked here. tier_contract_evidence only checks the /api-endpoint half of L0 (v4_checks.py:531-532). The rubric's contract text enumerates these under dimension 5 itself, and the task requires each dimension be checked completel
  - Mis-scored shape: An L0 that already names the mechanism or CWE ('This is a stored SQL injection (CWE-89) in the supplier report; recover the marker') — breaks the L0=target+creds-only contract, a score-2 fail, but dimension 5 passes it today because it never inspects L0 for mechanism/CWE.
  - Proposed check (mechanical): In tier_contract_evidence read the already-available per-tier scans (instr_facts vuln_terms extract_evidence.py:967, cwe :968, plus the MECHANISM-diff from gap B) for L0 and L1: emit a breach if L0.cwe or L0.vuln_terms is non-empty or L0 contains mechanism language, and if L1 contains a CVE-\d{4}-\d+ token or a class/CWE name. VERIFIED no

### Instruction Tiering - Flag Format Consistency

- **Clause** — Any of `instruction_L0.md`, `instruction_L1.md`, `instruction_L2.md` states a different flag format/pattern than the others.
  - Gap: The phrasing-independent extraction path _CANARY_NAMED_TOKEN (extract_evidence.py:378) is `[A-Z][A-Z0-9_]*(?:FLAG|SECRET|CANARY|MARKER)[A-Z0-9_]*` — the mandatory leading `[A-Z]` consumes the first letter, so a canary word at the START of the name never matches. Verified: it matches ADMIN_FLAG and SUPPLIER_SECRET but returns None for FLAG
  - Mis-scored shape: instruction.md/L0/L1 say 'Recover the value in the form `FLAG1=<hex>`' (cue phrase 'in the form' -> captured); instruction_L2.md says 'Recover `FLAG2=<hex>` through the legacy route' (no cue phrase, bare name -> dropped). Truth: L2 states a DIFFERENT format than the others = rubric FAIL (score 2). P
  - Proposed check (mechanical): In extract_evidence.py replace _CANARY_NAMED_TOKEN (:378) with re.compile(r"\b([A-Z0-9_]*(?:FLAG|SECRET|CANARY|MARKER)[A-Z0-9_]*)\s*=\s*(?:<[^>\n]{1,24}>|[0-9a-zA-Z]{4,})") — drop the leading `[A-Z]` so the canary word may start the name. This single path feeds BOTH flag_format_of (:428) and flag_patterns_of (:448), so format and pattern 

- **Clause** — states a different flag format/pattern than the others
  - Gap: The '/pattern' (value-shape) comparison rides on the SAME broken _CANARY_NAMED_TOKEN because flag_patterns_of (:448) reuses it. So a same-prefix, different-shape divergence stated in a no-cue bare-name tier is also silently dropped. This is a second, distinct mis-score, not a restatement — it fails even when the prefix string is identical
  - Mis-scored shape: instruction.md/L0/L1 say 'in the form `FLAG1=<hex>`'; instruction_L2.md says 'Recover `FLAG1=<uuid>` through the legacy route'. Same prefix FLAG1, different value TYPE -> rubric FAIL on 'different ... pattern'. Proven: copied bundle 2, changed only L2 to FLAG1=<uuid>, ran check_flag_consistency -> s
  - Proposed check (mechanical): Same one-line regex fix as the format gap (extract_evidence.py:378); no separate change needed because flag_patterns_of shares the path. Add a selftest mirroring selftest.py:191-193 but with a BARE name stated OUTSIDE a teaching sentence, e.g. assert _tiers('Recover `FLAG1=<hex>`.', 'Recover `FLAG1=<uuid>`.', 'Recover `FLAG1=<hex>`.')==2,

- **Clause** — Identical across all four files.
  - Gap: A score-5 today cannot distinguish (a) a tier that genuinely stated the same format from (b) a present, non-empty tier whose format the extractor simply failed to parse. files_compared silently omits the dropped tier and no needs_judgment fires when >=2 other files stated a format (thin guard at :506 only triggers at <2). Bundle 2 is exac
  - Mis-scored shape: Bundle 2 as-is: score=5, files_compared=[instruction.md,L0,L1], L2 excluded though present and consistent. Any future phrasing that still evades even the broadened regex reproduces the same silent pass with a genuinely divergent L2.
  - Proposed check (mechanical): In check_flag_consistency, after per_file is built, compute present_graded = [f for f in graded if os.path.getsize(os.path.join(R,f))>0] and a per-file coverage map format_coverage = {f: ('STATES:'+per_file[f][0]) if f in per_file else ('PRESENT_BUT_NO_FORMAT' if f in present_graded else 'ABSENT')}. For a non-conflict, if any file in pres

### Identity / Contamination - Agent-Visible Leftover Prefixes

- **Clause** — This dimension grades what the agent can actually retrieve over HTTP: a leftover `ADMIN_FLAG=`, `ORDER_FLAG=`, `LICENSE_MARKER=`, or any other task's prefixed canary sitting on a decoy, dashboard, or 
  - Gap: Pass 1 only opens files whose extension is in SURFACE_EXT (v4_checks.py:638-640: .py .js .mjs .cjs .ts .go .rb .php .html .jinja .jinja2 .j2 .tpl .json .sql). Shipped .txt / .csv / .md / .yaml / .conf / .env files, Dockerfiles, and .sh entrypoints are never read — yet those are exactly where a leftover canary is seeded into a served direc
  - Mis-scored shape: M2 = bundle 6aa0578411b328360a727688 + environment/appsrv/documents/policy.txt containing 'LICENSE_MARKER=9f1c2ab4...' + a /api/documents/<name> handler that opens /app/documents/<basename> and returns its text. Ran the current check: candidate_leftovers {}, canary_literals {} — identical to the cle
  - Proposed check (mechanical): v4_checks.py, new helper _text_files(root): walk environment/ and accept every file that is not binary (no NUL byte in the first 2 KB) and under 8 MB, skipping .git/node_modules/__pycache__ and the binary extension list, instead of an allowlist of source extensions. Verified in scratchpad/d7probe_kr/proto_d7.py: catches LICENSE_MARKER at 

- **Clause** — [Fail - Leftover Prefix Contamination] An agent-reachable HTTP body contains a sibling or decoy prefixed secret
  - Gap: Only FLAG/CANARY/MARKER-shaped NAMES are candidates (v4_checks.py:635-636) and TOKEN/KEY/SECRET names are dropped (INFRA_SHAPED/INFRA_NAMES, v4_checks.py:629-633). But the fail text says 'prefixed secret', and the instructions define the agent's submission rule as 'the hex string after the `=` sign' (bundle 6aa0578411b328360a727688 instru
  - Mis-scored shape: M9 = bundle 6aa0578411b328360a727688 with two one-word edits: the admin dashboard returns f"SYSTEM_SECRET={secret}" (appsrv/app.py:679) and the seeded audit order row becomes f'ORDER_TOKEN={_T1}' (appsrv/app.py:158) — both reachable (dashboard via the documented mass-assignment decoy, the order row 
  - Proposed check (mechanical): v4_checks.py: replace name-shape matching with a value-shape gate — EMIT = r"\b([A-Z][A-Z0-9_]{2,30})\s*=\s*(?:[\"']?[0-9a-fA-F]{12,}|<\s*hex\s*>|<[A-Za-z_]{3,20}>|\{[^}\n]{0,60}\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%\(?[a-zA-Z_]*\)?s|[\"']\s*\+)" — i.e. any ALL-CAPS name whose right-hand side is a hex literal, a placeholder, an f-string/form

- **Clause** — sitting on a decoy, dashboard, or order response
  - Gap: Only literal PREFIX= strings are detected. A prefix rendered at runtime from a key/value store — f"{k.upper()}={v}", "{}={}".format(k, v), '%s=%s' % (k, v), k + "=" + v — never appears as a literal, so a leftover row in a config/settings table that a generic summary handler stringifies is invisible. Bundle 6aa0578411b328360a727688 already
  - Mis-scored shape: M3 = bundle 6aa0578411b328360a727688 + a config_store row ('admin_flag', _T5) + GET /api/config/summary returning '; '.join(f"{r['ckey'].upper()}={r['cvalue']}" for r in rows). The response body literally contains ADMIN_FLAG=<hex> and the SQLi dump reaches the same row. Ran the current check: candid
  - Proposed check (judgment): v4_checks.py: add a runtime_constructed_prefix_sites list — DYNAMIC = r"\{[^}\n]*\}\s*=\s*\{[^}\n]*\}|\{\}\s*=\s*\{\}|%s\s*=\s*%s|\+\s*[\"']=[\"']\s*\+" — and, for each hit, emit the seeded keys of any table/dict the same file INSERTs into, so the judging agent is handed 'site app.py:691 renders KEY=VALUE over config_store, whose seeded k

### Metadata Accuracy - CWE / Vulnerability Kind Accuracy

- **Clause** — CWE and `vulnerability_kind` both precisely match the mechanism `solve.py` exploits.
  - Gap: conflict=='' (v4_checks.py:730) is the sole PASS signal and is emitted BOTH when declared sources genuinely agree AND when fewer than two declared sources resolve to a recognised family. An out-of-table cwe or kind term is silently dropped (verified: families('Reflected XSS')==set(), families('CWE-611')==set()), so a kind field that flatl
  - Mis-scored shape: task.toml cwe='CWE-89', vulnerability_kind='Reflected XSS', [task] name='app/sqli'; solve.py does SQLi. families(kind)==set() so it is dropped from the vote; cwe+name+docstring all say sqli -> conflict==''. The kind field is wrong (XSS != the SQLi mechanism) but never flagged. Human answer: not scor
  - Proposed check (mechanical): In identity_evidence add a positive-evidence block: sources_recognized = {src: sorted(fam) for src,fam in fam.items() if fam}; unrecognized = [src for src,fam in fam.items() if not fam and (meta value present)]; agreement = the single class when code_family and every recognised declared source name it, else the disagreement. Emit v4_ident

### Metadata Accuracy - Difficulty Explanation Accuracy

- **Clause** — Every named step matches current behavior exactly.
  - Gap: A PASS is established purely by the ABSENCE of candidate_mismatches, with no positive record of what was verified. There is no per-claim ledger, no coverage assertion that each of the three named-thing types (step/endpoint/formula) was actually exercised, and no file:line evidence attached to a pass. selftest.py:361-378 never checks that 
  - Mis-scored shape: Any bundle where the builder silently no-ops -- unrecognized router (B2), prose-only steps (B2), or no ALL_CAPS_UNDERSCORE tokens (B1). The evidence pack the scorer receives is identical to a fully-verified pass, so a human re-checking the audit cannot tell verification happened.
  - Proposed check (judgment): difficulty_claim_audit must emit a claim_ledger: one row per named step/endpoint/formula {claim_text, kind, status in {MATCHED, MISMATCH, NOT_ASSESSED}, evidence:'file:line'}, plus counts assessed_claims and per-kind coverage. Set fail (candidate_mismatches non-empty) only from MISMATCH rows. Force needs_judgment=True whenever assessed_cl

### Environment &amp; Segmentation - Verifier Token Wiring

- **Clause** — is that token actually set on the service it calls?
  - Gap: check_token_wiring (extract_evidence.py:690-811) never determines which service test.sh calls. extract_evidence.py:750 treats a hit on ANY service in env_map as coverage, so a token wired onto an unrelated sibling satisfies the check. I ran this: a bundle whose test.sh does `curl http://web:8080/internal/audit -H "X-Tok: $VERIFIER_TOKEN"`
  - Mis-scored shape: compose: main(no token), web(UPSTREAM=http://appsrv:8080), appsrv(no token), inventory_service(VERIFIER_TOKEN=abc123). tests/test.sh: `curl -s http://web:8080/internal/audit -H "X-Tok: $VERIFIER_TOKEN"`. appsrv/app.py gates on `request.headers.get("X-Tok") != VERIFIER_TOKEN` with a random fallback. 
  - Proposed check (mechanical): extract_evidence.py, new helpers feeding a rewritten check_token_wiring: (1) `_find_auth_calls(R)` regexes every `-H/--header "<Name>: <val>"` and python `headers={...}` entry in tests/**/*.sh|*.py, keeping those whose header name matches `(?i)^(authorization|cookie|api[-_]?key|x-[a-z0-9-]*(auth|token|key|secret|verifier|internal)[a-z0-9-

- **Clause** — If `tests/test.sh` reads a verifier/internal-auth token (VERIFIER_TOKEN) from its own environment
  - Gap: extract_evidence.py:698 reads only `tests/test.sh`. The verifier is frequently larger than that one file — 6aa05784's tests/test.sh:31 shells out to `python3 "$(dirname "$0")/solve.py"`, and tests/solve.py:18-20 does its own authenticated session setup. A token read and sent from tests/solve.py, or from a `python3 - <<'PY'` heredoc inside
  - Mis-scored shape: tests/test.sh calls `python3 tests/audit.py`; tests/audit.py does `requests.get("http://web:8080/internal/audit", headers={"X-Internal-Verifier": os.environ["VERIFIER_TOKEN"]})` and no compose service sets VERIFIER_TOKEN. Skill scores 5 and states no token exists.
  - Proposed check (mechanical): extract_evidence.py, `_verifier_scripts(R)`: glob `tests/**/*.{sh,bash,py}` excluding `__pycache__`, plus the bodies of `<<'PY' ... PY` heredocs inside test.sh, and run `_find_auth_calls` over all of them with per-file:line citations. Verified: on 6aa05784 this adds tests/solve.py, whose only credential is a runtime-issued `X-API-Key` fro

- **Clause** — "requires_justification": true (on the fail option)
  - Gap: extract_evidence.py:774-776 sets `score = 2` with `note = ""` on the main fail path, and the D10 evidence dict carries no `problems` key, so report.py:102-110 renders the fallback `f"check failed; evidence: {json.dumps(ev)[:400]}"` — a truncated dump of service_env — as the justification for a scored-2 dimension that the rubric marks requ
  - Mis-scored shape: Any bundle that trips `unwired` (e.g. the selftest broken fixture, selftest.py:544). The auditor form gets a JSON blob rather than "test.sh sends $VERIFIER_TOKEN (tests/test.sh:11) but appsrv, the service the call reaches via web (environment/web/app.py:38), sets no VERIFIER_TOKEN".
  - Proposed check (mechanical): extract_evidence.py, end of check_token_wiring: always build `note` for score 2 as a one-sentence chain — "<file:line> sends header <H> with <var>=<sent_value|EMPTY (unset on service `main`)>; the call reaches <svc> via <hop cite>; <svc> reads <var> at <file:line> and compares <H> at <file:line>, but its value at boot is <accepted_value|u

### Environment & Segmentation - Isolation and No Shortcut Routes

- **Clause** — Internal-only siblings must sit on a Compose network marked `internal: true`.
  - Gap: The evidence pack hands the judging agent the raw parsed compose dict (extract_evidence.py:1291) and asks it to eyeball the topology (workflow.js:173-176). No code resolves the network graph, so every non-obvious Compose form is unchecked: a service with no `networks:` key silently joins the implicit `default` network (never `internal: tr
  - Mis-scored shape: A compose file with `services: {web: {...}, appsrv: {...}, main: {...}}` and NO `networks:` key anywhere. Every service lands on the implicit `default` bridge, so `main` can `curl http://appsrv:8080/` directly and no network is `internal: true`. Because the literal token `internal: true` never appea
  - Proposed check (mechanical): New function `segmentation_evidence(R, compose, agent_svc="main")` in /Users/kunwar.singh/.claude/skills/qc-audit/extract_evidence.py, wired as `ev["d11_segmentation"]` beside `ev["compose"]` at extract_evidence.py:1291, and named in the D11 bullet at workflow.js:172-176. Resolve per service: `networks` list-form -> names; dict-form -> ke

- **Clause** — Is the environment segmented so the agent cannot reach this task's secret without the vulnerability?
  - Gap: The question says "reach this task's secret", not "reach it over HTTP". A shared Docker volume is a reach path that no part of the skill models. extract_evidence.py never compares the agent service's mounts against other services' mounts. 6aa05784 is a live example: `main` mounts `netinfo:/netinfo` (docker-compose.yaml:80) and so do `web`
  - Mis-scored shape: 6aa05784 with `main`'s volume list changed to include `shared_secrets:/shared` (a plausible copy-paste from the appsrv block, and in a task where the scored marker rather than a decoy is written there, fatal). `cat /shared/svc_token.txt` from the agent container yields the secret with no HTTP, no vu
  - Proposed check (mechanical): In `segmentation_evidence()` (extract_evidence.py): build `volnames(spec)` over both short-form `"src:dst:mode"` strings and long-form `{type, source, target}` dicts; compute `agent_mounts = volnames(services["main"])`; for every other service report `shared_with_agent = agent_mounts & volnames(spec)`. Then, for each shared volume, grep t

### Golden Solve / Oracle - Solve Script Writes the Submission

- **Clause** — Does `solution/solve.sh` (or the script it calls) write the recovered value to the submission path
  - Gap: extract_evidence.py:821 os.walk ingests every .sh/.py under solution/ and the write scan (:877) accepts a write found in ANY of them, with no check that the file is reachable from the solve.sh entrypoint. The clause's 'or the script it calls' is a transitive-invocation constraint that is never enforced, so a dead/unused helper satisfies t
  - Mis-scored shape: solution/solve.sh runs only `python3 solve.py`; solve.py computes the flag and just `print(flag)` (no write); an unused solution/leftover_notes.py contains `with open('/logs/verifier/submission.txt','w') as f: f.write(...)`. Human = 2 (Fail - No Write: the actual solve never writes the file). I buil
  - Proposed check (mechanical): In extract_evidence.py:check_solve_writes add reachable_from_solve(R): pick entrypoint solution/solve.sh (fallback solve.py); BFS its call graph with an invocation regex matching `(python3?|bash|sh|source|.) <x>.(py|sh)`, `./<x>`, `tests/<x>`, and `$(dirname "$0")/<x>` (reuse the shape of v4_checks.py gt_re at :264-268), resolving targets

- **Clause** — write the recovered value ... don't infer it from a `print(...)` call / [Fail - No Write] The recovered value only appears on stdout/logs
  - Gap: The check confirms a write EXISTS but never confirms WHAT is written. The write loop (:877-888) matches a sink pattern and excludes stdout, then score=5 (:902). It does not extract or classify the written value, so a solve that prints the recovered flag but writes a constant/placeholder/empty/wrong variable to the submission file is score
  - Mis-scored shape: solve.py does the real exploit into `flag`, `print(flag)`, then `with open('/logs/verifier/submission.txt','w') as f: f.write('TODO_PLACEHOLDER')`. The recovered value is only on stdout; a literal is written. Human = 2. I built this as d13_hardcode and check_solve_writes returned score=5.
  - Proposed check (mechanical): In check_solve_writes, after locating a submission write, capture the VALUE expression and classify it. Python: for `with open(SUB,'w') as h:` track handle h and inspect the following `h.write(EXPR)` / `print(EXPR,file=h)`; for inline `open(SUB,'w').write(EXPR)` and `Path(SUB).write_text(EXPR)` inspect EXPR. Shell: for `CMD > SUB` inspect

### Golden Solve / Oracle - Oracle Reward = 1

- **Clause** — score-5 pass option: "`reward` is exactly `1`, and `task/trajectories/oracle/` holds the `reward.txt` + `test.log` evidence from that run." (specifically 'from that run') and description 'On a fresh b
  - Gap: check_reward (extract_evidence.py:541) awards 5 on `reward.txt==1 AND test.log non-empty`. It never confirms the number was produced by the golden contract. I proved the miss: I copied reference bundle1, set trajectories/oracle/reward.txt='1' but trajectories/oracle/test.log='reason: Submission does not match ground truth' (a verbatim FAI
  - Mis-scored shape: trajectories/oracle/reward.txt = '1\n' while trajectories/oracle/test.log contains a FAIL-branch message from the task's own tests/test.sh (e.g. 'reason: Submission does not match ground truth', or 'FAIL: submitted value does not match the committed marker'), or a placeholder log with no success tok
  - Proposed check (mechanical): Add oracle_log_corroboration(R) in extract_evidence.py, called from check_reward when dim_id==14. Parse tests/test.sh: (1) resolve vars assigned a path matching reward\.(txt|json) (e.g. REWARD_TXT=... ), (2) detect helper funcs whose body writes the reward and treat `helper N` calls as writing value N, (3) walk lines tracking the last ech

- **Clause** — score-5 pass option: "`reward` is exactly `1`" (parse robustness of the value clause)
  - Gap: The regex fallback at extract_evidence.py:539 (`re.search(r"-?\d+(?:\.\d+)?", raw)`) grabs the FIRST integer anywhere in reward.txt when float() fails. A reward.txt that is not a clean number but happens to contain a 1 (e.g. a crash dump 'Traceback ... line 1', or 'attempt 1: reward unknown') parses to 1.0 and false-passes the value claus
  - Mis-scored shape: trajectories/oracle/reward.txt = 'Traceback (most recent call last):\n File ..., line 1' (oracle crashed, no numeric reward written) → regex extracts 1 → val=1.0 → score 5.
  - Proposed check (mechanical): Tighten the parse: accept only when the stripped reward.txt fullmatches `-?\d+(?:\.\d+)?` OR matches a `reward`-labelled number (e.g. `reward\s*[:=]\s*(-?\d+(?:\.\d+)?)`); otherwise set parsed=None and needs_judgment=true rather than scavenging the first digit. Mechanical; both references have raw='1' which fullmatches, so no false-fail.

### Noop / Free-Pass Resistance - Noop Reward = 0

- **Clause** — `reward` is exactly `0`, and `task/trajectories/noop/` holds the `reward.txt` + `test.log` evidence from that run.
  - Gap: The words 'from that run' are never tested. extract_evidence.py:541 asks only `os.path.exists(lg) and os.path.getsize(lg) > 0`; the log's content is copied to evidence at extract_evidence.py:558 and never compared to anything. The one artefact that could prove the reward came from a no-op execution of this verifier -- the log -- is treate
  - Mis-scored shape: Take 6aa05784 unchanged and copy trajectories/oracle/test.log over trajectories/noop/test.log, so noop/ holds reward.txt='0' + a log reading 'reason: Correct flag from intended endpoint' -- which is tests/test.sh:67, the branch that writes reward 1. I built this (mut/m1_copyoracle) and ran the real 
  - Proposed check (mechanical): New function `check_noop_log_attribution(task_root)` in v4_checks.py, called from extract_evidence.check_reward (extract_evidence.py:541) when dim_id == 15. (1) Read tests/test.sh; build a literal-assignment map (`VAR="literal"`) and textually expand $VAR/${VAR} so `> "$REWARD_TXT"` resolves to reward.txt. (2) Detect reward-writing helper

- **Clause** — On a fresh No-Op run, does `test.sh` score `reward = 0`?
  - Gap: Nothing in the skill asks whether a reward of 0 was even reachable for the right reason. A verifier that returns 0 because it could not reach the app produces a reward.txt indistinguishable from one that returns 0 because the free pass was resisted, and check_reward (extract_evidence.py:541) scores both 5. On this dimension -- whose title
  - Mis-scored shape: 6aa05784 with noop/test.log = 'reason: Could not reach verifier audit endpoint' (tests/test.sh:12 -- curl to web:8080 failed, so the verifier exited before the endpoint-match, the ground-truth re-derivation and the submission compare ever ran). I built this (mut/m4_infra) and ran the real extractor:
  - Proposed check (judgment): In the same `check_noop_log_attribution`, classify each attributed reward-0 branch with INFRA = re.compile(r'could not reach|unreachable|could not parse|could not derive|connection refused|timed? ?out|no route|curl|failed to start|not running|internal error|traceback|exception', re.I). If EVERY attributed reward-0 line is INFRA, set needs

- **Clause** — `reward` is exactly `0`
  - Gap: extract_evidence.py:537-540 falls back to `re.search(r'-?\d+(?:\.\d+)?', raw)` whenever float() fails, so 'exactly 0' is decided by the FIRST number anywhere in the file rather than by the file being the number 0. I ran the parse in isolation: '0\n1' -> 0.0, 'FAIL 0 of 1' -> 0.0, 'reward: 0' -> 0.0, '0 (noop)' -> 0.0 -- all scored as exac
  - Mis-scored shape: trajectories/noop/reward.txt containing '0\n1\n' (two appended runs -- the second is the free pass) or 'FAIL 0 of 1'. Parses to 0.0, test.log non-empty, D15 = 5.
  - Proposed check (mechanical): In extract_evidence.check_reward, after the existing parse, add a strictness flag: `bare = re.fullmatch(r'[-+]?(?:\d+(?:\.\d+)?|\.\d+)', raw or '') is not None`. Keep the lenient value for scoring (so no behaviour change on well-formed files) but when `bare` is False set needs_judgment with _why_judgment = f'trajectories/noop/reward.txt i

- **Clause** — [Fail - No-Op Succeeds]\n`reward.txt` from a fresh No-Op run contains a non-zero result. (requires_justification: true)
  - Gap: The score-2 path emits this option text verbatim regardless of WHY it failed, and extract_evidence.py:554-555 passes an empty note, so the justification the option demands is never written. When reward.txt is absent the report asserts something factually false about the bundle, and report.py:112 then prints `check failed; evidence: {json 
  - Mis-scored shape: Three shapes I built and ran through the real extractor, all reporting 'Answer: [Fail - No-Op Succeeds] `reward.txt` from a fresh No-Op run contains a non-zero result.' with note=''. m8_missing: noop/reward.txt deleted (reward_txt_raw=None). m9_json_only: reward.txt replaced by reward.json={'reward'
  - Proposed check (mechanical): In extract_evidence.check_reward, build the note instead of leaving it empty: note = 'trajectories/noop/reward.txt is absent (the directory holds: <listdir>)' when raw is None and the dir exists; 'trajectories/noop/ does not exist; sibling trajectory dirs present: <names under trajectories/>' when the dir is missing; 'trajectories/noop/te

### Verifier - Reward Schema Validity

- **Clause** — or `reward`'s value is non-numeric.
  - Gap: harbor_checks.py:265 does `val = vm.group(1).strip("'\"")` before the numeric test, so a JSON STRING value is unquoted into a number and passes. `{"reward": "1"}` is a schema mismatch for Harbor's typed model but scores 5 today.
  - Mis-scored shape: P4: `echo '{"reward": "1"}' > "$LOGS/reward.json"` + `echo 1 > "$LOGS/reward.txt"`, with no reward.json artefact in trajectories (or artefacts captured only from the reward=0 branch). Measured today: every_branch PASS, writer WARN => D16 5/5.
  - Proposed check (mechanical): harbor_checks.py `payload_shape` (see above): judge the value AFTER json.loads of the payload, not by regex on the raw token — `isinstance(obj['reward'], bool) or not isinstance(obj['reward'], (int, float))` => FAIL '[Fail - reward.json Structure]'. Record `value_token` separately so `$R`-style writers are reported as 'numeric-capable, re

- **Clause** — `reward.json` contains only the numeric key `reward`, and its value matches `reward.txt`.
  - Gap: The 'matches' half is only tested against artefacts and only when a sibling reward.txt happens to exist (extract_evidence.py:586-592, `elif sib_raw is not None`). A reward.json with no sibling records nothing at all. And the two writes inside test.sh itself are never compared, so a branch that writes disagreeing values is a clean pass.
  - Mis-scored shape: P7: the error branch writes `echo '{"reward": 0}' > "$LOGS/reward.json"` immediately followed by `echo 1 > "$LOGS/reward.txt"` (a copy-paste slip that hands Harbor 0 and the human reviewer 1). Measured today: every_branch PASS ('reward.json x2, reward.txt x2'), writer PASS => D16 5/5. Second shape: 
  - Proposed check (mechanical): TWO checks. (1) v4_checks.py new `pair_consistency(text)`: within each frame/function body, zip the ordered reward.json write sites with the reward.txt write sites and require the value tokens to be the same numeric literal or the same variable/positional parameter; FAIL otherwise, citing both line numbers. Verified: prototype PASS on REF

- **Clause** — [Fail - No Reward Written] Any branch of `test.sh` can exit (including a `set -e` abort or a failed `$(...)`) without writing both `reward.json` and `reward.txt`.
  - Gap: FALSE-FAIL RISK, not a miss: v4_checks.py:108 recognises an EXIT trap only as `trap "..."` / `trap '...'` with a reward path inside the quotes. The idiomatic form `trap finish EXIT`, where `finish()` writes both files, is not matched, so every risky substitution in such a script is reported as fatal even though the trap covers exactly the
  - Mis-scored shape: P8: `set -e`; `finish() { echo "{\"reward\": $RESULT}" > "$LOGS/reward.json"; echo "$RESULT" > "$LOGS/reward.txt"; }`; `trap finish EXIT`; `EXPECTED=$(python3 "$(dirname "$0")/solve.py")`. Measured today: FAIL, 'set -e with unguarded command substitution(s) before any reward write: line 10' => D16 2
  - Proposed check (mechanical): v4_checks.py: widen the trap detection to `^\s*trap\s+(.+?)\s+(?:EXIT|0)\b` and accept it when the trap argument either contains a reward path OR names a function whose body writes BOTH files; record `exit_trap_writes_both` and the covering function in the evidence. Verified: prototype flips P8 from FAIL to PASS ('line 8: trap calls finis

- **Clause** — For all options except the last, apply the error category.
  - Gap: report.py:377-379 prints the raw `error_categories` string, which for this dimension holds BOTH mappings: '[All] [All] [Fail - reward.json Structure]; [All] [All] [Fail - No Reward Written]'. I confirmed this in a real artefact: /Users/kunwar.singh/Downloads/Claude/6aa4219a_task2_pathtrav_qc_report.txt:119 shows both categories next to a 
  - Mis-scored shape: Any D16 fail. On REF B the report prints both categories although only the second applies; a reviewer who copies the first line files the wrong category on the auditor form.
  - Proposed check (mechanical): report.py `feedback_for`/the emit loop at report.py:377-379: split `r['error_categories']` on ';', match the segment whose trailing `[Fail - ...]` label equals the `[Fail - ...]` prefix of the chosen option text, and print only that segment (falling back to the whole string when no segment matches). Mechanical and purely presentational; c

- **Clause** — `reward.json` contains only the numeric key `reward`, and its value matches `reward.txt`.
  - Gap: A pass is recorded as the absence of a complaint. On REF A the whole D16 pass renders as three lines — /Users/kunwar.singh/Downloads/Claude/6aa05784_ssrf_qc_report.txt:118-121: 'Score: 5/5 [deterministic] / Feedback: All mechanical checks passed.' — produced by report.py:109-110, with no evidence lines at all because report.py:386 prints 
  - Mis-scored shape: P10: a test.sh whose only occurrence of the string reward.json is the comment '# Harbor reads /logs/verifier/reward.json; we write the txt form below.' and which writes only reward.txt, in a pack whose trajectories hold only oracle/noop reward.txt. Measured: every_branch PASS 'reward.json x1, reward
  - Proposed check (mechanical): extract_evidence.py `check_reward_schema`: assemble a `proof` block (the five sub-checks above) and adopt a three-valued status per sub-check — PASS / FAIL / UNPROVEN. Score 5 only when all five are PASS. When any is UNPROVEN, keep the score but set `needs_judgment: True` and `_why_judgment` naming the unproven clause, so report.py:380-38

### Verifier - Anti-Cheat Order

- **Clause** — Does an endpoint-match (or equivalent disclosure check) exist in `tests/test.sh`, and does it run BEFORE ground-truth re-derivation
  - Gap: gt_re (v4_checks.py:266-270) is matched against the whole de-commented line, so the word `solve` inside a STRING ARGUMENT counts as a ground-truth invocation. The de-commenter at :226-240 strips `#` comments but nothing distinguishes a command from an echo argument. This FALSE-FAILS, which is worse than a false pass: it turns a human-5/5 
  - Mis-scored shape: REF1's exact test.sh with one extra harmless line after the shebang: `echo "starting verifier; will solve later"`. Fixture .../d17probe_kx/E; the shipped check returns {"status":"FAIL","detail":"anti-cheat comparison at line 25 runs AFTER ground-truth re-derivation at line 2"}. Same misfire for `ech
  - Proposed check (mechanical): In /Users/kunwar.singh/.claude/skills/qc-audit/v4_checks.py, gate the gt_re match at :295 on command position. Add `_segments(line)` (quote-aware split on `;`, `&&`, `||`, `|`) and `_leadword(seg)` (`^\s*(?:!\s*)?(?:[A-Za-z_]\w*=\S*\s+)*([A-Za-z0-9_./-]+)`); skip any segment whose lead word is in {echo, printf, :, true, false, cat}. Only 

### Secrets - Fresh Canary and Live Re-Derive

- **Clause** — • A static `flag{...}` in source
  - Gap: "in source" is tested only against an extension whitelist (v4_checks.py:388: .py .js .sh .ts .go .sql .json .env .yaml .yml) under environment/. Dockerfiles, .conf, .html, .txt, .md, templates, seed data and any other file type are never opened, so a static flag living there is invisible — and the whitelist also means a non-Python/JS app 
  - Mis-scored shape: Copy of B1 with `ENV APP_FLAG=flag{static_baked_value_2024}` appended to environment/appsrv/Dockerfile (dir m3_dockerflag). The literal is a static flag{...} in source, baked into the image layer and identical in every trial; current check returns PASS with baked_literals=[]. Mirror case: an httpd-s
  - Proposed check (mechanical): v4_checks.py: replace the whitelist walk at v4_checks.py:385-391 with `_corpus(root, subdirs=("environment","tests","solution"))` returning [(relpath, text)] for every file under 2 MB whose bytes decode as UTF-8 and contain no NUL (skipping .git/node_modules/__pycache__/.venv), then run `_static_flag_sweep(corpus, prefixes)` per line: mat

- **Clause** — The secret is generated per boot and the verifier re-derives ground truth from the running app.
  - Gap: Nothing in the D18 output is re-checkable by a human. v4_checks.py:390 concatenates every environment file into one `blob` with no filename or offset, so csprng_call_sites (v4_checks.py:471-473) records line TEXT only — no file, no line number — and a flag{...} hit could not be attributed to a file even if found. Worse, the PASS `detail` 
  - Mis-scored shape: Reference bundle B1 itself: the 5/5 is correct, but the evidence cites SHARED_SVC_TOKEN (the inventory decoy token, environment/inventory_service/entrypoint.sh:10), TOKEN_SIGNING_SECRET (an HMAC key, appsrv/app.py:44) and VERIFIER_TOKEN (the audit auth header, appsrv/app.py:40). A reviewer re-checki
  - Proposed check (mechanical): v4_checks.py: build the corpus as [(relpath, text)] and record every finding as {file, line, text} (helper `_find_sites(corpus, pattern)` returning file/line/text). Make check_fresh_canary return, for a PASS, `canary_identity {var, prefix, file, line, text, why_ranked}`, `binding {file, line, rhs, kind}`, `boot_path {entrypoint, exec_site

- **Clause** — (`token_hex` / `urandom` or equivalent)
  - Gap: The CSPRNG vocabulary at v4_checks.py:396-397 is both too narrow and too loose. Missing "equivalents": uuid.uuid4(), crypto.randomBytes / crypto.randomUUID (Node), random_bytes (PHP), SecureRandom (Java/Ruby), crypto/rand (Go), and direct reads of /dev/urandom (`head -c 24 /dev/urandom | xxd -p`, `dd if=/dev/urandom`). Too loose: `$RANDOM
  - Mis-scored shape: False-FAIL direction: a Node bundle whose canary is `const TASK_MARKER = crypto.randomBytes(24).toString('hex')` in environment/app/server.js — not in the CSPRNG regex, so per_boot=False and any_csprng=False, and v4_checks.py:485-487 emits "no CSPRNG ... appears anywhere in the environment" → 2/5 on
  - Proposed check (mechanical): v4_checks.py: widen CSPRNG to (?:secrets\.token_(?:hex|urlsafe|bytes)|secrets\.choice|secrets\.randbelow|os\.urandom|SystemRandom|uuid\.uuid4|uuidgen|openssl\s+rand|/dev/urandom|crypto\.randomBytes|randomUUID|random_bytes|SecureRandom|crypto/rand) and move `$RANDOM` (and bare `random.random`/`Math.random`/`rand()`) to a separate WEAK_PRNG

### Pass@k Verification - Pass@k Calibration (Genuine Model Fails)

- **Clause** — A model that burns the full timeout (60 minutes is the agreed reasonable budget) with no result gets reward 0 and is a fail, regardless of how fast the oracle solved it.
  - Gap: Both this clause and its mirror exclusion are unimplemented in practice. classify_fail returns INFRA_EXCEPTION for any exception (harbor_checks.py:186-187) before the LOW_TIMEOUT arm (harbor_checks.py:204-205), so v4_checks.py:834's sub-60-minute test can never see a wall-clock timeout; it also reads three keys the extractor never sets (m
  - Mis-scored shape: Two directions, both built and run. (a) FALSE PASS: copied 6aa4219a and set both timed-out trials to config.agent.override_timeout_sec = 1800.0 with a 30-minute agent_execution window — a genuine sub-60-minute harness cut, so both fails are excluded and the only remaining trial is gemini's reward=1,
  - Proposed check (mechanical): In v4_checks.d19_passk_calibration, per trial: effective_budget = (result.json .config.agent.override_timeout_sec or .config.agent.max_timeout_sec or 3600.0) * (.config.agent_timeout_multiplier or .config.timeout_multiplier or 1.0); elapsed = agent_execution.finished_at - agent_execution.started_at; at_cap = "Timeout" in (exception_info.e

- **Clause** — From the CB's saved `/passk` run, open each model's reward and its `analyze-results/<job>.json` verdict.
  - Gap: The second half of the method line is never executed. extract_evidence.py:1113-1118 collects analyze-results JSON into an opaque list, does not key it to any model, and v4_passk_verdicts(models) (v4_checks.py:755) never receives it. Its ABSENCE is equally invisible: both reference bundles have analyze_results == [] and both harbor-analyze
  - Mis-scored shape: A packet whose analyze-results/<job>.json records a per-model verdict that contradicts the shipped reward file — e.g. analyze-results says the kimi job errored/was voided while verifier/reward.txt still reads 0 — or, conversely, a packet with NO analyze-results at all (both references). Today both r
  - Proposed check (mechanical): In v4_checks.d19_passk_calibration: ares = glob(pass@k/**/*.json) filtered on os.path.basename(os.path.dirname(p)) containing "analy" (tighten the current path-wide test). For each file, index its per-trial entries by trial_name/trial id and add the verdict to trials[i].reward_sources under the key "<rel path>:.<field>". If ares is empty,

- **Clause** — Do at least 1 of the 3 models fail (reward < 1) in the shipped `trajectories/pass@k/` results?
  - Gap: The reward that decides the dimension comes from one file with no corroboration and no failure mode. v4_checks.py:770-781 reads reward_txt (or `reward`) and returns None when it cannot parse; the None then falls through v4_checks.py:793 and lands in the catch-all counted branch at v4_checks.py:849-853, so an unreadable or missing reward i
  - Mis-scored shape: A packet where two models solved and the third trial's verifier crashed, leaving verifier/reward.txt absent (or containing "" / "None"). Verified at the function level: v4_passk_verdicts({"m1": {"classification": "GENUINE"}, "m2": {"reward_txt": "1"}, "m3": {"reward_txt": "1"}}) returns d19_score_hi
  - Proposed check (mechanical): In v4_checks.d19_passk_calibration, build trials[i].reward_sources as a dict of {file:field -> float} over verifier/reward.txt, verifier/reward.json:.reward, result.json:.verifier_result.rewards.reward, the job result.json:.stats.evals[<eval>].reward_stats bucket that lists this trial's trial_name, and any analyze-results verdict. Then: 0

- **Clause** — [Fail - No True Failures] • No model fails (all 3 score `reward = 1`) • Every `reward < 1` is excluded as `task_specification` (the task is broken or unsolvable) or a refusal
  - Gap: The option is a two-bullet disjunction over a THREE-model packet, but nothing ties the verdict to the packet's census or provenance. extract_evidence.py:1146 computes model_count and v4_checks.py:755-854 ignores it; _trial_dirs (extract_evidence.py:1008-1017) only recognises a trial when a verifier/ subdir exists; and when trajectories/pa
  - Mis-scored shape: (a) A bundle that ships one failing trial and no others: today d19 = 5 with no note that 1 of 3 models ran. (b) A fabricated packet where the same trial is copied into three model-named directories: today three counted fails, 5, no duplicate detected (the shipped dirs ARE renamed by the CB — both re
  - Proposed check (mechanical): In v4_checks.d19_passk_calibration add model_census and provenance assertions: len(trial_dirs) == job result.json .n_total_trials; len({trial .trial_name}) == len(trial_dirs); len({trial .agent_info.model_info.name}) == 3 and each is a suffix of one configured .agents[].model_name from task-*/config.json or harbor-job.json; every trial .c

- **Clause** — A model that does not solve the assigned/intended vulnerability is a fail, regardless of what path it took.
  - Gap: A counted fail is emitted with no trace of the three exclusion tests that were supposedly applied. v4_checks.py:849-853 writes {"model", "classification", "why": "did not solve the assigned vulnerability"} — no reward value, no file path, no oracle fact, no command count, no budget number. The exclusions are only implicit in control flow 
  - Mis-scored shape: Any packet with an unparsable trial result.json: exception_info, episodes and override_timeout_sec all become None, every exclusion test degrades to "cannot apply", and the model is reported as a clean counted fail indistinguishable from bundle 6aa05784's three real ones. The two hunters that D19 al
  - Proposed check (mechanical): Make v4_checks.d19_passk_calibration emit, per trial, an explicit exclusion_tests list of exactly three records — {"exclusion": "task_specification"|"refusal"|"sub_60_minute_budget", "applies": bool, "unknown": bool, "evidence": "<the numbers actually read>"} — plus verdict_basis = "reward <x> < 1 and all three rubric exclusions were test

- **Clause** — Not attempting counts the same as attempting and failing. A model that never attempts or probes the intended vulnerability is still a fail.
  - Gap: The rule is implemented (v4_checks.py:847-853) but it collides with the refusal exclusion and nothing states the boundary. A never-attempting model and a refusing model are the same trial shape minus one sentence, and classify_fail decides between them with a regex over the whole transcript blob (harbor_checks.py:197). The evidence pack a
  - Mis-scored shape: A model that opens the app, reads the index, writes "I can't see a way in here" and stops: zero engagement plus a decline-shaped phrase. The rubric counts it as a fail (never attempted); today it is labelled REFUSAL and excluded. In a packet where all three behave that way, D19 flips 5 -> 2.
  - Proposed check (mechanical): In v4_checks.d19_passk_calibration, make the no-attempt / refusal boundary explicit and printed: no_attempt = n_app_commands > 0 and chain_requests == 0 and technique_attempts == 0 => COUNTED FAIL with why="never probed the intended vulnerability — the rubric counts not attempting the same as attempting and failing"; refusal requires n_ap

### Pass@k Verification - Complexity Integrity — No Shortcut Wins

- **Clause** — Every `reward = 1` trial on the shipped 3-model packet used the intended endpoint and the claimed CWE.
  - Gap: A packet with ZERO reward=1 trials produces byte-identical output to a packet whose winners were all verified clean: d20_shortcut_wins=[], d20_score_hint=5, and the literally false reason string "every reward=1 trial used the intended endpoint and claimed CWE" (v4_checks.py:865). I confirmed this on bundle 1, which has three reward=0 tria
  - Mis-scored shape: Any packet where all three models score 0 (bundle 1 itself). Worse: a packet whose reward.txt files are missing or unparseable — _reward_num returns None, every trial falls through to the D19 branch, d20_shortcut_wins stays empty and D20 reports the same confident 5 even though the winner set was ne
  - Proposed check (mechanical): New function `v4_checks.d20_shortcut_audit(task_root)` returning an explicit `status` field, and v4_passk_verdicts() replacing `d20 = 2 if shortcut else 5` (v4_checks.py:855) with it. status must be one of NO_PACKET (trajectories/pass@k absent) / VACUOUS_NO_WINNER (packet present, n_winners==0) / PASS_VERIFIED (n_winners>=1 and every winn

- **Clause** — On the shipped 3-model packet
  - Gap: extract_evidence.py:1068 keys the model map by `f"{name} [{os.path.basename(md)}]"`. Trial dir basenames repeat across job dirs (gemini-3-7-flash-task, kimi-k3-task, deepseek-v4-pro-0813-task), so when more than one job directory sits under trajectories/pass@k the later one silently overwrites the earlier. D20's winner set is then compute
  - Mis-scored shape: A bundle shipping two pass@k runs (a re-run kept beside the shipped one, or an eval-set packet dropped into the same folder). I demonstrated it: copied task-20260915-160854 to task-20260916-999999 in a throwaway copy of bundle 2, then ran E._trial_dirs -> 6 dirs, but E.passk_evidence -> model_count 
  - Proposed check (mechanical): In extract_evidence.passk_evidence, key models by the job-qualified relative path: `key = f"{name} [{rel(root, md)}]"`, and add `d20_packet_shape` = {job_dirs: sorted distinct first path segments under pass@k, trials_per_job, declared_agents: [a['model_name'] for a in json.load(harbor-job.json)['agents']]}. In d20_shortcut_audit, set stat

- **Clause** — Any `reward = 1` trial
  - Gap: The winner set is derived from verifier/reward.txt alone. v4_checks.py:770-782 _reward_num tries keys 'reward_txt' and 'reward'; the model dict (extract_evidence.py:1069-1078) only carries 'reward_txt' and 'reward_json', so reward.json is dead as a reward source, and `grep -n "verifier_result|rewards"` over extract_evidence.py, v4_checks.
  - Mis-scored shape: A trial with verifier/reward.json {"reward": 1} and result.json verifier_result.rewards.reward = 1 but a missing or stale verifier/reward.txt (the exact shape D16's every-branch check exists to police). D20 reports 'no shortcut wins' while an unaudited win sits in the packet.
  - Proposed check (mechanical): In d20_shortcut_audit, read all three sources per trial: verifier/reward.txt, verifier/reward.json['reward'], result.json['verifier_result']['rewards']['reward']. A trial is a winner if ANY parses to >= 1. If the three disagree, set status=NEEDS_JUDGMENT and emit `reward_source_conflict: [{trial, reward_txt, reward_json, result_json}]`. O

- **Clause** — This is still complexity validation, not the eval set.
  - Gap: The skill has no concept of which packet is the complexity packet. _trial_dirs (extract_evidence.py:1008-1017) swallows every trial under trajectories/pass@k regardless of job, and extract_evidence.py:1121 does not load harbor-job.json, the only file carrying job_name / n_attempts / the agent roster. The description's explicit scoping ins
  - Mis-scored shape: A bundle that ships both the 3-model complexity packet and a larger eval-set run under trajectories/pass@k. D20 would audit wins from the eval set (out of scope per the description) and, because of the key collision above, could drop the complexity packet's own trials.
  - Proposed check (mechanical): In d20_shortcut_audit, parse trajectories/pass@k/harbor-job.json and report {job_name, n_attempts, n_concurrent_trials, agents[].model_name}. Scope the winner set to trial dirs whose parent basename equals job_name; report any trial dir outside it under `out_of_scope_trials` and set status=NEEDS_JUDGMENT rather than scoring. Cross-check t

### Pass@k Verification - Complexity Integrity — Discoverable Path

- **Clause** — At L0/L1, is the sink discoverable from the running app without the exact URL?
  - Gap: The route inventory that all app-side reasoning rests on is both under- and over-inclusive, and its failure is silent. Over-inclusive: `_ROUTE_DECL`'s Express branch at extract_evidence.py:1377 `\b\w+\.(?:get|post|put|patch|delete|all|use)\s*\(\s*[\"'`]([^\"'`]+)` matches ANY `obj.get("key")`. I ran `EE._route_of` line by line over bundle
  - Mis-scored shape: Any task built on http.server / BaseHTTPRequestHandler, a Go net/http switch on r.URL.Path, a Node http.createServer with a manual if/else router, or any framework not in _ROUTE_DECL, where all three models fail. route_count is nonzero (junk), the NOT-ASSESSABLE guard does not fire, sibling_api_fami
  - Proposed check (mechanical): Two edits in extract_evidence.py. (1) In `_route_of` (extract_evidence.py:1414-1419), after `m = _ROUTE_DECL.search(line)`, take `gi = list(m.groups()).index(raw)` and return None when `gi == 3 and not raw.startswith("/")` — the generic Express branch must see a literal already starting with "/". Also reject header-shaped paths via `re.co

- **Clause** — It must not be a zero-signal needle.
  - Gap: `index_or_listing_routes` (extract_evidence.py:1474-1475) matches route NAMES against a word list and never reads what those routes return. It is pure name-pattern astrology: it reported `["/", "/api/admin/dashboard"]` for my needle bundle where `/` had been stripped of the sink entry, so the block still advertised two 'discovery surfaces
  - Mis-scored shape: Any app that keeps a `/` or `/dashboard` route which returns `{"status":"ok"}` while the sink is unlisted. The judge reads index_or_listing_routes=['/','/dashboard'] plus hint=true and concludes a discovery surface exists.
  - Proposed check (mechanical): Replace `index_or_listing_routes` with `publishing_routes`: a route qualifies only when `served_links[route]` is non-empty after self-reference removal — i.e. it demonstrably puts at least one OTHER path into its response body. Report each as `{route, publishes: [paths], file:line}`. VERIFIED with the prototype: 6aa05784 -> `/` publishes 

### Vulnerability Type - Correctness

- **Clause** — Fail is "objectively misaligned" (binary 5/2, no partial credit)
  - Gap: The requiredReading branch for dim 22 (workflow.js:64-71) is written for dim 8 and describes a 'score-5 / score-3 / score-2 boundary' and the second-order-precision rule. Dim 22 has only score 5 and score 2. This primes the agent to look for a middle tier that does not exist and to treat a broad-but-correct radio as a deduction.
  - Mis-scored shape: A specifically-BOLA task with radio="Broken access control: IDOR / BOLA". IDOR and BOLA are ONE combined radio class, so this is ALIGNED (5); a dim-8-primed agent may reason 'broad label → imprecise → dock it' and wrongly score 2. (Neither reference bundle is IDOR, so this does not false-fail them, 
  - Proposed check (judgment): Give dim 22 its own requiredReading arm in workflow.js:63: state the bar is binary (aligned vs objectively-different-class), that IDOR and BOLA are a single radio class so a same-family broad label is aligned, and hand the agent ev['vuln_type_audit'] (radio_class, solve_class, status) instead of the dim-8 three-tier text.

### Explanations - Spam Check

- **Clause** — are spam
  - Gap: Nothing in the skill implements any spam test. No deterministic verdict exists for 23 (no `verdict(23, ...)` anywhere in extract_evidence.py), `grep -rn "spam"` over all .py/.js/.md returns nothing, and workflow.js:63-69 hands D23 `'(none beyond the evidence pack)'` as its required reading. The mechanically-decidable spam shapes — empty b
  - Mis-scored shape: form_fields = {"vulnerability_explanation": "n/a", "complexity_increase": "asdf asdf asdf asdf", "model_failure_reason": ""}. I ran this through report.py: D23 renders `NOT SCORED`, and if the single agent returns 5/5 nothing in workflow.js challenges it (D23 is not in HIGH_RISK at workflow.js:15).
  - Proposed check (mechanical): In `check_explanations_spam()` (extract_evidence.py), per field, hard-FAIL (score 2, option = the verbatim [Fail - Spam Explanations] text) if ANY of: (a) present and `text.strip() == ""`; (b) `re.fullmatch(r"\s*(n/?a|none|tbd|todo|test+|asdf+|xxx+|\.+|-+|lorem ipsum.*|same as above|see above)\s*\.?\s*", text, re.I)`; (c) `len(text.strip(

- **Clause** — Are any of the explanation fields spam?
  - Gap: When the fields are absent the dimension is not answered AND the report still prints a global pass. report.py:440-446 computes `_unrun = len(rubric) - len(scored) - _na` and `_overall = "FAIL" if fails else ("INCOMPLETE" if _unrun else "PASS")` — NOT ASSESSABLE dimensions are subtracted out, so they cannot make the audit incomplete. SKILL
  - Mis-scored shape: Reference bundle 2 (6aa4219af13d451666f8427f) itself: it has no fields file, so the pack's evidence.form_fields is null and D23 renders NOT ASSESSABLE while the human scored it 5/5. Any bundle audited without fields gets a clean OVERALL verdict with one rubric row never looked at.
  - Proposed check (mechanical): report.py `main()`: change line 443 to `_overall = "FAIL" if fails else ("INCOMPLETE" if (_unrun or _na) else "PASS")`, and extend the INCOMPLETE note at report.py:445-447 with `"Dimension 23 (Explanations - Spam Check) has no answer: the three explanation boxes were not supplied. Ask for them — they are on the platform submission form, n

- **Clause** — "Vulnerability Explanation", "Complexity Increase", or "Model Failure Reason"
  - Gap: Two silent-drop paths make supplied fields vanish and then mis-report why. (1) extract_evidence.py:1348 `if a.fields and os.path.exists(a.fields):` — a mistyped path is silently ignored; I ran the extractor on bundle 2 with `--fields .../DOES_NOT_EXIST_ks.json` and it exited 0 with `evidence.form_fields = None`. (2) A well-formed file wit
  - Mis-scored shape: Operator writes `$WORK/fields.json` but types `--fields $WORK/form_fields.json`, or names the keys `vuln_explanation` / `complexity` / `failure`. The audit reports D23 NOT ASSESSABLE and (per the previous gap) still prints OVERALL: PASS, while the operator believes the fields were scored.
  - Proposed check (mechanical): extract_evidence.py `main()`: replace line 1348 with `if a.fields:` and, when `not os.path.exists(a.fields)`, `raise SystemExit(f"--fields {a.fields} does not exist; dimensions 22 and 23 would be silently unscored")`. Immediately after the json.loads at line 1350 add key validation: `if not isinstance(fields, dict): fields = {"_parse_erro

## LOW (13)

### Structure - Required Files & Validity

- **Clause** — [Fail - Required Structure] Any required file is missing, empty
  - Gap: extract_evidence.py:219 uses `os.path.exists`, and 226 uses a bare `os.listdir` comprehension with no `os.path.isfile` guard. A directory satisfies exists(), has non-zero st_size, returns True from is_exec() (directories carry the +x bit), and makes has_shebang() raise IsADirectoryError which line 184-185 swallows as False — so the `is_ex
  - Mis-scored shape: Bundle 2 with tests/test.sh replaced by a DIRECTORY named tests/test.sh containing real.sh. VERIFIED: check_structure() returned score 5, problems [] — there is no grader in the bundle at all. Second verified shape: all instruction*.md deleted and a DIRECTORY named instruction_L0.md created — score 
  - Proposed check (mechanical): extract_evidence.py:219 — change the presence test to `if not os.path.isfile(p): problems.append('MISSING' if not os.path.exists(p) else f'{label} exists but is not a regular file ({"directory" if os.path.isdir(p) else "special file"})')`. extract_evidence.py:226 — add `os.path.isfile(os.path.join(R, f)) and` to the comprehension. Add a s

- **Clause** — or a referenced script isn't executable / has no shebang.
  - Gap: has_shebang (extract_evidence.py:180-185) reads exactly two bytes and returns True for `#!`. A CRLF-terminated shebang line passes that test but is not executable on Linux: the kernel takes the trailing \r as part of the interpreter path and the exec dies with 'bad interpreter: /bin/bash^M'. That is precisely the condition the clause name
  - Mis-scored shape: Bundle 2 with a single \r inserted before the newline of tests/test.sh line 1 (`#!/usr/bin/env bash\r\n`) — the shape produced by authoring on Windows or by a careless editor. VERIFIED: check_structure() returned score 5, problems []. The grader would never run, so every trajectory reward in the bun
  - Proposed check (mechanical): extract_evidence.py, inside the referenced-script loop: read the first line as bytes and `if first.rstrip(b'\n').endswith(b'\r'): problems.append(f"{rel(R,p)}:1: shebang line has a CRLF terminator; exec will fail with 'bad interpreter'")`. Apply to solution/solve.sh, tests/test.sh and every script resolved by the referenced-scripts check.

### Structure - Compose Service Contract

- **Clause** — No service named exactly `main` in `environment/docker-compose.yaml`.
  - Gap: A file that declares `main:` twice passes today: PyYAML's safe_load silently keeps the last duplicate, so extract_evidence.py:319 sees one `main` key and scores 5. `docker compose config` refuses to parse the file at all: `failed to parse …: yaml: construct errors: line 1: line 6: mapping key "main" already defined at line 2` (rc=1, I ran
  - Mis-scored shape: services: main: build: ./agent web: image: alpine main: image: alpine (A merge/paste artefact — the commonest way a hand-edited compose goes wrong.) Correct D2 = 2/5; today = 5/5.
  - Proposed check (mechanical): extract_evidence.py, `check_compose_main_deep(R)`. Because `yaml.compose()` preserves every (key_node, value_node) pair, count `[k for k,_,_ in pairs(services_node) if k == "main"]`; if `len > 1`, score 2 with problem `f"`main` is declared {n} times ({rel}:{l1}, {rel}:{l2}); docker refuses the file: 'mapping key \"main\" already defined'"

- **Clause** — A `main` service exists in environment/docker-compose.yaml
  - Gap: A `main` service that is excluded from the default compose project scores 5 today with no trace. With `profiles: ["debug"]` on `main`, `docker compose config --services` prints only `web` — `docker compose up` never creates the agent container — yet extract_evidence.py:319-321 sees the key and scores 5 with `problems: []`. Same for `deplo
  - Mis-scored shape: services: main: build: ./agent profiles: ["debug"] web: image: alpine Today = 5/5 silent. Required: 5/5 with an explicit OPEN QUESTION carrying the docker output, so the human decides.
  - Proposed check (mechanical): extract_evidence.py, `check_compose_main_deep(R)`: detect `spec.get("profiles")` non-empty and `spec.get("deploy", {}).get("replicas") == 0`; do NOT change the score (that would risk false-failing against the rubric's literal "exists" wording), but append `main_in_default_profile: WARN (profiles=[…])` / `main_replicas_nonzero: WARN` to `e

- **Clause** — [Fail - No `main` Service] No service named exactly `main` in `environment/docker-compose.yaml`.
  - Gap: All fail paths collapse into one string, `f"no service named exactly `main`; found: {svcs or 'none'}"` (extract_evidence.py:326-327). A missing compose file, an unparsable compose file (compose stays None at extract_evidence.py:250-253), and a parsed file with no `main` all print `found: none`. The verdict cites no file:line, so a human c
  - Mis-scored shape: services: agent: build: ./agent container_name: main web: image: alpine Correct D2 = 2/5 (today's score is right), but the feedback says only `found: agent, web`, which tells neither the reviewer nor the author that the author confused container_name with the service key.
  - Proposed check (mechanical): extract_evidence.py, `check_compose_main_deep(R)`: give each fail path its own problem string — `f"{CANON} does not exist, so it defines no service named `main`"`, `f"{rel} is unparsable YAML ({err}); no `main` service can be read from it"`, and for the ordinary miss `f"no service named exactly `main` in {rel}; services found: {names}"` p

- **Clause** — environment/docker-compose.yaml
  - Gap: The path in the rubric is part of the clause, and the pass option is a sentence that names it. extract_evidence.py:211-215 silently accepts `environment/docker-compose.yml`, and D2 then prints `option = "A `main` service exists in environment/docker-compose.yaml"` while `evidence.compose = environment/docker-compose.yml` — I reproduced th
  - Mis-scored shape: A bundle whose only compose file is environment/docker-compose.yml with a valid `main`. Today = 5/5 with a false answer sentence. Required = the score stays 5 (auto-failing would risk a false fail, since the harness may accept `.yml` and D1 already grades location), but the divergence must be stated
  - Proposed check (mechanical): extract_evidence.py, `check_compose_main_deep(R)`: resolve the canonical path itself rather than inheriting D1's aliased one; if only the `.yml` spelling exists, keep the pass but emit `file_at_canonical_path: WARN (environment/docker-compose.yml, not environment/docker-compose.yaml)` into `evidence["checks"]` and set `_why_judgment` so r

### Metadata Accuracy - CWE / Vulnerability Kind Accuracy

- **Clause** — See the "Example & Notes" tab in the spec sheet for a list of the possible assigned vulnerabilities.
  - Gap: Nothing asserts the declared cwe/kind maps to one of the five assignable classes (references/vulnerability_taxonomy.md). An off-list CWE resolves to families()==set() (verified for CWE-611 XXE, CWE-352 CSRF) and is silently ignored, so a task shipping a class outside the assignable set produces no signal and looks like a pass.
  - Mis-scored shape: task.toml cwe='CWE-611', vulnerability_kind='XML External Entity'; solve.py does XXE. Every families() call returns set(), conflict=='', and no field notes the class is off-list. Whether this is a hard D8 fail is arguable under the option wording, but it must at least be surfaced for judgment, which
  - Proposed check (mechanical): In identity_evidence, after resolving the declared CWE number, set v4_identity.assignable_class = (num in {'89','22','918','915','639','284'}) and, when False, emit off_list_class='declared CWE <num>/<kind> is not one of the five assignable classes (idor/sqli/ssrf/traversal/mass-assignment) - confirm against references/vulnerability_taxon

- **Clause** — For all options except the last, apply an error category.
  - Gap: report.py:377-379 prints the full rubric['error_categories'] string, which for D8 concatenates all three categories ('[Fail - Inconsistent Vulnerability in Oracle]; [Non-Fail - Inconsistent Vulnerability in Oracle]; [Fail - Name / CWE Identity]'). It does not select the one category that matches the chosen non-5 option, leaving the review
  - Mis-scored shape: Any D8 non-5 verdict: e.g. the skill scores 3 [Non-Fail - Inconsistent Vulnerability in Oracle], but the report prints all three error categories, so the form could be filled with the wrong '[Fail - ...]' tag.
  - Proposed check (mechanical): In report.py where error_categories is printed (report.py:377-379), parse the chosen v['option'] leading bracket label (e.g. '[Non-Fail - Inconsistent Vulnerability in Oracle]') and print only the matching semicolon-separated segment of error_categories; fall back to the full string when no label matches. Mechanical and cannot affect scor

### Noop / Free-Pass Resistance - Noop Reward = 0

- **Clause** — On a fresh No-Op run, does `test.sh` score `reward = 0`?
  - Gap: 'Fresh' is asserted by the option text and tested by nothing. If the author edits tests/test.sh or environment/ after capturing the noop evidence, the shipped reward.txt describes a task that no longer exists, and check_reward cannot tell.
  - Mis-scored shape: Any bundle where trajectories/noop/reward.txt predates tests/test.sh or environment/ -- e.g. an author who captures /noop, then adds the 'hardening' that accidentally pre-seeds the submission, then ships without re-running. Today: score 5, silently. mut/m7_vacuous is this shape in extreme form (test
  - Proposed check (mechanical): Add `noop_evidence_provenance` to the D15 evidence in extract_evidence.check_reward (guarded by `if dim_id == 15`). Compute the set of distinct rounded mtimes over every file in the bundle. If that set has size <= 1, emit {'mtime_provenance': 'UNAVAILABLE', 'why': 'every file in the bundle shares one mtime (<ts>); the archive did not pres

- **Clause** — ...the `reward.txt` + `test.log` evidence from that run.
  - Gap: The attribution check in gap 1 depends on tests/test.sh being shell and parseable. A verifier written in Python, or one whose messages are all built from variables, yields zero parseable branches and degrades to REVIEW -- which is correct but leaves the cheapest tell unchecked.
  - Mis-scored shape: A bundle whose author copies oracle/test.log to noop/test.log AND whose verifier emits no parseable literal messages (e.g. tests/test.sh is a two-line wrapper around `python3 /tests/verify.py`). Attribution returns nothing, so the contradiction is invisible.
  - Proposed check (mechanical): Add an unconditional, parser-independent assertion to check_noop_log_attribution: `if os.path.exists(oracle_log) and open(noop_log,'rb').read() == open(oracle_log,'rb').read(): problems.append('trajectories/noop/test.log is byte-identical to trajectories/oracle/test.log; one run cannot be evidence for both')`. Verified safe: `cmp -s` repo

### Verifier - Anti-Cheat Order

- **Clause** — For all options except the last, apply the error category.
  - Gap: extract_evidence.py:1187-1190 calls verdict() with five positional arguments and no `note` (helper signature at extract_evidence.py:195-197), so report.py:103-111 falls through to the literal string "All mechanical checks passed." for a passing D17. I confirmed both packs carry "note": "" for dimension 17. The line numbers the check compu
  - Mis-scored shape: Any passing bundle: the relay row reads "All mechanical checks passed." with no file, no line, and no statement of what was compared against what — indistinguishable from a check that found nothing to look at.
  - Proposed check (mechanical): In /Users/kunwar.singh/.claude/skills/qc-audit/extract_evidence.py:1187, pass the clause-by-clause string as the `note=` argument, e.g. `note=_ac["detail"]` (and on FAIL keep the `[Fail - Vacuous Anti-Cheat]` option text, which is already correct). Combined with the per-clause detail proposed above, the PASS row becomes "C1 tests/test.sh:

### Vulnerability Type - Correctness

- **Clause** — "the radio selection ... aligned with the task" (canonicalizer must recognise every one of the five exact radio labels)
  - Gap: The families() canonicalizer that any mechanical dim-22 check must reuse does NOT recognise the exact taxonomy label "Server-side request forgery": its ssrf key is only ('ssrf','cwe-918','cwe 918') (v4_checks.py:35). So a valid SSRF radio spelled as the taxonomy's own class name maps to [] and would be wrongly flagged AMBIGUOUS. This must
  - Mis-scored shape: An SSRF bundle (cwe=CWE-918, solve.py forges a server-side request) with radio="Server-side request forgery" — the exact taxonomy label. families('Server-side request forgery')=[] (verified) → AMBIGUOUS_RADIO instead of ALIGNED, a false non-pass.
  - Proposed check (mechanical): Before the mechanical audit lands, build a dim-22 canonical map keyed on the five VERBATIM taxonomy class labels from references/vulnerability_taxonomy.md and match the radio against those first (normalized), falling back to families(); and extend SKILL_FAMILIES['ssrf'] (v4_checks.py:35) with 'server-side request forgery','request forgery

### Explanations - Spam Check

- **Clause** — Any of the explanation fields
  - Gap: report.py:339 `_ff_err = _ff.get("_parse_error")` assumes form_fields is a dict. A fields file containing a JSON array survives extract_evidence.py:1350 unvalidated and crashes the report. I ran it: `AttributeError: 'list' object has no attribute 'get'` at report.py:339, after the extractor had exited 0. make_args.py:44-46 does not crash 
  - Mis-scored shape: An operator exports the platform form as `[{"vulnerability_explanation": "..."}]` (a one-row array). The extractor succeeds, make_args quietly omits D23, and report.py dies mid-render with a traceback.
  - Proposed check (mechanical): extract_evidence.py `main()` after line 1350: `if not isinstance(fields, dict): fields = {"_parse_error": f"expected a JSON object with the four form keys, got {type(fields).__name__}"}`. This reuses the existing `_parse_error` path that report.py:353 already renders. Neither reference bundle is affected (B1's fields file is a JSON object

