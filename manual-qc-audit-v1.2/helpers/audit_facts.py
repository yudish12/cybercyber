#!/usr/bin/env python3
"""audit_facts.py <task_root> — deterministic facts for a manual V11 QC audit.

FACTS ONLY. This scores NOTHING. It gathers the few things that are tedious to do by eye across many
files — per-trial behavior values, the recorded tier, mtime freshness, and a danger-sweep index — so the
auditor can then OPEN every flagged file and the decision-relevant files and score each dimension by hand.

Usage:  python3 audit_facts.py /path/to/task        (the dir containing task.toml)
Run with -I on untrusted bundles:  python3 -I audit_facts.py /path/to/task
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: audit_facts.py <task_root>")
    root = Path(sys.argv[1]).resolve()
    if not (root / "task.toml").exists():
        sys.exit(f"ERROR: {root}/task.toml not found — pass the inner task/ dir")

    print(f"# audit_facts for {root}\n")

    # ---- identity (facts; still read task.toml yourself) ----
    toml = (root / "task.toml").read_text(errors="replace")
    def grab(k):
        m = re.search(rf'^{k}\s*=\s*"([^"]*)"', toml, re.M)
        return m.group(1) if m else "(not found)"
    print("## identity")
    for k in ("name", "cwe", "vulnerability_kind", "version"):
        print(f"  {k}: {grab(k)}")

    # ---- PACKAGING HYGIENE (F5) — agent identity in task.toml, digest pins, fresh_state ----
    # F5 is a DECLARATIVE check: the rubric requires a non-root agent identity DECLARED IN task.toml
    # (an agent running non-root only via the Dockerfile USER does NOT satisfy it). These facts are
    # mechanically checkable, so surface them here — do not rely on the eye.
    print("\n## PACKAGING HYGIENE (F5) — task.toml agent identity / digest pins / fresh_state")
    # [agent] table user= (scope to the [agent] section so [verifier] user='root' does not match)
    am = re.search(r"^\[agent\]\s*$(.*?)(^\[|\Z)", toml, re.M | re.S)
    agent_block = am.group(1) if am else ""
    um = re.search(r'^\s*user\s*=\s*"([^"]*)"', agent_block, re.M)
    if not am:
        print("  task.toml [agent] user: !! NO [agent] TABLE -> F5 [Fail - Packaging Hygiene] candidate (task.toml omits a non-root agent identity)")
    elif not um:
        print("  task.toml [agent] user: !! MISSING -> F5 [Fail - Packaging Hygiene] candidate (task.toml [agent] declares no `user`; a Dockerfile USER does NOT satisfy the rubric's task.toml requirement)")
    elif um.group(1) in ("root", "0"):
        print(f"  task.toml [agent] user: !! '{um.group(1)}' is ROOT -> F5 [Fail - Packaging Hygiene] candidate")
    else:
        print(f"  task.toml [agent] user: '{um.group(1)}' (non-root, declared in task.toml) -> ok")
    # agent Dockerfile USER (corroborating runtime identity; required too, but does not substitute for task.toml)
    adf = next(iter(sorted(root.glob("environment/**/agent/Dockerfile*"))), None) \
        or next(iter(sorted(root.glob("environment/agent/Dockerfile*"))), None)
    if adf:
        udm = re.findall(r"^\s*USER\s+(\S+)", adf.read_text(errors="replace"), re.M)
        last = udm[-1] if udm else None
        if not last:
            print(f"  agent Dockerfile USER: !! none ({adf.relative_to(root)}) -> container may run as root")
        elif last in ("root", "0"):
            print(f"  agent Dockerfile USER: !! '{last}' (root) -> {adf.relative_to(root)}")
        else:
            print(f"  agent Dockerfile USER: '{last}' (non-root) -> {adf.relative_to(root)}")
    else:
        print("  agent Dockerfile: (not found under environment/**/agent/)")
    # digest pins: every FROM + compose image: must carry @sha256 (F5 mutable-tag / EN4 unpinned)
    comp_f5 = next(iter(sorted(root.glob("environment/docker-compose.y*ml"))), None)
    pin_targets = []  # (where, image-ref)
    for df in root.glob("environment/**/Dockerfile*"):
        if "node_modules" in str(df):
            continue
        for ln in df.read_text(errors="replace").splitlines():
            m = re.match(r"\s*FROM\s+(\S+)", ln, re.I)
            if m:
                pin_targets.append((str(df.relative_to(root)), m.group(1)))
    if comp_f5:
        for ln in comp_f5.read_text(errors="replace").splitlines():
            m = re.search(r"image:\s*(\S+)", ln)
            if m:
                pin_targets.append(("docker-compose", m.group(1)))
    unpinned = [(w, r) for (w, r) in pin_targets if "@sha256:" not in r]
    if not pin_targets:
        print("  digest pins: (no FROM/image: lines found)")
    elif unpinned:
        print(f"  digest pins: !! {len(unpinned)} MUTABLE tag(s) -> F5/EN4 [Unpinned] candidate:")
        for w, r in unpinned:
            print(f"      {w}: {r}")
    else:
        print(f"  digest pins: all {len(pin_targets)} base images @sha256-pinned -> ok")
    # fresh_state.json present + parses (F5 + F1 + EN4)
    fs = root / "fresh_state.json"
    if not fs.exists():
        print("  fresh_state.json: !! MISSING -> F5 + F1 + EN4 candidate")
    else:
        try:
            json.loads(fs.read_text())
            print("  fresh_state.json: present + valid JSON -> ok")
        except Exception as e:
            print(f"  fresh_state.json: !! present but INVALID JSON ({e}) -> F5 + F1 candidate")
    print("  NOTE (F5): the rubric fail is a 4-way OR — a mutable base-image tag, exploit narration in the")
    print("  agent-readable tree, task.toml omitting a non-root agent identity, OR a missing/invalid")
    print("  fresh_state.json. The task.toml [agent] user is REQUIRED there even when the Dockerfile USER is")
    print("  non-root; cross-check against a known-good sibling task.toml if the schema convention is unclear.")

    # ---- F1 STRUCTURE & PARSE — required files present, parse clean, scripts runnable ----
    # enumerate.sh lists only files that EXIST (a MISSING required file simply doesn't appear); this block
    # flags MISSING explicitly, parses the JSON (and TOML/YAML when libs are available), and checks shebangs.
    print("\n## F1 STRUCTURE & PARSE (required files present / parseable / executable)")
    required = ["task.toml", "instruction.md", "instruction_L0.md", "instruction_L1.md", "instruction_L2.md",
                "fresh_state.json", "environment/NOTICE.md", "solution/solve.sh",
                "tests/test.sh", "tests/isolation_test.sh"]
    comp_ok = comp_f5 is not None
    miss = [r for r in required if not (root / r).exists()]
    if not comp_ok:
        miss.append("environment/docker-compose.y*ml")
    for d in ("trajectories/oracle", "trajectories/noop", "trajectories/pass@k"):
        if not (root / d).exists():
            miss.append(d)
    if miss:
        print(f"  !! MISSING required path(s) -> F1 [Fail - Required Structure]: {miss}")
    else:
        print("  required files: all present")
    # empty-file check
    empties = [r for r in required if (root / r).exists() and (root / r).stat().st_size == 0]
    if empties:
        print(f"  !! EMPTY required file(s) -> F1 candidate: {empties}")
    # JSON parse
    for jp in ["fresh_state.json", "delivery.json"] + [str(p.relative_to(root)) for p in root.glob("operator/*.json")]:
        fp = root / jp
        if fp.exists():
            try:
                json.loads(fp.read_text()); verdict = "parse ok"
            except Exception as e:
                verdict = f"!! INVALID JSON -> F1 candidate ({e})"
            print(f"  JSON {jp}: {verdict}")
    # TOML/YAML parse when libs available (else note)
    try:
        import tomllib
        for tp in ["task.toml", "tests/reward.toml", "tests/stages/rubric.toml", "tests/report/rubric.toml"]:
            fp = root / tp
            if fp.exists():
                try:
                    tomllib.loads(fp.read_text()); v = "parse ok"
                except Exception as e:
                    v = f"!! INVALID TOML -> F1 candidate ({e})"
                print(f"  TOML {tp}: {v}")
    except Exception:
        print("  TOML parse: tomllib unavailable in this python -> parse task.toml/reward.toml/stages+report rubric.toml BY EYE")
    try:
        import yaml  # noqa
        if comp_f5:
            try:
                yaml.safe_load(comp_f5.read_text()); print(f"  YAML {comp_f5.relative_to(root)}: parse ok")
            except Exception as e:
                print(f"  YAML {comp_f5.relative_to(root)}: !! INVALID YAML -> F1/F2 candidate ({e})")
    except Exception:
        print("  YAML parse: pyyaml unavailable -> parse docker-compose BY EYE (or trust the boot: oracle=1 proves it parsed)")
    # scripts: executable bit OR shebang
    for s in ["solution/solve.sh", "tests/test.sh", "tests/isolation_test.sh", "tests/behavior/behavior.sh"]:
        fp = root / s
        if fp.exists():
            execbit = bool(fp.stat().st_mode & 0o111)
            first = fp.read_text(errors="replace").splitlines()[:1]
            sheb = bool(first and first[0].startswith("#!"))
            ok = execbit or sheb
            print(f"  script {s}: {'ok' if ok else '!! NO exec bit AND NO shebang -> F1 candidate'} "
                  f"(exec={'+x' if execbit else '-'}, shebang={'yes' if sheb else 'no'})")
    # pass@k: >=3 trials with trajectory.json + test-stdout.txt
    pk = root / "trajectories" / "pass@k"
    jobdirs = sorted([p for p in pk.glob("task-*") if p.is_dir()]) if pk.exists() else []
    good = 0
    for job in jobdirs:
        for tr in job.glob("*deepseek*"):
            if (tr / "agent" / "trajectory.json").exists() and (tr / "verifier" / "test-stdout.txt").exists():
                good += 1
    print(f"  pass@k trials with trajectory.json + test-stdout.txt: {good} "
          f"({'ok (>=3)' if good >= 3 else '!! <3 -> F1 [Fail - Required Structure] candidate'})")

    # ---- FORM FIELDS (delivery.json) — grounds F4 Vulnerability Type + dim-21 Spam ----
    # The skill used to treat Spam + F4's radio as "not assessable without form fields." Bundles routinely
    # ship delivery.json with exactly those fields, so surface them — do not default the two dims to unscored.
    print("\n## FORM FIELDS (delivery.json) — F4 Vulnerability Type selection + dim-21 Spam explanations")
    form = None
    for cand in ["delivery.json"] + [p.name for p in root.glob("*submission*.json")] + [p.name for p in root.glob("*form*.json")]:
        fp = root / cand
        if fp.exists():
            try:
                form = json.loads(fp.read_text()); form_file = cand; break
            except Exception as e:
                print(f"  {cand}: present but INVALID JSON ({e})")
    if not form:
        print("  (no delivery.json / *submission*.json / *form*.json at task root -> F4 radio + dim-21 may be genuinely unscored; SAY SO, don't leave blank)")
    else:
        print(f"  {form_file}:")
        vt = form.get("vulnerability_type") or form.get("vulnerability_type_selection") or "(not present)"
        print(f"    vulnerability_type (F4 selection, compare to task.toml cwe/vulnerability_kind + the solve): {vt}")
        for fld in ("vulnerability_explanation", "complexity_increase", "model_failure_reason"):
            v = form.get(fld)
            if v is None:
                print(f"    {fld}: !! MISSING (dim-21 candidate if the field is required)")
            else:
                s = str(v).strip()
                flag = " !! very short -> possible spam" if len(s) < 40 else ""
                print(f"    {fld}: {len(s)} chars{flag}  — read it; dim-21 fails only if spam/irrelevant")

    # ---- COMPOSE / ISOLATION / CREDENTIAL HYGIENE (F2 / EN2 / EN3) ----
    print("\n## COMPOSE & CREDENTIAL HYGIENE (F2 static ports/IPs, EN2 escape-privilege + topology, EN3 creds)")
    comp_txt = comp_f5.read_text(errors="replace") if comp_f5 else ""
    if not comp_f5:
        print("  (no docker-compose found)")
    else:
        # F2: static host port mappings + fixed subnet literals
        port_hits = re.findall(r'^\s*(?:-\s*)?"?(\d{2,5}):\d{2,5}"?\s*$', comp_txt, re.M)
        subnet_hits = re.findall(r'^\s*subnet:\s*(\S+)', comp_txt, re.M)
        if port_hits:
            print(f"  F2 !! static host-port mapping(s) -> candidate [Fail - Static Ports/IPs]: {sorted(set(port_hits))}")
        else:
            print("  F2 host ports: none pinned -> ok")
        if subnet_hits:
            print(f"  F2 !! fixed subnet literal(s) -> verify per-boot-unique/harness-isolated, else [Fail - Static Ports/IPs]: {subnet_hits}")
        else:
            print("  F2 subnet literals: none -> ok")
        # EN2: escape-grade privilege on any service (main especially)
        esc_pat = r"privileged:\s*true|cap_add|/var/run/docker\.sock|pid:\s*[\"']?host|network_mode:\s*[\"']?host|ipc:\s*[\"']?host|devices:|security_opt"
        esc = [ln.strip() for ln in comp_txt.splitlines() if re.search(esc_pat, ln)]
        if esc:
            print("  EN2 !! escape-grade-privilege candidate line(s) -> confirm NOT on main:")
            for ln in esc[:12]:
                print(f"      {ln}")
        else:
            print("  EN2 escape-grade privilege (privileged/cap_add/docker.sock/host-ns/devices): none -> ok")
        # EN2 topology: per-service network membership + which top-level networks are internal:true,
        # so you can confirm main shares NO network with an internal-only app/DB/registry.
        print("  EN2 topology (confirm main shares NO network with an internal-only app/DB/registry):")
        svc_nets = {}            # service -> [networks]
        internal_nets = set()    # networks declared internal: true
        cur_svc = None
        in_services = False
        in_net_list = False
        for ln in comp_txt.splitlines():
            if re.match(r'^services:\s*$', ln):
                in_services = True; continue
            if re.match(r'^\S', ln):          # a top-level key ends the services block
                in_services = False
            sm = re.match(r'^\s{2}([\w-]+):\s*$', ln)
            if in_services and sm:
                cur_svc = sm.group(1); svc_nets.setdefault(cur_svc, []); in_net_list = False
            if cur_svc and re.match(r'^\s{4}networks:\s*$', ln):
                in_net_list = True; continue
            if in_net_list:
                nm = re.match(r'^\s{4,}-\s*([\w-]+)\s*$', ln)      # list item (same-indent or deeper)
                if nm:
                    svc_nets[cur_svc].append(nm.group(1))
                elif re.match(r'^\s{2,4}[\w-]+:', ln) or re.match(r'^\S', ln):
                    in_net_list = False
        # top-level networks: <name>:\n ... internal: true
        for m in re.finditer(r'^\s{2}([\w-]+):\s*$(.*?)(?=^\s{2}\S|\Z)', comp_txt.split('networks:')[-1], re.M | re.S):
            if re.search(r'internal:\s*true', m.group(2)):
                internal_nets.add(m.group(1))
        for svc, ns in svc_nets.items():
            tag = ""
            if ns:
                pub = [n for n in ns if n not in internal_nets]
                tag = f" [on: {','.join(ns)}]" + (f" PUBLIC-side: {','.join(pub)}" if pub else " (all internal)")
            print(f"      {svc}{tag}")
        if internal_nets:
            print(f"      internal:true networks: {sorted(internal_nets)}")
        print("      -> main should sit ONLY on a public/bridge net; internal app/DB/registry ONLY on internal:true nets")
    # EN3: credential literals in compose / .env / Dockerfile ENV + per-boot freshness
    cred_pat = r"(PASSWORD|PASSWD|_PASS|SECRET|API_KEY|APIKEY|TOKEN|PRIVATE_KEY)\s*[:=]\s*[\"']?[^\s\"'$#{]{3,}"
    cred_files = [comp_f5] if comp_f5 else []
    cred_files += list(root.glob("environment/**/*.env")) + list(root.glob("environment/**/.env"))
    cred_files += [p for p in root.glob("environment/**/Dockerfile*") if "node_modules" not in str(p)]
    print("  EN3 hardcoded-credential-literal candidates (a value that is NOT ${VAR}/_FILE/urandom/secrets):")
    en3_hits = 0
    for p in cred_files:
        if not p or not p.exists():
            continue
        for i, ln in enumerate(p.read_text(errors="replace").splitlines(), 1):
            m = re.search(cred_pat, ln)
            if m and not re.search(r"\$\{|_FILE|urandom|token_hex|secrets\.|/dev/urandom|<|example|changeme-?placeholder", ln):
                en3_hits += 1
                if en3_hits <= 20:
                    print(f"      {p.relative_to(root)}:{i}: {ln.strip()[:100]}")
    if not en3_hits:
        print("      (none — credentials look ${VAR}/_FILE/per-boot-minted; still confirm freshness by eye)")
    print("  NOTE: EN3 fails on a REUSED/low-entropy/hardcoded non-scored credential; a per-boot urandom/secrets")
    print("  mint written to a _FILE or ${VAR} is fine. EN2 fails if main shares a net with an internal service or")
    print("  carries escape privilege. F2 fails on a pinned host port or a collidable fixed subnet literal.")

    # ---- EV5: per-trial behavior gate + panel + tier ----
    print("\n## EV5 — per-trial BEHAVIOR gate (verifier/reward.json; NOT reward.txt, NOT staged)")
    pk_root = root / "trajectories" / "pass@k"
    jobs = sorted([p for p in pk_root.glob("task-*") if p.is_dir()]) if pk_root.exists() else []
    if not jobs:
        print("  (no pass@k job dir found)")
    for job in jobs:
        print(f"  job: {job.name}")
        # tier from run.log (one level up, or in job)
        tier = "(not recorded)"
        for logp in (job.parent / "run.log", job / "run.log"):
            if logp.exists():
                m = re.search(r"Using tier (L\d+)", logp.read_text(errors="replace"))
                if m:
                    tier = m.group(1)
                break
        print(f"    recorded tier: {tier}")
        # result.json panel stats
        rj = job / "result.json"
        n_tri = n_err = None
        if rj.exists():
            try:
                st = json.loads(rj.read_text())["stats"]
                ev = list(st.get("evals", {}).values())
                if ev:
                    e = ev[0]
                    n_tri, n_err = e.get("n_trials"), e.get("n_errors")
                    print(f"    model: {list(st['evals'].keys())[0]}")
                    print(f"    n_trials: {n_tri}  n_errors: {n_err}  mean: {e['metrics'][0]['mean'] if e.get('metrics') else '?'}")
            except Exception as ex:
                print(f"    (result.json parse error: {ex})")
        # per-trial behavior
        solves = nonsolves = 0
        for trial in sorted(job.glob("*deepseek*")):
            if not trial.is_dir():
                continue
            rpath = trial / "verifier" / "reward.json"
            bv = "?"
            if rpath.exists():
                try:
                    bv = json.loads(rpath.read_text()).get("reward")
                except Exception:
                    bv = "(parse error)"
            if bv == 1.0:
                solves += 1
            elif bv == 0.0:
                nonsolves += 1
            # staged score + per-stage for context (diagnostic only)
            sd = trial / "verifier" / "stages" / "reward-details.json"
            stginfo = ""
            if sd.exists():
                try:
                    crit = json.loads(sd.read_text())["reward"]["criteria"]
                    fired = [c["name"].split("_")[0] for c in crit if c.get("value") == 1.0]
                    stginfo = f"  staged[{','.join(fired)}]"
                except Exception:
                    pass
            print(f"    {trial.name}: behavior={bv}{stginfo}")
        total = solves + nonsolves
        # non-errored count: prefer n_trials - n_errors from result.json; fall back to parsed reward.json files
        non_errored = (n_tri - n_err) if (isinstance(n_tri, int) and isinstance(n_err, int)) else total
        if total or non_errored:
            flags = []
            if isinstance(non_errored, int) and non_errored < 3:
                flags.append(f"!! FAIL [Difficulty Too Low] candidate: only {non_errored} non-errored trajectories (<3 required)")
            if total and solves == total and (n_tri is None or solves == n_tri):
                flags.append("!! FAIL [Difficulty Too Low]: model solved EVERY trial (too easy)")
            verdict = "; ".join(flags) if flags else "PASS on the count (solve rate <100% and >=3 non-errored)"
            print(f"    -> behavior solve rate: {solves}/{total}  (non-errored: {non_errored})  {verdict}")
            print(f"       genuine-non-solve candidates to VERIFY by reading the trajectory: {nonsolves}")
        print("    NOTE: EV5 also FAILS [Difficulty Too Low] if NO apparent non-solve is GENUINE — i.e. every")
        print("    non-solve is a refusal, an infra/timeout abort, a mis-grade, or a broken env. 'solve rate <100%'")
        print("    is necessary but NOT sufficient. Open each non-solve's agent/terminus_2.pane + result.json and")
        print("    prove it is genuine (0 refusals, exception_info=null, real HTTP responses, >=1 real non-solve);")
        print("    de-wrap ANSI/CR+wrapped pane lines before concluding a value was never observed.")

    # ---- EN4 service-discovery retry budgets (verifier/solver must be >= agent) ----
    print("\n## EN4 SERVICE-DISCOVERY RETRY BUDGETS (rubric: verifier/solver retry budget >= agent)")
    def _budget(relpath, label):
        fp = root / relpath
        if not fp.exists():
            return
        t = fp.read_text(errors="replace")
        seqs = re.findall(r"seq 1 (\d+)", t)
        lts = re.findall(r"-lt (\d+)|lt (\d+)", t)
        tos = re.findall(r"timeout=(\d+)", t)
        bits = []
        if seqs:
            bits.append(f"resolve/retry seq≈{max(int(s) for s in seqs)}s")
        if lts:
            flat = [int(a or b) for a, b in lts]
            if flat:
                bits.append(f"readiness-loop≈{max(flat)} iters")
        if tos:
            bits.append(f"rk timeout={','.join(tos)}s")
        if bits:
            print(f"  {label} ({relpath}): {'; '.join(bits)}")
    _budget("tests/behavior/behavior.sh", "VERIFIER resolve loop")
    _budget("tests/behavior/check.py", "VERIFIER rk wrapper")
    _budget("solution/solve.sh", "SOLVER")
    # agent (main) command budget + healthcheck retries live in compose
    if comp_f5:
        ct = comp_f5.read_text(errors="replace")
        aseq = re.findall(r"seq 1 (\d+)", ct)
        alt = re.findall(r"-lt (\d+)", ct)
        if aseq or alt:
            print(f"  AGENT (main, compose command): resolve seq≈{max(int(s) for s in aseq) if aseq else '?'}s; "
                  f"readiness-loop≈{max(int(s) for s in alt) if alt else '?'} iters")
        hcs = re.findall(r"retries:\s*(\d+)", ct)
        if hcs:
            print(f"  compose healthcheck retries: {hcs}")
    hc = re.search(r"\[environment\.healthcheck\][^\[]*", toml, re.S)
    if hc:
        r_ = re.search(r"retries\s*=\s*(\d+)", hc.group(0))
        iv = re.search(r"interval_sec\s*=\s*([\d.]+)", hc.group(0))
        print(f"  task.toml [environment.healthcheck]: retries={r_.group(1) if r_ else '?'} interval={iv.group(1) if iv else '?'}s")
    print("  NOTE: compare the VERIFIER/SOLVER budget to the AGENT budget. If the verifier's rk `timeout=` is")
    print("  SMALLER than the agent's resolve/readiness budget, confirm whether a slow boot can make the verifier")
    print("  give up first (false infra_error). It is NOT a fail if boot ordering (main depends_on web:healthy +")
    print("  a pre-written web_ip the resolver finds in <1s) means the cap is never the binding constraint and 0")
    print("  trials errored — but SAY which it is; don't leave 'verifier<agent' unexamined. (EN4 [Reproducibility].)")

    # ---- freshness: graded source vs pass@k artifacts (mtime) ----
    print("\n## EVIDENCE FRESHNESS — graded source vs pass@k artifacts (mtime)")
    graded = []
    for pat in ("environment/**/app.py", "environment/**/setup.py", "tests/**/*.sh", "tests/**/*.py",
                "tests/**/*.toml", "task.toml", "instruction*.md"):
        graded += list(root.glob(pat))
    art = []
    for job in jobs:
        art += list(job.glob("**/trajectory.json")) + list(job.glob("**/verifier/reward.json"))
        if (job / "run.log").exists():
            art.append(job / "run.log")
        elif (job.parent / "run.log").exists():
            art.append(job.parent / "run.log")
    art_mtime = max((p.stat().st_mtime for p in art), default=0)
    if art_mtime:
        import datetime
        def ts(t): return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  newest pass@k artifact mtime: {ts(art_mtime)}")
        newer = [(p, p.stat().st_mtime) for p in graded if p.stat().st_mtime > art_mtime]
        if newer:
            print("  !! GRADED SOURCE NEWER THAN THE PASS@K EVIDENCE (stale → recommend a re-run):")
            for p, m in sorted(newer, key=lambda x: -x[1]):
                print(f"     {ts(m)}  {p.relative_to(root)}")
        else:
            print("  ok: no graded-source file is newer than the pass@k artifacts")
    else:
        print("  (no pass@k artifacts to compare)")

    # ---- danger-sweep index: OPEN every file that hits (STACK-AWARE) ----
    print("\n## DANGER SWEEP — open every file that hits (grounds VU2 / VU5 / EV2 / F5 / VU1)")
    # The sweep must cover the task's ACTUAL stack, not just Next.js. The old version globbed only
    # app/api + lib and grepped *.ts/*.js, so on a PHP/Flask/Python/Go task it swept NOTHING and printed
    # "(none)" — a false clean. Now: sweep the whole environment/ tree across stacks (vendored dirs
    # excluded), run JS/TS + PHP + Python sink patterns, and REPORT what was scanned so "(none)" means
    # "looked and found nothing," not "did not look."
    INCLUDES = ["--include=*.ts", "--include=*.js", "--include=*.php", "--include=*.py",
                "--include=*.rb", "--include=*.go", "--include=*.inc"]
    EXCLUDE_DIRS = ["node_modules", "vendor-wheels", "vendor", ".venv", "site-packages",
                    ".next", "dist", "build", "__pycache__"]
    excl = [f"--exclude-dir={d}" for d in EXCLUDE_DIRS]
    env_dir = root / "environment"
    # count in-scope first-party source files per extension (so a "(none)" is trustworthy)
    import collections
    scope_counts = collections.Counter()
    if env_dir.exists():
        for p in env_dir.rglob("*"):
            if p.is_file() and p.suffix in (".ts", ".js", ".php", ".py", ".rb", ".go", ".inc") \
               and not any(part in EXCLUDE_DIRS for part in p.parts):
                scope_counts[p.suffix] += 1
    scope_str = ", ".join(f"{ext}:{n}" for ext, n in sorted(scope_counts.items())) or "no source files found"
    print(f"  (scanned under environment/ excluding vendored dirs — {scope_str})")
    if not scope_counts:
        print("  !! NO first-party source files found under environment/ — the app ships only as a prebuilt")
        print("     image; the sweep cannot see its code. Hand-read any shipped wrapper (document.php, app.py,")
        print("     entrypoint*) and treat the app's own routes as un-swept (confirm sinks from the image/CVE).")
    patterns = {
        # --- JS / TS (Next.js) ---
        "[ts] body-spread (2nd mass-assignment?)": r"\.\.\.\(?(body|req|await|result)",
        "[ts] file read w/ user path": r"readFile|readFileSync|createReadStream|sendFile",
        "[ts] code exec / raw sql": r"eval\(|child_process|[^a-z]exec\(|sql\.raw|\.raw\(",
        "[ts] sql via string interpolation": r"(SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|LIKE|VALUES)\b[^;]*\$\{|\$\{[^}]*\}[^;]*\b(FROM|WHERE|LIKE|INTO|SET)\b",
        # --- PHP (LFI/traversal, SQLi, code exec) ---
        "[php] file read / LFI w/ variable": r"(include|include_once|require|require_once|readfile|fopen|file_get_contents|fpassthru|readgzfile|highlight_file|show_source)\s*\(\s*[^)]*\$",
        "[php] raw/interpolated sql": r"(->query|->exec|->multi_query|mysqli_query|mysql_query|pg_query|->prepare)\s*\(\s*[^)]*\$|\"[^\"]*(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\"]*\$",
        "[php] code exec / dynamic": r"\b(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|create_function)\s*\(|preg_replace\s*\(\s*['\"][^'\"]*/[a-z]*e",
        "[php] request superglobal near sink": r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b",
        # --- Python (traversal, SQLi, code exec) ---
        "[py] file read w/ request input": r"(open|send_file|send_from_directory|FileResponse|StreamingResponse)\s*\([^)]*(request\.|params|args|form|query|filename|path)",
        "[py] raw/interpolated sql": r"(execute|executemany|executescript|cursor\.execute|\.raw)\s*\(\s*(f[\"']|[\"'][^\"']*(%|\+)|[^)]*\.format\()",
        "[py] code exec / dynamic": r"\b(eval|exec|os\.system|subprocess\.|__import__|pickle\.loads|yaml\.load)\s*\(",
        # --- stack-agnostic secret disclosure ---
        "[*] secret/seed/token disclosure": r"/seed/|/tokendrop/|/canary/|concierge|CONCIERGE|[^a-z]marker|MARKER|token_hex|REAL_TOKEN|SCORED",
    }
    CAP = 40
    for label, pat in patterns.items():
        print(f"  [{label}]")
        hits = 0
        try:
            out = subprocess.run(["grep", "-rnE", *INCLUDES, *excl, pat, str(env_dir)],
                                 capture_output=True, text=True, timeout=120).stdout
        except Exception:
            out = ""
        for line in out.splitlines():
            if ".test.ts:" in line:   # test fixtures are not served routes
                continue
            hits += 1
            if hits <= CAP:
                print("    " + line.replace(str(root) + "/", ""))
        if not hits:
            print("    (none)")
        elif hits > CAP:
            print(f"    ... (+{hits - CAP} more — many hits; narrow to first-party files, this app may ship full source)")
    # ---- gateway guard <-> forward path confusion (EN2/VU2/EV2/VU5) — calibration case 1 ----
    # ---- F5 narration-in-agent-tree + VU1 foreign/leftover-prefix secret (candidates) ----
    print("\n## F5 NARRATION IN AGENT TREE + VU1 FOREIGN-PREFIX SECRET (candidates — judgment)")
    # F5: exploit narration / hint comments must not live where the agent can read them. The agent-readable
    # tree = the agent build context (environment/agent/, minus vendored wheels) + files staged into
    # agent-mounted volumes. Grep for CWE/CVE ids, vuln-class names, and exploit words in comments/docs.
    cwe = grab("cwe")
    cve = grab("cve")
    class_re = re.compile(r"\bCWE-\d+\b|\bCVE-\d{4}-\d+\b|path.?traversal|SQL ?injection|SQLi|\bIDOR\b|\bBOLA\b|\bSSRF\b|mass.?assign|LFI|arbitrary file (read|write)|broken (access|function)|exploit|backdoor|vulnerab", re.I)
    agent_tree = [p for p in root.glob("environment/agent/**/*")
                  if p.is_file() and "vendor-wheels" not in str(p)]
    # staged-into-agent dirs are host dirs volume-mounted into main; their on-disk source is under environment/
    narr_hits = 0
    for p in agent_tree:
        if p.suffix in (".whl", ".so", ".pyc"):
            continue
        try:
            for i, ln in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if class_re.search(ln):
                    narr_hits += 1
                    if narr_hits <= 15:
                        print(f"  !! {p.relative_to(root)}:{i}: {ln.strip()[:100]}  -> F5 narration candidate (agent-readable)")
        except Exception:
            pass
    if not narr_hits:
        print(f"  F5 narration: no CWE/CVE/class/exploit tokens in the agent build tree (environment/agent/, {len(agent_tree)} files ex-wheels) -> ok")
    print("     (also confirm by eye that files mounted into main — compose volumes on the `main` service — carry no narration)")
    # VU1: a foreign/sibling PREFIXED secret reachable over HTTP. The taught success format here is:
    print(f"  VU1 taught marker: cwe={cwe}; confirm the submission format in instruction*.md (e.g. bare 48-hex vs a PREFIX).")
    # match prefixed-secret VALUES (flag braces, class-named flags, sibling-task prefix + hex suffix),
    # NOT code identifiers like REAL_TOKEN/VERIFIER_TOKEN.
    foreign_re = re.compile(r"FLAG\{|CTF\{|flag\{|\b(SQLI|IDOR|BOLA|SSRF|LFI|XXE|RCE|TRAV)_FLAG\b|\b(pandora|shopora|gitea|jiro|salsa|concierge|archive)[a-z0-9]*_[0-9a-f]{8,}", re.I)
    served = subprocess.run(["grep", "-rnE", *INCLUDES, *excl, foreign_re.pattern, str(env_dir)],
                            capture_output=True, text=True, timeout=120).stdout if env_dir.exists() else ""
    fp = served.splitlines()
    if fp:
        print(f"  !! foreign/prefixed-secret-shaped strings in served source ({len(fp)} hit(s)) -> VU1 [Leftover Prefix] candidates; confirm NONE is agent-reachable over HTTP with a prefix other than this task's:")
        for l in fp[:12]:
            print("      " + l.replace(str(root) + "/", ""))
    else:
        print("  VU1 foreign-prefix: no sibling/foreign prefixed-secret strings in served source -> ok (still confirm no leftover copy of THIS secret is HTTP-reachable off-path)")

    print("\n## GATEWAY GUARD <-> FORWARD — path-canonicalization bypass candidates (EN2/VU2/EV2/VU5)")
    gw = []
    for p in root.glob("environment/**/*.py"):
        if "node_modules" in str(p):
            continue
        try:
            t = p.read_text(errors="replace")
        except Exception:
            continue
        if p.name == "app.py" or "proxy" in p.name.lower() or ("request" in t and "path" in t):
            gw.append(p)
    guard_pat = r"is_blocked|BLOCKED_|_is_decoy|TECHNIQUE_EXCLUDED|\.startswith\(|== *[\"']api/|normpath|realpath|path-as-is"
    fwd_pat = r"f[\"']\{[A-Z_]+\}/\{path\}|\.(request|get|post|put|delete)\(|url *= *f?[\"']|urljoin\(|APPSERVER"
    found_gw = False
    for p in sorted(set(gw)):
        g = subprocess.run(["grep", "-nE", guard_pat, str(p)], capture_output=True, text=True).stdout
        fwd = subprocess.run(["grep", "-nE", fwd_pat, str(p)], capture_output=True, text=True).stdout
        if g.strip() and fwd.strip():
            found_gw = True
            print(f"  --- {p.relative_to(root)} (decides on a path AND forwards one) ---")
            print("    [guard / block / decoy decisions]")
            for ln in g.splitlines():
                print("      " + ln)
            print("    [forward construction]")
            for ln in fwd.splitlines():
                print("      " + ln)
    if not found_gw:
        print("  (no gateway file both decides on a path and forwards one — re-check by hand)")
    print("  NOTE: if a guard decides on the RAW request path but the forward concatenates that SAME raw path,")
    print("  a `..`/%2e%2e segment via raw socket / `curl --path-as-is` bypasses it and normalizes downstream.")
    print("  Manually reach EVERY blocked route + EVERY credit-excluded decoy that way; if any discloses the")
    print("  secret -> EN2 + VU2 + EV2 + VU5.")

    # ---- env-var VALUE leak (VU3) — calibration case 1 ----
    print("\n## ENV-VAR VALUE LEAK (VU3) — main/agent env values vs the foothold handoff")
    comp = next(iter(sorted(root.glob("environment/docker-compose.y*ml"))), None)
    if comp:
        env_hits = subprocess.run(
            ["grep", "-nE", r"NO_PROXY|no_proxy|_URL:|_HOST|APPSERVER|BACKEND|INTERNAL|_ENDPOINT", str(comp)],
            capture_output=True, text=True).stdout
        print(f"  compose: {comp.relative_to(root)}")
        for ln in env_hits.splitlines():
            print("    " + ln)
        if not env_hits.strip():
            print("    (no NO_PROXY/_URL/_HOST-style env lines)")
    else:
        print("  (no environment/docker-compose.y*ml found)")
    foot = ""
    for p in root.glob("environment/**/*.py"):
        if "node_modules" in str(p):
            continue
        try:
            t = p.read_text(errors="replace")
        except Exception:
            continue
        if "/api/credentials" in t or "base_url" in t:
            fh = subprocess.run(["grep", "-nE", r"base_url|/api/credentials|\"note\"", str(p)],
                                capture_output=True, text=True).stdout
            if fh.strip():
                foot += f"  {p.relative_to(root)}:\n" + "\n".join("    " + l for l in fh.splitlines()) + "\n"
    if foot:
        print("  foothold handoff discloses:")
        print(foot, end="")
    print("  NOTE: an internal host/target NAMED in main's env (e.g. NO_PROXY=appserver) but NOT in the foothold")
    print("  handoff is a bare-`printenv` leak -> VU3 [Fail - Env-Var Value Leak]. IP ranges + the disclosed")
    print("  foothold host (e.g. web:8080) are fine.")

    # ---- EN4 base-image LICENSE coverage in the TOP-LEVEL NOTICE (calibration case 2) ----
    print("\n## EN4 — base-image LICENSE coverage in environment/NOTICE.md (a nested app NOTICE does NOT count)")
    imgs = set()
    for df in root.glob("environment/**/Dockerfile*"):
        if "node_modules" in str(df):
            continue
        try:
            for ln in df.read_text(errors="replace").splitlines():
                m = re.match(r"\s*FROM\s+([^\s@]+)", ln, re.I)
                if m:
                    imgs.add(m.group(1))
        except Exception:
            pass
    if comp:
        for ln in comp.read_text(errors="replace").splitlines():
            m = re.search(r"image:\s*([^\s@]+)", ln)
            if m:
                imgs.add(m.group(1))
    lic_re = re.compile(r"\b(MIT|BSD|Apache|GPL|LGPL|AGPL|MPL|ISC|Zlib|Unlicense|CC0|musl|PSF|PSL|PostgreSQL|proprietary|license)\b", re.I)
    # known-correct base-image licenses (see references/base_image_licenses.md). A license PRESENT but
    # contradicting this counts as MISSING for EN4 (calibration case 3: busybox labeled BSD-3-Clause = wrong).
    KNOWN_LICENSES = {
        "busybox": ["GPL"],                      # GPL-2.0-only — NOT BSD
        "python": ["PSF", "PSL", "Python Software Foundation"],
        "node": ["MIT"], "nodejs": ["MIT"],
        "alpine": ["MIT"], "gitea": ["MIT"], "golang": ["BSD"], "go": ["BSD"],
        "nginx": ["BSD"], "postgres": ["PostgreSQL", "BSD"], "mariadb": ["GPL"], "mysql": ["GPL"],
    }
    top_notice = root / "environment" / "NOTICE.md"
    if top_notice.exists():
        nlines = top_notice.read_text(errors="replace").splitlines()
        print(f"  top-level environment/NOTICE.md ({len(nlines)} lines):")
        for img in sorted(imgs):
            base = img.split(":")[0].split("/")[-1]
            ctxs = []
            for i, ln in enumerate(nlines):
                if base in ln.lower() or img in ln.lower():   # same line or the next line only
                    ctxs.append("\n".join(nlines[i:i + 2]))
            blob = "\n".join(ctxs)
            mentioned = bool(ctxs)
            lic_m = lic_re.search(blob)
            known = KNOWN_LICENSES.get(base)
            correct = bool(known) and any(re.search(k, blob, re.I) for k in known)
            if not mentioned:
                tag = "NOT MENTIONED"
            elif not lic_m:
                tag = "MENTIONED but NO license"
            elif known and not correct:
                tag = f"license '{lic_m.group(0)}' may be WRONG for {base} (expected ~{known[0]}) -- VERIFY"
            else:
                tag = "LICENSE ok"
            print(f"    {img:<46s} -> {tag}")
    else:
        print("  !! environment/NOTICE.md MISSING (EN4 + F1 + F5 fail)")
    nested = [p for p in sorted(root.glob("environment/**/NOTICE*")) if p != top_notice]
    if nested:
        print("  nested NOTICE files present (do NOT satisfy EN4):")
        for p in nested:
            print(f"    {p.relative_to(root)}")
    print("  NOTE: every base image + the app need a stated, CORRECT LICENSE in environment/NOTICE.md; a digest")
    print("  pin is not a license, a WRONG license is factually wrong (e.g. busybox is GPL-2.0, not BSD -- see")
    print("  references/base_image_licenses.md), and a nested <app>/NOTICE.md does not rescue it.")
    print("  DIVERGENCE (calib7, a PASS bundle, labels busybox 'BSD-3-Clause' AND omits a license for python/app,")
    print("  yet PASSED EN4 — the same gaps that FAILED calib2/3). Base-image licensing is NOISY: surface a")
    print("  wrong/missing license as a CANDIDATE and flag the divergence; do NOT auto-fail. EN4 overall is the")
    print("  single noisiest dimension — every sub-pattern appears in both fail and pass bundles.")

    # ---- isolation-test coverage (EV4 removed in V11 -> advisory) (calibration case 2) ----
    print("\n## ISOLATION-TEST COVERAGE (advisory; EV4 removed in V11)")
    iso = root / "tests" / "isolation_test.sh"
    if iso.exists():
        it = iso.read_text(errors="replace")
        print(f"  tests/isolation_test.sh present ({len(it.splitlines())} lines). What it actually probes:")
        check_re = re.compile(
            r"curl|printenv|\benv\b|grep|\bls\b|\bcat\b|\[ -[rfde]|/tests|/solution|/operator|/vchan|/seed|/canary|/app|/src|http://",
            re.I)
        shown = False
        for i, ln in enumerate(it.splitlines(), 1):
            if check_re.search(ln):
                print(f"      {i}: {ln.strip()}")
                shown = True
        if not shown:
            print("      (no recognizable check lines — read it by hand)")
        print("  Confirm by eye it covers ALL of: task SOURCE, /tests, /solution, and credentials (incl. MOUNTED")
        print("  files like /vchan/verifier_token — NOT just env-var *names* like VERIFIER_TOKEN). Each uncovered")
        print("  item is an advisory gap.")
    else:
        print("  tests/isolation_test.sh MISSING (also F1 fail)")
    if comp:
        mnt = subprocess.run(["grep", "-nE", r":/vchan|:/seed|:/canary", str(comp)],
                             capture_output=True, text=True).stdout
        if mnt.strip():
            print("  secret/credential volume mounts in compose (each SHOULD be isolation-tested by file path):")
            for ln in mnt.splitlines():
                print("    " + ln)
    print("  NOTE: isolation-test coverage gaps are an ADVISORY in V11 (EV4 removed), not a scored dimension.")

    # ---- VU3 tier-contract completeness (calibration case 4) ----
    print("\n## VU3 TIER CONTRACT — L2 must ADD the CWE/class (not just endpoint+recipe); L0/L1 must not leak")
    cwe = grab("cwe")
    vkind = grab("vulnerability_kind")
    print(f"  task.toml: cwe={cwe!r}  vulnerability_kind={vkind!r}")
    class_pats = [r"CWE-\d+", r"CVE-\d{4}-\d+", r"\bBFLA\b", r"\bBOLA\b", r"\bIDOR\b", r"\bSSRF\b",
                  r"\bXXE\b", r"\bRCE\b", r"\bLFI\b", r"\bSSTI\b", r"\bSQLi\b", r"SQL injection",
                  r"broken function[- ]level authorization", r"broken object[- ]level authorization",
                  r"broken access control", r"missing authorization", r"mass assignment",
                  r"path traversal", r"insecure direct object", r"server-side request forgery",
                  r"value binding", r"arbitrary file (read|inclusion)"]
    if cwe and cwe != "(not found)":
        class_pats.append(re.escape(cwe))  # the task's own CWE id, e.g. CWE-862
    # NOTE: we deliberately do NOT derive patterns from vulnerability_kind words/acronyms — generic tokens
    # like "API"/"CSV"/"URL" in a kind string match foothold/recipe text and false-flag clean tiers.
    class_re = re.compile("|".join(class_pats), re.I)
    endpoint_re = re.compile(r"\?action=|\?format=|/admin/|\.php\b|\.aspx\b|\.jsp\b|/sync/|/registry/|/internal/", re.I)
    verdicts = {}
    for tier in ("instruction_L0.md", "instruction_L1.md", "instruction_L2.md"):
        f = root / tier
        if not f.exists():
            print(f"    {tier}: MISSING")
            continue
        txt = f.read_text(errors="replace")
        cls = bool(class_re.search(txt))
        ep = any(endpoint_re.search(ln) and "/api/credentials" not in ln for ln in txt.splitlines())
        verdicts[tier] = (cls, ep)
        print(f"    {tier:<18s} explicit_CWE/class={'YES' if cls else 'no '}   vuln_endpoint={'YES' if ep else 'no'}")
    l2 = verdicts.get("instruction_L2.md")
    if l2 and not l2[0]:
        print("  !! L2 names NO explicit CWE/class -> VU3 [Fail - Non-Monotonic Hint Progression] candidate")
        print("     (L2 must add BOTH the CWE/CVE AND the exact endpoint + recipe; a restated L1 mechanism is NOT the class.)")
    for t in ("instruction_L0.md", "instruction_L1.md"):
        v = verdicts.get(t)
        if v and (v[0] or v[1]):
            leaked = ", ".join(x for x, present in (("class/CWE", v[0]), ("exact endpoint", v[1])) if present)
            print(f"  !! {t} appears to leak {leaked} -> VU3 [Vulnerability Leakage / Non-Monotonic] candidate")
    print("  NOTE: heuristic — confirm by reading the tiers. A CASE NAME (e.g. 'privilege-escalation-probe') is")
    print("  data, not the vuln class; HTTP 'Authorization:' headers are recipe, not a class statement.")

    # VU3 app-source class leak: the SERVED app source (not just L0/L1) must not NAME the vuln class/CWE.
    # Scan served first-party source across stacks (exclude vendored + the instruction files, which may name
    # the class at L2). A class/CWE token in agent-reachable served source is VU3 [Fail - Vulnerability Leakage].
    print("  VU3 app-source class-leak scan (served source must not name the class/CWE below L2):")
    vclass_re = re.compile(r"\bCWE-\d+\b|\bCVE-\d{4}-\d+\b|path.?traversal|SQL.?injection|\bSQLi\b|\bIDOR\b|\bBOLA\b|\bSSRF\b|mass.?assign|\bLFI\b|broken (access|function).?level", re.I)
    leak_hits = 0
    if env_dir.exists():
        out = subprocess.run(["grep", "-rinE", *INCLUDES, *excl, vclass_re.pattern, str(env_dir)],
                             capture_output=True, text=True, timeout=120).stdout
        for line in out.splitlines():
            # exclude obvious non-leaks: license/provenance NOTICE text is EN4 not served-to-agent; comments
            # naming the CVE in operator/behavior files (not agent-reachable) are handled elsewhere.
            leak_hits += 1
            if leak_hits <= 12:
                print("    " + line.replace(str(root) + "/", ""))
    if not leak_hits:
        print("    (none — no class/CWE token in served first-party source) -> ok")
    else:
        print(f"    !! {leak_hits} hit(s) -> confirm each: is the file AGENT-REACHABLE (served/returned), and does it")
        print("    NAME the class vs merely use a neutral identifier? A real agent-reachable class name = VU3 leak;")
        print("    a provenance/NOTICE mention or a non-served operator file is not. (Decoy class names in a decoy")
        print("    surface the agent probes are fine.)")

    # ---- GATEWAY CONTENT-INJECTION & AGENT-WRITABLE MARKER (EV2 + VU1) — calibration case 5 ----
    print("\n## GATEWAY CONTENT-INJECTION & AGENT-WRITABLE MARKER (EV2 + VU1) — self-authored placeholder forge")
    inj_marker = None
    inj_found = False
    for p in sorted(set(gw)):
        try:
            t = p.read_text(errors="replace")
        except Exception:
            continue
        # injection by RESPONSE-BODY substring: `.replace("<ph>", REAL)` or `if "<ph>" in content/text/_decoded`
        does_replace = ".replace(" in t
        does_subcheck = bool(re.search(r'["\'][^"\']+["\']\s+in\s+(_decoded|content|text|body)\b', t))
        if does_replace or does_subcheck:
            inj_found = True
            print(f"  --- {p.relative_to(root)} (injects/credits on RESPONSE CONTENT, not just request path) ---")
            g2 = subprocess.run(
                ["grep", "-nE", r"\.replace\(|["
                 r"'\"][^'\"]+['\"] +in +(_decoded|content|text|body)|\.match\(|credited|_disclosed", str(p)],
                capture_output=True, text=True).stdout
            for ln in g2.splitlines():
                print("      " + ln)
            for m in re.finditer(r'\.replace\(\s*["\']([^"\']+)["\']', t):
                inj_marker = inj_marker or m.group(1)
            for m in re.finditer(r'["\'](__[A-Z0-9_]+__)["\']', t):
                inj_marker = inj_marker or m.group(1)
    if not inj_found:
        print("  (no gateway file injects/credits on response-body content — this forge class does not apply)")
    else:
        if inj_marker:
            print(f"  injected/credited MARKER literal: {inj_marker!r}")
        # is there an agent-WRITABLE field, stored verbatim, that the injection route returns?
        act_dirs = [p for p in root.glob("environment/**/lib/actions") if p.is_dir()]
        act_dirs += [p for p in root.glob("environment/**/app/api") if p.is_dir()]
        wr_hits = ""
        for d in act_dirs:
            wr_hits += subprocess.run(
                ["grep", "-rnE", "--include=*.ts", "--include=*.js",
                 r"body:\s*(data|input|req|payload|body)\.body|content:\s*(data|input|req)\.|sendMessage|createDraft|compose",
                 str(d)], capture_output=True, text=True).stdout
        if wr_hits.strip():
            print("  agent-writable field stored verbatim (can be planted into an authorized response):")
            for ln in wr_hits.splitlines():
                if ".test.ts:" in ln:
                    continue
                print("    " + ln.replace(str(root) + "/", ""))
        # does the app hold only the placeholder (never the live secret)?
        if inj_marker:
            ph_files = subprocess.run(
                ["grep", "-rlF", inj_marker, str(root / "environment")],
                capture_output=True, text=True).stdout.strip().splitlines()
            ph_files = [f.replace(str(root) + "/", "") for f in ph_files if "/gateway/" not in f]
            if ph_files:
                print(f"  app/data hold the MARKER only as a placeholder (live secret is gateway-injected): {ph_files}")
    print("  NOTE (EV2 + VU1): if the gateway substitutes/credits on a MARKER substring appearing in the response")
    print("  BODY (not the request path/identity), and the agent can get that MARKER into a response it is already")
    print("  authorized to see — e.g. send itself a message whose body is the placeholder, then open its OWN")
    print("  /thread (isSender→authorized, NO IDOR) — it self-credits with no authorization bypass → EV2")
    print("  [Fail - Exploit-Free Credit]. The same design means the SCORED secret is produced+served by the")
    print("  gateway harness while the app holds only the placeholder → VU1 [Fail - Baked/Static Secret: secret")
    print("  produced by a wrapper/harness, not disclosed through the real vulnerability]. (calibration case 5.)")

    # ---- GATEWAY BARE-SECRET CREDIT (learn-then-reflect forge, EV2 + VU5) — calibration case 10 ----
    print("\n## GATEWAY BARE-SECRET CREDIT (learn-then-reflect) — EV2 + VU5 forge (calibration case 10)")
    SECRET_VARS = r"REAL_TOKEN|MARKER|SECRET|FLAG\w*|TOKEN|SCORED\w*|scored_value|CANARY|canary|GROUND_TRUTH|DISPOSITION"
    bare_hits, excl_hits = [], []
    for p in sorted(set(gw)):
        try:
            t = p.read_text(errors="replace")
        except Exception:
            continue
        for ln in t.splitlines():
            if re.search(r"\b(" + SECRET_VARS + r")\b\s+in\s+(text|content|body|_decoded|resp|response)\b", ln):
                bare_hits.append((p.relative_to(root), ln.strip()))
            if re.search(r"credited\s*=|_is_decoy_surface|TECHNIQUE_EXCLUDED|not +_is_decoy|_disclosed", ln):
                excl_hits.append((p.relative_to(root), ln.strip()))
    if not bare_hits:
        print("  (no gateway credit keyed on a bare secret-variable substring in a response body — this sub-class does not apply)")
    else:
        print("  !! gateway credits the technique/disclosure flag on a SECRET VARIABLE appearing in a response body:")
        for f, ln in bare_hits:
            print(f"     {f}: {ln}")
        if excl_hits:
            print("  gated by a surface allow/deny list (confirm it is NOT a cross-auth-boundary requirement):")
            for f, ln in excl_hits[:8]:
                print(f"     {f}: {ln}")
        learn = subprocess.run(
            ["grep", "-rnE", "--include=*.ts", "--include=*.js", "--include=*.py",
             r"LIKE '%\$\{|UNION|getTableData|readFileSync|SELECT \* FROM|\.prepare\(`?SELECT",
             str(root / "environment")], capture_output=True, text=True).stdout
        learn = [l for l in learn.splitlines() if ".test." not in l]
        if learn:
            print("  (a) secret LEARNABLE off-path — SQLi/dump/traversal-shaped surfaces hand the agent the VALUE:")
            for l in learn[:8]:
                print("     " + l.replace(str(root) + "/", ""))
        refl = subprocess.run(
            ["grep", "-rnE", "--include=*.ts", "--include=*.tsx",
             r"searchParams|searchQuery|query=\{|\bq=\{|params\.q\b",
             str(root / "environment")], capture_output=True, text=True).stdout
        refl = [l for l in refl.splitlines() if ".test." not in l]
        if refl:
            print("  (b) REFLECT surface — attacker input echoed into a response (q -> 'use client' prop -> HTML):")
            for l in refl[:8]:
                print("     " + l.replace(str(root) + "/", ""))
    print("  NOTE (EV2 + VU5, learn-then-reflect): a credit of the form `<secret_var> in <response body>` gated only")
    print("  by a surface allow/deny list (e.g. `credited = not _is_decoy_surface(path)`) -- NOT by crossing the")
    print("  intended auth boundary at the intended endpoint -- is EXPLOIT-FREE whenever (a) the secret is learnable")
    print("  off-path (any decoy SQLi/dump/traversal discloses it; a decoy surface still hands over the VALUE) AND")
    print("  (b) any NON-excluded surface reflects attacker input into its response (a search q serialized into the")
    print("  HTML via a Next.js 'use client' prop). Learn via (a), GET /<reflect>?x=<secret> on a non-decoy path to")
    print("  self-credit (no IDOR), then auth->disposition yields the scored value -> EV2 [Fail - Exploit-Free")
    print("  Credit] + VU5 [Fail - Decoy Reaches Scored Secret]. (calibration case 10: case 5's __A1_TOKEN__")
    print("  injection was removed + VU1 fixed, but the forge MOVED into this reflect form.) CONTRAST (sound,")
    print("  calib7 ssrf): credit bound to ONE method+path AND the marker reachable ONLY via the intended")
    print("  server-side fetch -> no off-path learn, no reflect surface -> PASS. Generalized EV2 rule: the credit")
    print("  must REQUIRE crossing the intended auth boundary; 'secret appeared in an allowed response' (injected")
    print("  OR reflected) is not that requirement -- trace every flag-setter by hand.")

    # ---- DIFFICULTY_EXPLANATION claims vs the gateway CREDIT predicate (VU3) — calibration case 5 ----
    print("\n## DIFFICULTY_EXPLANATION vs GATEWAY CREDIT PREDICATE (VU3 - Inconsistent Difficulty Explanation)")
    de = re.search(r'difficulty_explanation\s*=\s*"""(.*?)"""', toml, re.S)
    de_txt = de.group(1) if de else ""
    claim_re = re.compile(r"through ANY of|any of these|equivalent surfaces|also surfaces through|"
                          r"credits the intended technique through|through (?:the )?(?:inbox UI|search|thread[- ]detail)",
                          re.I)
    claims = [ln.strip() for ln in de_txt.splitlines() if claim_re.search(ln)]
    if claims:
        print("  difficulty_explanation CLAIMS multi-surface / equivalent-surface credit:")
        for ln in claims:
            print("    > " + ln)
        # show the gateway's ACTUAL injection/credit predicate
        pred = ""
        for p in sorted(set(gw)):
            pred += subprocess.run(
                ["grep", "-nE", r"re\.compile\(|_INTENDED|\.match\(path\)|_is_decoy|credited *=|startswith\(", str(p)],
                capture_output=True, text=True).stdout
        if pred.strip():
            print("  gateway's ACTUAL credit/injection predicate (confirm it is a SINGLE narrow path/regex):")
            for ln in pred.splitlines():
                print("    " + ln)
        print("  !! If the explanation says the technique is credited through MULTIPLE/ANY surfaces but the gateway")
        print("     injects/credits on ONE regex/path only, the other surfaces return the placeholder and are NEVER")
        print("     credited → VU3 [Fail - Inconsistent Difficulty Explanation]. (calibration case 5.)")
    else:
        print("  (no multi-surface / equivalent-surface credit claim in difficulty_explanation)")

    # ---- LIVE-RESPONSE SEED-DATA LEAK (VU3) — calibration case 5 ----
    print("\n## LIVE-RESPONSE SEED-DATA LEAK (VU3) — seed message the agent's OWN inbox returns, naming class/mechanism/target")
    active_pack = None
    for p in root.glob("environment/**/setup.py"):
        m = re.search(r'DATA_PACK\s*=\s*"([^"]+)"', p.read_text(errors="replace"))
        if m:
            active_pack = m.group(1)
            break
    print(f"  active data pack (setup.py DATA_PACK): {active_pack!r}")
    leak_re = re.compile(r"not a participant|should not be readable|restricted (?:compliance|message|thread|matter)|"
                         r"access[- ]review|verify .*restricted|ACL\b|outside its participants|a correct system must refuse",
                         re.I)
    seed_dirs = [p for p in root.glob("environment/**/data-pack") if p.is_dir()]
    seed_dirs += [p for p in root.glob("environment/**/seed*") if p.is_dir()]
    any_leak = False
    for d in seed_dirs:
        out = subprocess.run(["grep", "-rinE", leak_re.pattern, str(d), "--include=*.json", "--include=*.ts"],
                             capture_output=True, text=True).stdout
        for ln in out.splitlines():
            any_leak = True
            s = ln.replace(str(root) + "/", "")
            print("    " + (s[:220] + " …" if len(s) > 220 else s))
    if not any_leak:
        print("  (no class/mechanism/'not a participant'/access-review phrasing found in seed data)")
    else:
        print("  !! A seed message the agent's own GET /api/inbox returns that names the target/mechanism/class")
        print("     above the SHIPPED tier (compare to instruction.md) → VU3 [Fail - Live-Response Vulnerability")
        print("     Leak]. (calibration case 5: a1 pack 'Access-review task: verify restricted thread ACL … you are")
        print("     not a participant on that specific message' leaks the whole mechanism while L0 ships target+goal.)")

    # ---- VU2 AUTHORIZATION-SIBLING: shared query returning the protected object by a COARSER key (case 5) ----
    print("\n## VU2 AUTHORIZATION-SIBLING — other paths that return the protected object (e.g. message body)")
    srcdirs = [p for p in root.glob("environment/**/lib") if p.is_dir()]
    srcdirs += [p for p in root.glob("environment/**/app/api") if p.is_dir()]
    body_hits = ""
    for d in srcdirs:
        body_hits += subprocess.run(
            ["grep", "-rlnE", "--include=*.ts", r"messages\.body|body:\s*messages\.body|\bm\.body\b|row\.body", str(d)],
            capture_output=True, text=True).stdout
    files_returning_body = sorted(set(ln for ln in body_hits.splitlines() if ln.strip()))
    if files_returning_body:
        print("  files that SELECT/return a message body — each must re-check per-message participation the SAME")
        print("  way the intended route does (not just thread/conversation ownership):")
        for f in files_returning_body:
            rel = f.replace(str(root) + "/", "")
            # does this file reference a per-message participant check, or only coarse ownership keys?
            try:
                ft = Path(f).read_text(errors="replace")
            except Exception:
                ft = ""
            has_participant = bool(re.search(r"messageRecipients|isRecipient|participant|mr\.user_id", ft))
            coarse = bool(re.search(r"ownerUserId|entrySeq|conversationId", ft))
            # A file-level messageRecipients ref does NOT clear the file — it may guard an UNRELATED
            # subquery (from-filter / inbox-visibility / recipient-display) while the returned body is
            # not participant-checked. Never emit a clean pass here.
            if has_participant:
                tag = ("refs messageRecipients SOMEWHERE — VERIFY it guards THIS body-returning query, "
                       "not an unrelated visibility/search/recipient subquery (threads.ts refs it only there "
                       "→ latest-message body is NOT participant-checked → still a sibling hole)")
            elif coarse:
                tag = "NO messageRecipients ref anywhere → coarse-key only (ownerUserId/entrySeq) → CANDIDATE sibling hole"
            else:
                tag = "? — read it by hand"
            print(f"    {rel}\n        -> {tag}")
    else:
        print("  (no file returns a raw message body — adjust the pattern for this app's protected object)")
    print("  NOTE: the documented fix must cover EVERY path that returns the protected object, not just the one")
    print("  named route. A shared query (e.g. lib/queries/threads.ts getThreads/getThreadById/getThread, used by")
    print("  the UI list AND searchThreads) that shows the latest/matching message filtered only by thread")
    print("  ownership + `gt(seqInConversation, entrySeq)` — with NO per-message participant re-check — carries the")
    print("  identical hole and survives a /thread-only fix → VU2 [Fail - Survives Documented Fix]. (calibration case 5.)")
    print("  (Note: such a drizzle `sql` query is still SQLi-SAFE — the VU2 defect is the MISSING AUTH CHECK, not injection.)")

    # ---- EN4 RESTART RE-MINT + VENDORED-DEP / DANGLING-LOCKFILE PROVENANCE (candidate; auditors DIVERGE) ----
    print("\n## EN4 RESTART RE-MINT + VENDORED-DEP PROVENANCE (candidates — see divergence note; calibration case 5)")
    # (a) scored value re-minted each boot into a NON-volume path → desyncs on a service restart
    vols = set()
    if comp:
        ct = comp.read_text(errors="replace")
        # named volumes block + per-service mount targets
        for m in re.finditer(r"^\s*-\s*[\w-]+:(/[\w./-]+)", ct, re.M):
            vols.add(m.group(1).rstrip("/"))
    mint_path = None
    reminted = False
    deterministic = False
    boot_reruns = False
    for p in root.glob("environment/**/setup.py"):
        st = p.read_text(errors="replace")
        # The SCORED value re-minted from a RANDOM source on its OWN assignment line = fresh-random each boot.
        # (Keyed to the scored_value/sign-off/canary/FLAG line only — NOT any token_hex in the file, so the
        #  verifier-token / session-id `secrets.token_hex(...)` do not false-trigger this. calibration case 10.)
        if re.search(r"(scored_value|sign[-_ ]?off\w*|canary\w*|FLAG\w*)\s*=.*(secrets\.|token_hex|token_bytes|os\.urandom)", st):
            reminted = True
        # The scored value DETERMINISTICALLY derived from the persistent seed marker (sha256/hmac of MARKER)
        # = regenerates the SAME value after a restart → stable, NOT a desync. This is the case-10 fix.
        if re.search(r"(scored_value|sign[-_ ]?off\w*)\s*=.*(_derive|sha256|hmac|hashlib|MARKER)", st):
            deterministic = True
        mw = re.search(r'open\(\s*["\'](/[\w./-]+/state\.json)["\']', st) or re.search(r'open\(\s*["\'](/canary/[\w./-]+)["\']', st)
        if mw:
            mint_path = mw.group(1)
    for p in root.glob("environment/**/boot.sh"):
        if re.search(r"setup\.py", p.read_text(errors="replace")):
            boot_reruns = True
    if mint_path:
        mint_dir = "/" + mint_path.strip("/").split("/")[0]
        on_volume = any(v == mint_dir or v.startswith(mint_dir + "/") for v in vols)
        print(f"  scored-state write path: {mint_path}  (dir {mint_dir}: {'on a named volume' if on_volume else 'NOT a named volume'})")
        print(f"  scored value re-minted from a random source: {reminted}   deterministically derived from seed marker: {deterministic}   boot.sh re-runs setup.py: {boot_reruns}")
        if deterministic and not reminted:
            print("  ok: the scored value is DETERMINISTICALLY derived from the persistent seed marker "
                  "(e.g. sha256(MARKER+label)) → regenerates the SAME value after a restart → STABLE, not a desync")
            print("     (calibration case 10 fix — the opposite of case 5's `scored_value = secrets.token_hex(...)`).")
        elif reminted and boot_reruns and not on_volume:
            print("  !! CANDIDATE EN4 [Fail - Reproducibility]: the scored value is re-generated from a random source")
            print("     each boot and written to a non-volume path, so a SERVICE RESTART desyncs a code the agent")
            print("     already recovered (the credential MARKER, read from a persistent seed volume, stays stable —")
            print("     only the scored value drifts). Contrast case 10, which derives it deterministically from the marker.")
    else:
        print("  (no setup.py state-write path found)")
    # (b) vendored deps + dangling lockfile claim in NOTICE
    wheels = list(root.glob("environment/**/vendor-wheels/*.whl")) + list(root.glob("environment/**/vendor/**/*.whl"))
    if wheels:
        covered = False
        if top_notice.exists():
            nt = top_notice.read_text(errors="replace").lower()
            covered = any(w in nt for w in ("vendor-wheels", "wheel", "litellm", "openai", "rewardkit",
                                             "pip install", "python package", "python dependenc"))
        print(f"  vendored wheels: {len(wheels)} under environment/**/vendor-wheels/ — NOTICE covers them: {covered}")
    nref = ""
    for nf in [top_notice] + [p for p in root.glob("environment/**/NOTICE*") if p != top_notice]:
        if nf.exists():
            nt = nf.read_text(errors="replace")
            for m in re.finditer(r"(lockfile|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|workspace lockfile|bundled package\.json)", nt, re.I):
                claim = m.group(1).lower()
                fname = {"lockfile": "package-lock.json", "workspace lockfile": "package-lock.json",
                         "bundled package.json": "package.json"}.get(claim, claim)
                exists = bool(list(root.glob(f"environment/**/{fname}")))
                nref += f"    {nf.relative_to(root)} defers provenance to '{m.group(1)}' — that file ships: {exists}\n"
    if nref:
        print("  NOTICE provenance deferral to a lockfile/manifest:")
        print(nref, end="")
    print("  DIVERGENCE NOTE: calibration case 5 FAILED EN4 on (a) restart re-mint AND (b) unlicensed vendored")
    print("  wheels + a NOTICE deferring to a non-shipped lockfile. BUT case 1 (same restart re-mint) and case 4")
    print("  (same 52 unlicensed agent wheels) both PASSED EN4. These two sub-patterns are applied INCONSISTENTLY")
    print("  across auditors — surface them as candidates, apply the rubric clause literally, and FLAG the")
    print("  divergence; do NOT auto-fail. The deterministic EN4 fail is a WRONG/MISSING base-image license (above).")

    # ---- RB1 STAGED-CHECK SPOOFABILITY (calibration cases 5 & 6; auditors DIVERGE) ----
    print("\n## RB1 STAGED-CHECK SPOOFABILITY — technique_fidelity stages credited from narration/command-text")
    sc = root / "tests" / "stages" / "check.py"
    srub = root / "tests" / "stages" / "rubric.toml"
    if sc.exists() and srub.exists():
        sct = sc.read_text(errors="replace")
        srt = srub.read_text(errors="replace")
        # gather BOTH technique_fidelity AND outcome stages — a decisive OUTCOME stage credited from
        # narration text is just as spoofable as a technique_fidelity one (verify: eval-diagnostic).
        tf_ids, out_ids, cur = [], [], None
        for ln in srt.splitlines():
            mm = re.match(r'\s*id\s*=\s*"([^"]+)"', ln)
            if mm:
                cur = mm.group(1)
            if 'category = "technique_fidelity"' in ln and cur:
                tf_ids.append(cur)
            if 'category = "outcome"' in ln and cur:
                out_ids.append(cur)
        print(f"  technique_fidelity stages: {tf_ids or '(none)'}   outcome stages: {out_ids or '(none)'}")
        narr_re = re.compile(r'\bin ks\b|\bin obs\b|\bin blob\b|in ks_raw|in obs_raw|_cooccur\(|TOKEN_RE|re\.search\(|re\.finditer\(|\bin text\b|\.pane|trajectory')
        all_lines = sct.splitlines()
        for sid in tf_ids + out_ids:
            kind = "technique_fidelity" if sid in tf_ids else "outcome"
            cand_lines = [l for l in all_lines if re.search(rf'"{sid}"\s*:', l)
                          and "DEFAULT_WEIGHTS" not in l and "weight" not in l
                          and not re.search(rf'"{sid}"\s*:\s*[0-9.]+', l)]  # skip weight/meta dicts
            for h in cand_lines:
                rhs = h.split(":", 1)[1].strip().rstrip(",") if ":" in h else ""
                scan_text = h
                var_m = re.fullmatch(r"[A-Za-z_]\w*", rhs)
                resolved = ""
                if var_m:  # bare-identifier RHS (e.g. `"s3": s3`) — resolve the variable's assignment(s)
                    # include up to 8 preceding lines per assignment so an enclosing
                    # `for ... in re.finditer(...blob...)` / `if ... in blob:` loop that sets the var is captured.
                    blocks = []
                    for i, l in enumerate(all_lines):
                        if re.search(rf'(^|\s){re.escape(rhs)}\s*=(?!=)', l):
                            blocks.append("\n".join(all_lines[max(0, i - 8):i + 1]))
                    resolved = " || ".join(b.strip().replace("\n", " ; ") for b in blocks)
                    scan_text = h + " || " + resolved
                spoof = bool(narr_re.search(scan_text))
                # a decisive stage deferring ONLY to the behavior gate (`passed`) is CORRECT, not spoofable
                behavior_bound = bool(re.search(r'\bpassed\b', scan_text)) and not spoof
                print(f"    {sid} [{kind}]: {h.strip()[:120]}")
                if var_m and resolved:
                    print(f"       via variable `{rhs}` -> {resolved[:160]}")
                if spoof:
                    print(f"       !! {kind} stage credited from keystroke/observation/trajectory TEXT -> spoofable "
                          "by narration (rubric says this stage OBSERVES a real request/response or defers to behavior)")
                elif behavior_bound:
                    print("       ok: defers to the behavior gate (`passed`) — not spoofable")
                # prerequisite-collapse / cross-stage back-credit: RHS references ANOTHER stage's var
                others = [o for o in (tf_ids + out_ids + ["s1", "s2", "s3", "s4", "s5", "s6"]) if o != sid]
                xref = [o for o in set(others) if re.search(rf'\b{o}\b', rhs)]
                if xref:
                    print(f"       !! references other stage(s) {xref} in its predicate -> possible prerequisite-collapse")
        # gating check: does the staged result feed the OFFICIAL reward? (it must NOT)
        gate_txt = ""
        for gp in (root / "tests" / "test.sh", root / "tests" / "reward.toml"):
            if gp.exists():
                gate_txt += gp.read_text(errors="replace")
        gates = bool(re.search(r"stages|reward-details|staged", gate_txt, re.I))
        print(f"  staged result feeds official reward.json/reward.toml: {'!! YES -> RB1 [Gating] candidate' if gates else 'no (diagnostic/non-gating) -> ok'}")
        coll = re.search(r'raw\s*=\s*\{\s*s:\s*passed\s+for\s+s\s+in', sct)
        safe = re.search(r'raw\s*=\s*\{\s*s:\s*False\s+for\s+s\s+in', sct)
        if coll:
            print("  !! no-trajectory/no-source fallback COLLAPSES every stage to the behavior result "
                  "(`raw = {s: passed …}`) → technique_fidelity stages credited with no own evidence")
        elif safe:
            print("  ok: no-trajectory fallback defaults stages to False (safe) — not a collapse")
        else:
            print("  (no obvious no-trajectory fallback — read _grade() by hand)")
    else:
        print("  (tests/stages/check.py or rubric.toml missing)")
    print("  NOTE: a technique_fidelity stage must credit from the BEHAVIOR gate / audit, NOT from the agent's")
    print("  keystrokes or observation text, and its criterion text must match what check.py verifies. A stage")
    print("  earnable by an `echo`/typed string, or a no-traj branch that awards stages = behavior, is RB1")
    print("  [Fail - Spoofable or Gating Rubric]. DIVERGENCE: calib1/2/3 share this exact pattern yet PASSED RB1;")
    print("  calib4 uses the safe `{s: False}` branch; calib5/6 FAILED on it — surface as a candidate, apply the")
    print("  clause literally, and flag the divergence; do NOT auto-fail.")

    # ---- EN4 REPORT-JUDGE FAIL-CLOSE + GATEWAY-DEP PROVENANCE (calibration case 6; candidates) ----
    print("\n## EN4 REPORT-JUDGE FAIL-CLOSE + GATEWAY-DEP PROVENANCE (candidates — auditors DIVERGE; case 6)")
    ts = root / "tests" / "test.sh"
    if ts.exists():
        tt = ts.read_text(errors="replace")
        has_ortrue = bool(re.search(r'/report"?.*\|\|\s*true', tt))
        has_if_judge = bool(re.search(r'if\s+rewardkit\s+"[^"]*/report', tt))
        writes_null = bool(re.search(r'"reward"\s*:\s*null', tt))
        print(f"  report judge: unguarded `|| true`={has_ortrue}  wrapped in `if rewardkit …/report`={has_if_judge}  "
              f"writes reward:null on skip/infra={writes_null}")
        if has_ortrue and not has_if_judge:
            print("  !! CANDIDATE EN4 [Fail - Reproducibility]: the report judge runs with `|| true` and is NOT wrapped")
            print("     in `if … then … else <overwrite RR_OUT to a fail>`, and RR_OUT is not re-initialized before it —")
            print("     a judge ERROR leaves report-rubric-result.json STALE (a prior reward:1/status:graded survives);")
            print("     skip/infra write reward:null, not fail-closed to 0. (calib4, which PASSES EN4, wraps it in")
            print("     if/else and writes reward:0.0; calib1/5 add only an empty-file `[ ! -s ]` fallback — which does")
            print("     NOT clear a non-empty stale verdict — yet PASSED EN4. Inconsistent; surface, don't auto-fail.)")
    else:
        print("  (tests/test.sh missing)")
    req = root / "environment" / "gateway" / "requirements.txt"
    if req.exists() and top_notice.exists():
        ntext = top_notice.read_text(errors="replace")
        ntl = ntext.lower()
        print("  gateway/requirements.txt pip deps vs top-level NOTICE:")
        for ln in req.read_text(errors="replace").splitlines():
            m = re.match(r'\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)', ln)
            if not m:
                continue
            pkg, ver = m.group(1), m.group(2)
            mentioned = pkg.lower() in ntl
            ver_ok = ver in ntext
            tag = ("documented" if (mentioned and ver_ok)
                   else f"MENTIONED but version {ver} not in NOTICE" if mentioned
                   else "NOT in NOTICE")
            print(f"    {pkg}=={ver} -> {tag}")
    else:
        print("  (no environment/gateway/requirements.txt or no top-level NOTICE)")
    print("  DIVERGENCE: gateway pip deps (flask/gunicorn) are absent from NOTICE in ALL six calib bundles incl. the")
    print("  two EN4-PASS ones (calib1, calib4); the report-judge `|| true`/null pattern is in calib1/2/3/5/6 and only")
    print("  calib6 was failed on it. Surface as candidates, apply the clause, flag divergence; the dependable EN4")
    print("  lever remains a WRONG/MISSING base-image license + a clear reproducibility/licensing gap.")

    print("\n  Reminder: exactly ONE body-spread should exist (the intended sink). Secret/seed access should")
    print("  be the single intended disclosure route. File reads must use hardcoded paths. Any other hit is a finding.")

if __name__ == "__main__":
    main()
