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
import importlib.util as _ilu


def _load_qc():
    """v1.3: ONE implementation for both tools -- trial discovery, runtime egress, wheel licensing and the F3 format
    regex come from helpers/qc_selfcheck.py (a trusted sibling file, loaded by explicit path; -I keeps the bundle
    out of sys.path)."""
    try:
        spec = _ilu.spec_from_file_location("qc_selfcheck_shared", str(Path(__file__).resolve().parent / "qc_selfcheck.py"))
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception as e:
        print(f"# NOTE: helpers/qc_selfcheck.py not loadable ({e!r}); shared sections fall back to local scans")
        return None


def main():
    # v14 (item 1): `--mode pre|post` forces the mode, exactly as qc_selfcheck's flag does (default: auto)
    args = [a for a in sys.argv[1:]]
    mode = None
    for i, a in enumerate(list(args)):
        if a.startswith("--mode"):
            val = a.split("=", 1)[1] if "=" in a else (args[i + 1] if i + 1 < len(args) else "")
            if val not in ("pre", "post", "auto"):
                sys.exit("usage: audit_facts.py <task_root> [--mode auto|pre|post]")
            mode = None if val == "auto" else val
            args = [x for j, x in enumerate(args) if j != i and not (j == i + 1 and "=" not in a)]
            break
    if not args:
        sys.exit("usage: audit_facts.py <task_root> [--mode auto|pre|post]")
    root = Path(args[0]).resolve()
    if not (root / "task.toml").exists():
        sys.exit(f"ERROR: {root}/task.toml not found — pass the inner task/ dir")

    print(f"# audit_facts for {root}\n")
    _QC = _load_qc()
    _QCX = _QC.Ctx(str(root), mode=mode) if _QC is not None else None
    _PRE = (getattr(_QCX, "mode", None) == "pre") if _QCX is not None else not (root / "trajectories" / "pass@k").is_dir()
    if _QC is not None:
        print(f"# shared checks from qc_selfcheck {getattr(_QC, 'QC_TOOL_VERSION', '(unversioned -- stale copy?)')}")
        # v14 (item 1): the mode decides which clauses are scored now and which wait for the pass@5 run
        print(f"# MODE: {'PRE-PASS@K (pass@5 clauses DEFERRED)' if getattr(_QCX, 'mode', 'post') == 'pre' else 'POST-PASS@K'}"
              f" ({getattr(_QCX, 'mode_src', '?')}) -- qc_selfcheck --mode pre|post forces it\n")

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
    # tolerate `[ agent ]`, a trailing comment, and the inline table `agent = { user = "agent" }` (same as qc)
    _tsec, _tsca = (getattr(_QCX, "toml_section", None), getattr(_QCX, "toml_scalar", None)) if _QCX is not None else (None, None)
    _isroot = getattr(_QC, "_is_root_identity", None) if _QC is not None else None
    if _tsec and _tsca:  # V13e (#40): the qc TOML reader (tomllib on >=3.11), so qc and audit_facts agree
        _asec = _tsec("agent")
        am = bool(str(_asec or "").strip()) or bool(re.search(r"(?m)^\[[ \t]*agent[ \t]*\]|^[ \t]*agent[ \t]*=", toml))
        _u = _tsca(_asec, "user") if _asec else None
        um = re.match(r"(.*)", str(_u), re.S) if _u is not None else None
    else:
        am = re.search(r"(?ms)^\[[ \t]*agent[ \t]*\][ \t]*(?:#[^\n]*)?$(.*?)(?=^\[|\Z)", toml) or \
            re.search(r"(?m)^[ \t]*agent[ \t]*=[ \t]*\{([^}\n]*)\}", re.split(r"(?m)^\[", toml, maxsplit=1)[0])
        agent_block = am.group(1).replace(",", "\n") if am else ""
        um = re.search(r'^\s*user\s*=\s*"([^"]*)"', agent_block, re.M)
    if not am:
        print("  task.toml [agent] user: !! NO [agent] TABLE -> F5 [Fail - Packaging Hygiene] candidate (task.toml omits a non-root agent identity)")
    elif not um:
        print("  task.toml [agent] user: !! MISSING -> F5 [Fail - Packaging Hygiene] candidate (task.toml [agent] declares no `user`; a Dockerfile USER does NOT satisfy the rubric's task.toml requirement)")
    elif (_isroot(um.group(1)) if _isroot else um.group(1) in ("root", "0")):
        print(f"  task.toml [agent] user: !! '{um.group(1)}' is ROOT(-equivalent) -> F5 [Fail - Packaging Hygiene] candidate")
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
    for d in ("trajectories/oracle", "trajectories/noop") + (() if _PRE else ("trajectories/pass@k",)):
        if not (root / d).exists():
            miss.append(d)
    if _PRE:
        print("  pass@k: DEFERRED (pre-pass@k) -- F1's pass@k clause is checked after the pass@5 run")
    # v14 (items 3, 24): oracle/ and noop/ each hold reward.txt + a NON-EMPTY test.log
    for d in ("oracle", "noop"):
        for f in ("reward.txt", "test.log"):
            fp = root / "trajectories" / d / f
            if not fp.exists() or fp.stat().st_size == 0:
                print(f"  !! trajectories/{d}/{f} {'EMPTY' if fp.exists() else 'MISSING'} -> F1 [Fail - Required Structure] [Tier A]"
                      + (" (+TR2: the noop log must show the rejected submission)" if d == "noop" and f == "test.log" else ""))
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
    # pass@k: >=3 trials with trajectory.json + a NON-EMPTY verifier/test-stdout.txt (F1's text: present AND non-empty).
    # Any job-dir name (task-*, <task-name>-<date>, ...); EV5/TR2 still read the reward artifacts, not this capture.
    pk = root / "trajectories" / "pass@k"
    if _QC is not None:  # NON-errored trials with a parseable trajectory.json + test-stdout.txt (the qc count)
        _good = [Path(r[0]) for r in _QC.passk_trials(_QCX) if r[2] and r[3] and not _QC.trial_errored(r[0], _QCX)]
    else:
        _good = sorted({p.parent.parent for p in pk.glob("**/agent/trajectory.json")
                        if (p.parent.parent / "verifier" / "test-stdout.txt").exists()}) if pk.exists() else []
    _full = [tr for tr in _good if (tr / "verifier" / "test-stdout.txt").stat().st_size > 0]
    if _QC is None:  # V13e (#45): no errored-trial exclusion without qc -- the count below is not the qc count
        print(f"  pass@k trials with trajectory.json + test-stdout.txt: {len(_good)} (non-empty: {len(_full)}) "
              "-- UNVERIFIED (qc not loaded): errored trials are not excluded; re-run beside qc_selfcheck.py")
    else:
        _nerr = len([r for r in _QC.passk_trials(_QCX) if _QC.trial_errored(r[0], _QCX)])
    if not _PRE and _QC is not None:
        print(f"  pass@k non-errored trials with trajectory.json + test-stdout.txt: {len(_good)} (non-empty test-stdout.txt: "
              f"{len(_full)}) "
              + ("ok (>=3)" if len(_full) >= 3 else "!! <3 with a NON-EMPTY test-stdout.txt -> F1 [Fail - Required Structure] [Tier A]"
                 + (" (all captures empty: tests/test.sh prints nothing to stdout -- the rubric requires non-empty)"
                    if len(_good) >= 3 else ""))
              + (f"  (+{_nerr} errored, excluded)" if _nerr else ""))

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
    if form is not None and not isinstance(form, dict):  # V13e (#42): a JSON array / scalar is not a form
        print(f"  {form_file}: !! top-level JSON is a {type(form).__name__}, not an object -> no form fields read (F2/F4 by hand)")
        form = None
    if not form:
        print("  (no delivery.json / *submission*.json / *form*.json at task root -> the form may live on the PLATFORM, not in the")
        print("   bundle: ask the requester for the Vulnerability Type + the three explanation fields; only if unobtainable is")
        print("   F4's radio + dim-21 genuinely unscored -- SAY SO, don't leave blank)")
    else:
        print(f"  {form_file}:")
        # v1.3 (massassign): forms ship snake_case OR Title-Case keys ("Vulnerability Explanation") -- accept both.
        _fk = {re.sub(r"[^a-z0-9]+", "_", str(k).strip().lower()).strip("_"): v for k, v in form.items()}
        vt = _fk.get("vulnerability_type") or _fk.get("vulnerability_type_selection") or "(not present)"
        print(f"    vulnerability_type (F4 selection, compare to task.toml cwe/vulnerability_kind + the solve): {vt}")
        for fld in ("vulnerability_explanation", "complexity_increase", "model_failure_reason"):
            v = _fk.get(fld)
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
        has_key = {}             # v14: service -> declares a networks: key
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
            if cur_svc and re.match(r'^\s{4}networks:\s*', ln):
                has_key[cur_svc] = True
                fl = re.match(r'^\s{4}networks:\s*\[([^\]]*)\]', ln)   # flow list
                if fl:
                    svc_nets[cur_svc] += [x.strip().strip("'\"") for x in fl.group(1).split(",") if x.strip()]
                    continue
                in_net_list = True; continue
            if in_net_list:
                nm = re.match(r'^\s{4,}-\s*([\w-]+)\s*$', ln)      # list item (same-indent or deeper)
                dm = re.match(r'^\s{6}([\w-]+):\s*(?:\{\s*\}|null|~)?\s*$', ln)   # v14: map form (`backend:`)
                if nm:
                    svc_nets[cur_svc].append(nm.group(1))
                elif dm:
                    svc_nets[cur_svc].append(dm.group(1))
                elif re.match(r'^\s{2,4}[\w-]+:', ln) or re.match(r'^\S', ln):
                    in_net_list = False
        # top-level networks: <name>:\n ... internal: true
        for m in re.finditer(r'^\s{2}([\w-]+):\s*$(.*?)(?=^\s{2}\S|\Z)', comp_txt.split('networks:')[-1], re.M | re.S):
            if re.search(r'internal:\s*true', m.group(2)):
                internal_nets.add(m.group(1))
        if _QC is not None and _QCX.services():     # v14: the YAML-parsed model wins over the regex walk
            svc_nets = {k: sorted(_QCX.svc_nets(k)) for k in _QCX.services()}
            has_key = {k: isinstance(v, dict) and "networks" in v for k, v in _QCX.services().items()}
            internal_nets = {n for n in _QCX.networks() if _QCX.net_internal(n)}
        for svc, ns in svc_nets.items():
            # v14 (item 8): a service with no networks: key is on the project's `default` network
            if not has_key.get(svc):
                ns = []
            if ns:
                pub = [n for n in ns if n not in internal_nets]
                tag = f" [on: {','.join(ns)}]" + (f" PUBLIC-side: {','.join(pub)}" if pub else " (all internal)")
            else:
                tag = " [on: default -- no networks: key]"
            if svc == "main" and has_key.get(svc):
                tag += "  !! main declares networks: -> EN2 fail: REMOVE main's networks: key (guidelines §1.4)"
            print(f"      {svc}{tag}")
        if internal_nets:
            print(f"      internal:true networks: {sorted(internal_nets)}")
        print("      -> v14 (Nov 13 rule): main has NO networks: key (Compose puts it on default and the egress sidecar sets its")
        print("         network mode); every service main talks to also joins default; internal app/DB/registry sit ONLY on")
        print("         internal: true nets; [environment] and [agent] use network_mode = \"allowlist\" with allowed_hosts.")
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
    # any job-dir name (task-*, <task-name>-<date>, ...) and trials directly under pass@k -- the qc discovery
    _ev_trials = [Path(r[0]) for r in _QC.passk_trials(_QCX)] if _QC is not None else \
        (sorted({p.parent.parent for p in pk_root.glob("**/agent/trajectory.json")}) if pk_root.exists() else [])
    jobs = sorted({tr.parent for tr in _ev_trials})
    if not jobs:
        print("  (no pass@k job dir found)")
    for job in jobs:
        print(f"  job: {job.name}")
        # tier from run.log (one level up, or in job)
        _jtr = getattr(_QC, "job_tier_record", None) if _QC is not None else None
        _ttr = getattr(_QC, "trial_tier_record", None) if _QC is not None else None
        if _jtr and _ttr:  # V13e (#5, policy 4): run.log `Using tier` OR extra_instruction_paths in a config ([] = base)
            _jt = _jtr(_QCX)
            print(f"    recorded tier (job): {_jt or '(not recorded at job level)'}")
        else:
            tier = "(not recorded)"
            for logp in (job.parent / "run.log", job / "run.log"):
                if logp.exists():
                    m = re.search(r"Using tier (L\d+)", logp.read_text(errors="replace"))
                    if m:
                        tier = m.group(1)
                    break
            print(f"    recorded tier (run.log only; qc not loaded -- also check config.json extra_instruction_paths): {tier}")
        _untiered = []
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
        for trial in sorted(tr for tr in _ev_trials if tr.parent == job):
            if not trial.is_dir():
                continue
            rpath = trial / "verifier" / "reward.json"
            bv = "?"
            _tb = getattr(_QC, "trial_behavior", None) if _QC is not None else None
            if _tb:  # V13e (#22): BEHAVIOR (reward.json .behavior, else .reward) -- the qc definition
                bv = _tb(str(trial))
                bv = "?" if bv is None else bv
            elif rpath.exists():
                try:
                    _rj = json.loads(rpath.read_text())
                    bv = _rj.get("behavior", _rj.get("reward")) if isinstance(_rj, dict) else "(not an object)"
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
            _tinfo = ""
            if _ttr:
                _tr = _ttr(_QCX, str(trial))
                _tinfo = f"  tier={_tr}" if _tr else "  tier=(not recorded)"
                if not _tr:
                    _untiered.append(trial.name)
            _rl = getattr(_QC, "refusal_leads", None) if _QC is not None else None
            _leads = []
            if _rl:  # V13e (#2, policy 2): refusal LEADS (pane/observations + agent messages) -- read in context
                try:
                    _ttx = getattr(_QC, "_trial_texts", None)
                    if _ttx is not None:  # the exact qc EV5 source: pane (CRs kept) / decoded observations + agent messages
                        _term, _src, _msgs = _ttx(_QCX, str(trial))
                        _cl = getattr(_QC, "_LINE_SAFE_ANSI", None)
                        _term = _cl.sub("", _term or "") if _cl is not None else (_term or "")
                        _leads = [(f"{_src}:{n}", sn) for n, sn in _rl(_term)]
                        for _sid, _m in _msgs:
                            _leads += [(f"trajectory.json step {_sid} message", sn) for _, sn in _rl(_m)]
                        _leads = list(dict.fromkeys(_leads))
                    else:
                        _src, _txt = _QC._trial_obs_text(_QCX, str(trial))
                        _leads = [(f"{Path(_src).name}:{n}" if _src else f"obs:{n}", sn) for n, sn in _rl(_txt or "")]
                except Exception:
                    pass
            print(f"    {trial.name}: behavior={bv}{stginfo}{_tinfo}")
            for _w, _sn in _leads[:5]:
                print(f"      refusal lead: {_w} {str(_sn)[:120]!r} -- read in context (a lead, not a count that must be 0)")
        if _ttr and _untiered:
            print(f"    !! CANDIDATE EV5 [Fail - Tier Not Recorded] [Tier A]: no tier record for {_untiered}"
                  " (no `Using tier` line and no extra_instruction_paths in trial/job config)")
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
        print("    prove it is genuine (refusal leads read in context, exception_info=null, real HTTP responses, >=1 real non-solve);")
        print("    de-wrap ANSI/CR+wrapped pane lines before concluding a value was never observed.")

    # ---- EN4 service-discovery retry budgets (verifier/solver must be >= agent) ----
    print("\n## EN4 SERVICE-DISCOVERY RETRY BUDGETS (rubric: verifier/solver retry budget >= agent)")
    if _QC is not None:
        _wf, _wn = _QC._wait_budgets(_QCX)
        for _x in _wn:
            print(f"  v14 §1.4: {_x}")
        for _x in _wf:
            print(f"  !! v14 §1.4 EN4 [Fail - Reproducibility] [Tier A]: {_x}")
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

    # ---- freshness (v14, item 26): oracle/noop vs EVERY source file; pass@5 vs the current instruction_L0.md ----
    print("\n## EVIDENCE FRESHNESS (v14) — oracle/noop after the last edit (must-fix re-run); pass@5 only if L0 changed")
    if _QC is not None:
        _st = _QC.gl_evidence_staleness(_QCX)
        print(f"  qc GL-evidence-staleness: [{_st.verdict}] {(_st.failmode + ' :: ') if _st.failmode else ''}{_st.evidence}")
        for _w in _st.warn:
            print(f"    {_w}")
    print("  (the mtime listing below is the older pass@k-only view, kept for reference)")
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
            print("  graded source newer than the pass@k evidence by mtime (pass@5 re-runs only if instruction_L0.md changed --"
                  " qc GL-evidence-staleness above checks the L0 text; oracle/noop must be re-run after any edit):")
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
    print("\n## ENV-VAR VALUE LEAK (VU3) — the MAIN service's env values vs the foothold handoff")
    comp = next(iter(sorted(root.glob("environment/docker-compose.y*ml"))), None)
    if comp:
        _envrx = r"NO_PROXY|no_proxy|_URL|_HOST|APPSERVER|BACKEND|INTERNAL|_ENDPOINT"
        print(f"  compose: {comp.relative_to(root)}")
        _menv = None
        if _QCX is not None and getattr(_QCX, "svc_env", None):
            try:
                _menv = _QCX.svc_env("main")  # V13e (#10): main's env only (the qc scope), never other services'
            except Exception:
                _menv = None
        if _menv is not None and not (getattr(_QC, "yaml_degraded", None) and _QC.yaml_degraded(_QCX)):
            _mh = [f"{k}={v}" for k, v in sorted(_menv.items()) if re.search(_envrx, k)]
            for ln in _mh:
                print("    [main] " + ln)
            if not _mh:
                print("    [main] (no NO_PROXY/_URL/_HOST-style env keys)")
        else:  # fallback: grep the whole file, but label each hit with its owning top-level service
            _svc, _in, _own = None, False, {}
            _ct = comp.read_text(errors="replace").splitlines()
            for _i, _l in enumerate(_ct, 1):
                if re.match(r"^services\s*:", _l):
                    _in = True
                    continue
                if re.match(r"^\S", _l):
                    _in, _svc = False, None
                    continue
                _m = re.match(r"^( {2}|\t)([A-Za-z0-9_.-]+)\s*:", _l) if _in else None
                if _m:
                    _svc = _m.group(2)
                _own[_i] = _svc
            _hits = [(_i, _l) for _i, _l in enumerate(_ct, 1) if re.search(_envrx, _l)]
            print("    (compose not parsed by qc -- every hit labelled with its OWNING service; only [main] counts)")
            for _i, _l in _hits:
                print(f"    [{_own.get(_i) or 'top-level'}] {_i}:{_l.strip()}")
            if not _hits:
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
    _birf = getattr(_QC, "base_image_license_report", None) if _QC is not None else None
    _bir = None
    if _birf is not None and top_notice.exists():
        try:
            _bir = _birf(_QCX)  # V13e (#9): qc's per-image license check, so both tools agree
        except Exception as _e:
            print(f"  (qc base_image_license_report raised {_e}; local scan used)")
    if _bir is not None:
        print("  top-level environment/NOTICE.md (qc base_image_license_report):")
        for _r in _bir:
            _st = _r.get("status")
            _pre = "!! CANDIDATE EN4 [Tier A] (QC failed this in cases 2/3; case 7 is the lone PASS dissent) " if _st in ("wrong", "missing") else ""
            print(f"    {_pre}{_r.get('image')}: {str(_st).upper()} (NOTICE says {_r.get('notice_says')!r}; expected "
                  f"{_r.get('expected')!r}; at {_r.get('where')})")
        if not _bir:
            print("    (no Dockerfile FROM / build-less compose image found)")
    elif top_notice.exists():
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
    print("  LADDER (SKILL.md rule 5): a WRONG or MISSING base-image/app license is Tier A -- QC failed it in calib2/3 and")
    print("  the calib3->9 fix flipped EN4 to PASS. calib7 (a PASS bundle: busybox 'BSD-3-Clause', no python/app license)")
    print("  is the lone dissent -- mention it in the report, don't score on it. Other EN4 sub-patterns are classified")
    print("  one by one (v14, item 34: wheels below -- misstated AND undocumented are both Tier A; no QC-record leniency).")

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
        _harness = re.compile(r"/environment/(operator|verifier|[\w-]*-init|seed[\w-]*|sidecar[\w-]*)/|/NOTICE\.md:", re.I)
        # gateway / internal-service / registry RESPONSES are agent-reachable (web IS the gateway; a registry can sit
        # behind the planted SSRF) -- only their COMMENT lines are harness-only (calibration case 10)
        _svc_src = re.compile(r"/environment/(gateway|internal[_-]?service|[\w-]*registry)/", re.I)
        harness_hits = []
        for line in out.splitlines():
            # v1.3 (calibration case 10): a class token in HARNESS-ONLY source the agent cannot read (gateway /
            # internal-service / init / verifier code that no agent-reachable route serves) is a hygiene ADVISORY
            # (guidelines §1.5: strip class narration from comments), NOT a VU3 leak. Agent-readable source
            # (served, in main's image, or in the container the planted file-read reaches) is the VU3 scope.
            if _harness.search(line) or (_svc_src.search(line) and re.match(r"^[^:]+:\d+:\s*(#|//|\*|/\*|<!--)", line)):
                harness_hits.append(line); continue
            leak_hits += 1
            if leak_hits <= 12:
                print("    " + line.replace(str(root) + "/", ""))
        if harness_hits:
            print(f"    ({len(harness_hits)} hit(s) in HARNESS-ONLY source -- advisory, not a VU3 fail unless that source is")
            print("     agent-readable; confirm no route serves it and the planted file-read cannot reach that container):")
            for line in harness_hits[:6]:
                print("      " + line.replace(str(root) + "/", ""))
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

    # ---- GATEWAY BARE-SECRET CREDIT (learn-then-reflect forge, EV2 + VU5 + VU2) — calibration case 10 ----
    print("\n## GATEWAY BARE-SECRET CREDIT (learn-then-reflect) — EV2 + VU5 + VU2 forge (calibration case 10)")
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
    print("  NOTE (EV2 + VU5 + VU2, learn-then-reflect): a credit of the form `<secret_var> in <response body>` gated only")
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
    # v1.3 (massassign): the scored value / marker can be re-minted in ANY boot path (entrypoint-wrapper.sh,
    # boot.sh, start*.sh, an inline `python3 -c`, a Dockerfile CMD) -- not only setup.py.
    _remint_other = []
    _rx_mint = re.compile(r"(marker|scored\w*|sign[-_ ]?off\w*|canary\w*|FLAG\w*|sync_token|real_token)[^\n]{0,80}"
                          r"(secrets\.|token_hex|token_bytes|os\.urandom|/dev/urandom|openssl rand|uuidgen|\$RANDOM)", re.I)
    for p in list(root.glob("environment/**/*.sh")) + [q for q in root.glob("environment/**/*.py") if q.name != "setup.py"]:
        if "vendor-wheels" in p.parts:
            continue
        for i, ln in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if _rx_mint.search(ln) and not ln.lstrip().startswith("#"):
                _remint_other.append(f"{p.relative_to(root).as_posix()}:{i}: {ln.strip()[:110]}")
    if _remint_other:
        print(f"  secret/marker minted in non-setup.py boot paths ({len(_remint_other)}) -- for EACH: does it run on EVERY start,")
        print("  to a NON-volume path, while another service caches the old value? (= restart desync, EN4 [Reproducibility]):")
        for x in _remint_other[:8]:
            print("    " + x)
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
    _nprf = getattr(_QC, "npm_license_report", None) if _QC is not None else None
    _npr = None
    if _nprf is not None:
        try:
            _npr = _nprf(_QCX)  # V13e (#9/#25): qc's npm license + dangling-pointer check
        except Exception as _e:
            print(f"  (qc npm_license_report raised {_e}; local scan used)")
    if _npr is not None:
        for _r in _npr:
            _k, _t = _r.get("kind"), _r.get("tier")
            if _k == "dangling":
                nref += f"    !! CANDIDATE EN4 [Tier A] NOTICE provenance pointer to a file that does not ship: {_r.get('notice_where')} -> {_r.get('claim')!r}\n"
            elif _t == "A":
                nref += (f"    !! CANDIDATE EN4 [Tier A] npm license misstated: {_r.get('pkg')}@{_r.get('version')} ({_r.get('license')}) vs "
                         f"{_r.get('claim')!r} ({_r.get('notice_where')}; {_r.get('lock_where')})\n")
            elif _t == "probable":
                nref += (f"    !! MUST-CONFIRM EN4 npm: {_r.get('pkg')}@{_r.get('version')} ({_r.get('license')}"
                         f"{', optional' if _r.get('optional') else ''}{', dev' if _r.get('dev') else ''}) would contradict "
                         f"{_r.get('claim')!r} ({_r.get('notice_where')}; {_r.get('lock_where')}) if installed\n")
            else:
                nref += f"    (note) {_k}: {_r.get('lock_where') or _r.get('notice_where')} {_r.get('claim') or ''}\n"
    for nf in ([top_notice] + [p for p in root.glob("environment/**/NOTICE*") if p != top_notice]) if _npr is None else ():
        if nf.exists():
            nt = nf.read_text(errors="replace")
            for m in re.finditer(r"(lockfile|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|workspace lockfile|bundled package\.json)", nt, re.I):
                claim = m.group(1).lower()
                fname = {"lockfile": "package-lock.json", "workspace lockfile": "package-lock.json",
                         "bundled package.json": "package.json"}.get(claim, claim)
                exists = bool(list(root.glob(f"environment/**/{fname}")))
                nref += f"    {nf.relative_to(root)} defers provenance to '{m.group(1)}' — that file ships: {exists}\n"
    if nref:
        print("  NOTICE provenance / npm license findings:" if _npr is not None else "  NOTICE provenance deferral to a lockfile/manifest:")
        print(nref, end="")
    print("  DIVERGENCE NOTE: calibration case 5 FAILED EN4 on (a) restart re-mint AND (b) unlicensed vendored")
    print("  wheels + a NOTICE deferring to a non-shipped lockfile. BUT case 1 (same restart re-mint) and case 4")
    print("  (same 52 unlicensed agent wheels) both PASSED EN4. LADDER (SKILL.md rule 5, v14): a static restart re-mint is")
    print("  Tier B (5 + MUST-FIX); UNDOCUMENTED wheels are now Tier A (item 34: every NOTICE gap is a fail), as are a")
    print("  DEMONSTRATED desync, a NOTICE that MISSTATES a wheel's license and a WRONG/MISSING base-image or app license.")

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
        reasoning_re = re.compile(r"reasoning_content|['\"]message['\"]|json\.dumps\(\s*(?:s|step)\b|str\(\s*(?:s|step)\s*\)")  # v1.3f: credit from the agent's THINKING / whole-step dump -> Tier A
        all_lines = sct.splitlines()
        _RBX = getattr(_QC, "_RB1Expr", None) if _QC is not None else None
        _rbx = None
        if _RBX is not None:
            try:
                _rbx = _RBX(sct)  # V13e (#6): qc's ast reading of each stage value (helpers / assignments resolved)
            except Exception:
                _rbx = None
        for sid in (tf_ids + out_ids) if _rbx is not None else ():
            kind = "technique_fidelity" if sid in tf_ids else "outcome"
            for _ln, _ex in _rbx.exprs_for(sid):
                _ex1 = re.sub(r"\s+", " ", str(_ex)).strip()
                if not _ex1 or re.fullmatch(r"[0-9.]+|False|True|None", _ex1) or _ex1.startswith("{"):
                    continue  # weight/meta dicts and constant no-evidence defaults
                print(f"    {sid} [{kind}]: check.py:{_ln}: {_ex1[:120]}")
                try:
                    _sp, _gt = _rbx.credits(_ex1), _rbx.requires_gate(_ex1)
                except Exception as _e:
                    print(f"       (qc _RB1Expr could not read it: {_e}) -- read by hand")
                    continue
                if _sp:
                    print(f"       !! {kind} stage can be credited from keystroke/observation/trajectory TEXT alone -> spoofable "
                          "by narration (qc _RB1Expr; rubric says this stage OBSERVES a real request/response or defers to behavior) "
                          + ("[Tier A: outcome stage]" if kind == "outcome" else ("[Tier A (v1.3f): credited from reasoning_content / whole-step serialization -- agent credited for THINKING, never executing]" if reasoning_re.search(_ex1) else "[Tier B (i) on technique_fidelity: 5 + MUST-FIX, rule 5]")))
                elif _gt:
                    print("       ok: requires the behavior gate (reward/behavior artifact, directly or via a helper/variable) — not spoofable")
                else:
                    print("       (qc: not narration-only and not behavior-gated -- read its predicate by hand)")
                others = [o for o in (tf_ids + out_ids + ["s1", "s2", "s3", "s4", "s5", "s6"]) if o != sid]
                xref = sorted(o for o in set(others) if re.search(rf'\b{re.escape(o)}\b', _ex1))
                if xref:
                    print(f"       !! references other stage(s) {xref} in its predicate -> possible prerequisite-collapse")
        for sid in (tf_ids + out_ids) if _rbx is None else ():
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
                    blocks = []  # V13e (#6): the ASSIGNMENT EXPRESSION only (no look-back into unrelated lines)
                    for i, l in enumerate(all_lines):
                        _am = re.search(rf'(^|\s){re.escape(rhs)}\s*=(?!=)(.*)$', l)
                        if _am:
                            blocks.append(_am.group(2))
                    resolved = " || ".join(b.strip().replace("\n", " ; ") for b in blocks)
                    scan_text = h + " || " + resolved
                spoof = bool(narr_re.search(scan_text))
                # a decisive stage deferring ONLY to the behavior gate (`passed`) is CORRECT, not spoofable
                behavior_bound = bool(re.search(r'\bpassed\b|_behavior|reward\.json|behavior', scan_text)) and not spoof
                print(f"    {sid} [{kind}]: {h.strip()[:120]}")
                if var_m and resolved:
                    print(f"       via variable `{rhs}` -> {resolved[:160]}")
                if spoof:
                    print(f"       !! {kind} stage credited from keystroke/observation/trajectory TEXT -> spoofable "
                          "by narration (rubric says this stage OBSERVES a real request/response or defers to behavior)"
                          + ("  [Tier A: outcome stage]" if kind == "outcome" else ("  [Tier A (v1.3f): reasoning_content / whole-step serialization credit]" if reasoning_re.search(scan_text) else "  [Tier B: 5 + MUST-FIX]")))
                elif behavior_bound:
                    print("       ok: defers to the behavior gate (`passed`) — not spoofable")
                # prerequisite-collapse / cross-stage back-credit: RHS references ANOTHER stage's var
                others = [o for o in (tf_ids + out_ids + ["s1", "s2", "s3", "s4", "s5", "s6"]) if o != sid]
                xref = sorted(o for o in set(others) if re.search(rf'\b{o}\b', rhs))
                if xref:
                    print(f"       !! references other stage(s) {xref} in its predicate -> possible prerequisite-collapse")
        # gating check: does the staged result feed the OFFICIAL reward? (it must NOT)
        gate_txt = ""
        for gp in (root / "tests" / "test.sh", root / "tests" / "reward.toml"):
            if gp.exists():
                gate_txt += gp.read_text(errors="replace")
        # v1.3: judge GATING by DATA FLOW -- does a staged result reach reward.json/reward.txt? The old
        # `re.search("stages", ...)` printed YES whenever test.sh merely RAN the stages (deterministic false positive).
        _gate_hits = []
        _OFF = re.compile(r"(\$\{?OUT\}?|/logs/verifier/reward\.(?:json|txt)\b)")
        _STG = re.compile(r"(stages/[\w./-]*reward[\w.-]*\.json|stages_reward|run_stages|tests/stages|\$\{?HERE\}?/stages|/stages\b)", re.I)
        _tsh = (root / "tests" / "test.sh").read_text(errors="replace") if (root / "tests" / "test.sh").exists() else ""
        for _ln in re.sub(r"\\\n", " ", _tsh).splitlines():
            _s = _ln.strip()
            if not _s or _s.startswith("#") or not _STG.search(_s):
                continue
            _m = re.search(r"\b(cp|mv|install)\b\s+(?:-\S+\s+)*(\S+)\s+(\S+)", _s)
            _r = re.search(r">\s*[\"']?(\$\{?OUT\}?|/logs/verifier/reward\.(?:json|txt))", _s)
            if (_m and _STG.search(_m.group(2)) and _OFF.search(_m.group(3))) or (_r and _STG.search(_s[:_r.start()])) \
               or re.search(r"--output\s+[\"']?(\$\{?OUT\}?|/logs/verifier/reward\.json)", _s) or re.search(r"\btee\b[^|]*" + _OFF.pattern, _s):
                _gate_hits.append(_s[:110])
        _rt = (root / "tests" / "reward.toml").read_text(errors="replace") if (root / "tests" / "reward.toml").exists() else ""
        if re.search(r"stages", _rt, re.I):
            _gate_hits.append("tests/reward.toml references the staged rubric")
        _sgo = getattr(_QC, "_stages_gate_official_reward", None) if _QC is not None else None
        if _sgo is not None:  # V13e (#14): qc's data-flow test is authoritative; the scan above is the no-qc fallback
            _srcs = []
            _sdir = root / "tests" / "stages"
            for _p in sorted(list(_sdir.glob("*.py")) + list(_sdir.glob("*.sh"))):
                if _p.is_file() and not _p.is_symlink():
                    _srcs.append((str(_p.relative_to(root)), _p.read_text(errors="replace")))
            _srcs.append(("tests/stages/rubric.toml", srt))
            try:
                _gate_hits = list(_sgo(_tsh, _rt, _srcs))
            except Exception as _e:
                print(f"  (qc _stages_gate_official_reward raised {_e}; local scan used)")
        gates = bool(_gate_hits)
        print(f"  staged result feeds official reward.json/reward.txt (DATA FLOW): {'!! YES -> RB1 [Gating] [Tier A]: ' + str(_gate_hits[:2]) if gates else 'no (diagnostic/non-gating) -> ok'}")
        if not gates and _STG.search(_tsh):
            print("  (test.sh runs the staged rubric inline but its output never reaches the official reward -> non-gating;")
            print("   guidelines §5.5 prefers running it offline via run_stages.sh -- a flag, not a deduction)")
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
    print("  [Fail - Spoofable or Gating Rubric] pattern -- the rubric AND guidelines §5.5 both fail whole-trajectory /")
    print("  narration credit and prerequisite-collapse. calib1/2/3/7/8/9 share it yet PASSED RB1; calib5/6 and the")
    print("  dolibarr-traversal QC review FAILED on it. LADDER (SKILL.md rule 5): on technique_fidelity stages, and the")
    print("  {s: passed} collapse, it is Tier B on the QC record alone (5 + MUST-FIX: key each predicate on one step's own")
    print("  keystrokes anchored on the literal intended target / live token); on an OUTCOME-category stage, or when")
    print("  staged output reaches the official reward, it is Tier A.")
    print("  v1.3f: credit from reasoning_content, the agent message, or a whole-step json.dumps(step)/str(step)")
    print("  serialization is Tier A (gating) even on a technique_fidelity stage -- the agent is credited for THINKING.")

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
        _rjf = getattr(_QC, "report_judge_status", None) if _QC is not None else None
        _rjs = None
        if _rjf is not None:
            try:
                _rjs = _rjf(_QCX)
            except Exception as _e:
                print(f"  (qc report_judge_status raised {_e})")
        if _rjs and _rjs.get("present"):
            print(f"  report judge (qc): guard={_rjs.get('guard')}  fail_closed={_rjs.get('fail_closed')}  "
                  f"partial={_rjs.get('partial')}  evidence={list(_rjs.get('evidence') or [])[:4]}")
            if _rjs.get("guard") == "public":
                print("  !! CANDIDATE EN4 [Tier A] [Fail - Reproducibility] report-judge needs the public internet "
                      "(ANTHROPIC_BASE_URL assigned/exported/defaulted to anthropic.com, or a hardcoded endpoint)")
            elif _rjs.get("guard") == "none":
                print("  [MUST-FIX - skill extension] report judge has no ANTHROPIC_BASE_URL refusal guard "
                      "(no QC record; the extracted QC controls c6/c7/c9/c10 all carry one)")
        _fc = bool(_rjs and _rjs.get("fail_closed"))
        if _rjs is None and re.search(r'\[\s*!\s*-s\s', tt) and re.search(r'"reward"\s*:\s*0(\.0)?\b', tt):
            _fc = True  # no qc: a post-judge [ ! -s ] fallback writing reward 0 is fail-closed (policy 9)
        if has_ortrue and not has_if_judge and not _fc:
            print("  !! CANDIDATE EN4 [Tier B] [Fail - Reproducibility]: the report judge runs with `|| true` and is NOT wrapped")
            print("     in `if … then … else <overwrite RR_OUT to a fail>`, and RR_OUT is not re-initialized before it —")
            print("     a judge ERROR leaves report-rubric-result.json STALE (a prior reward:1/status:graded survives);")
            print("     skip/infra write reward:null, not fail-closed to 0. (Among calib1–6 only calib4 fails closed; calib8")
            print("     does too. calib1/11 passed EN4 with this pattern (calib5 has it but its EN4 fail cites other findings);")
            print("     QC record PASS 1/7/9/11, FAIL 6. Tier B (i) by SKILL.md rule 5: 5 + MUST-FIX.)")
        elif has_ortrue and _fc:
            print("  report judge `|| true` is followed by a fail-closed reward-0 write (e.g. post-judge `[ ! -s ]` -> reward 0;"
                  " policy 9) -> not the Tier B pattern")
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
    print("  calib6 was failed on it (case 5's EN4 fail cites wheels/lockfile/re-mint). LADDER (SKILL.md rule 5, v14):")
    print("  undocumented gateway deps are Tier A now (item 34); the report-judge `|| true`/null pattern stays Tier B")
    print("  (5 + MUST-FIX); a WRONG/MISSING base-image or app license stays Tier A.")

    # ---- EN4 WHEEL LICENSES (v1.3): per wheel, against the NOTICE section for its vendor-wheels dir (qc's code) ----
    print("\n## EN4 WHEEL LICENSES (vendored *.whl real license vs the NOTICE section for its vendor-wheels dir)")
    if _QC is None:
        print("  (qc_selfcheck not loadable -- read each vendor-wheels/*.whl METADATA against NOTICE by hand)")
    else:
        _n, _mis, _und, _has = _QC.wheel_license_report(_QCX)
        if not _n:
            print("  (no vendor-wheels/*.whl found)")
        elif not _has:
            print(f"  !! CANDIDATE EN4 [Tier A - undocumented]: {_n} vendored wheel(s) shipped but NOTICE has NO vendored-wheel entry")
            print("     (v14, item 34: list each wheel's license from its METADATA -- an undocumented wheel is a fail, not 5 + MUST-FIX)")
        else:
            if _mis:
                print(f"  !! CANDIDATE EN4 [Fail - Provenance/Licensing] [Tier A - MISSTATED]: {len(_mis)} wheel(s):")
                for x in _mis[:12]:
                    print("      " + x)
            if _und:
                print(f"  !! CANDIDATE EN4 [Tier A - license undocumented for these wheels]: {_und[:10]}")
            if not _mis and not _und:
                print(f"  {_n} wheel(s) scanned; every notable (MPL/PSF/CNRI/GPL/LGPL/AGPL/EPL/CDDL) wheel license is stated -> ok")
        print("  NOTE: a wheel is judged against the NOTICE section for ITS vendor-wheels dir; another component's line (glpi-idor:")
        print("  the gateway's own certifi, MPL-2.0) does not license the agent wheels. A blanket 'MIT/Apache/BSD' over")
        print("  MPL/CNRI/PSF wheels is a MISSTATEMENT (Tier A; the dolibarr-traversal QC fail).")

    # ---- F3 FLAG-FORMAT CROSS-TIER (qc's shared regex) ----
    print("\n## F3 FLAG-FORMAT CROSS-TIER (marker format present + identical in ALL four tiers)")
    if _QC is None:
        print("  (qc_selfcheck not loadable -- compare the marker-format sentence across the four tiers by eye)")
    else:
        _tiers = _QCX.instr_tiers()
        _have, _miss, _bound = _QC.f3_format_tiers(_tiers)
        _said = {n: sorted({m.group(0) for m in _QC.F3_FORMAT_RE.finditer(_tiers.get(n) or "")})[:3] for n in _have}
        if _have and _miss:
            print("  !! CANDIDATE F3 [Fail - Flag Consistency]%s: marker format stated in %s but ABSENT in %s" % (
                " [Tier A]" if _bound else " (confirm the phrase describes the MARKER)", _have, _miss))
            print("      stated: %s" % _said)
            print("      Tier A once the phrase describes the marker (shares a line with sign-off/marker/flag/submission wording")
            print("      here: %s); silent in all four tiers = identical = pass. (dolibarr-traversal QC fail)" % _bound)
        elif not _have:
            print("  no explicit marker-format token in ANY tier -> all four are identically silent = consistent (QC-PASS cases 6/7/9/10)")
        else:
            print("  marker format token present in all four tiers: %s -> confirm identical by eye" % _said)

    # ---- EN4 IP-ACL vs SUBNET (V13 blind-spot #4) ----
    print("\n## EN4 IP-ACL vs SUBNET (hardcoded client-IP allowlist vs compose-assigned subnet)")
    _ipf = getattr(_QC, "ip_acl_candidates", None) if _QC is not None else None
    _ipr = None
    if _ipf is not None:
        try:
            _ipr = _ipf(_QCX)  # V13e (#34/#38): qc's allow-context scan; the local heuristic below is the no-qc fallback
        except Exception as _e:
            print(f"  (qc ip_acl_candidates raised {_e}; local heuristic used)")
    if _ipr is not None:
        for _r in _ipr:
            if _r.get("tier") == "A":
                print(f"  !! CANDIDATE EN4 [Tier A] allowlist excludes the pinned Docker subnet: {_r.get('where')} "
                      f"{_r.get('cidrs')} vs pinned {_r.get('pinned_subnets')}")
            else:
                print(f"  !! MUST-CONFIRM client-IP allowlist vs the Docker-allocated subnet (fails only if shown to fall outside): "
                      f"{_r.get('where')} {_r.get('cidrs')}")
        if not _ipr:
            print("  no hardcoded client-IP allowlist found (qc ip_acl_candidates) -> ok (or the ACL lives in app config; confirm by eye)")
    _acl = []
    for _f in (root.glob("environment/**/*") if _ipr is None else ()):
        if _f.is_file() and _f.suffix in (".sh", ".py"):
            _t = _f.read_text(errors="replace")
            for _ln in _t.splitlines():
                # an ALLOWLIST (who may connect) -- never a private-range BLOCKLIST (what an SSRF fix must refuse)
                if re.search(r"(?i)block|deny|forbid|reject|is_private|private_(?:range|net)|ssrf|disallow", _ln):
                    continue
                if not re.search(r"(?i)allow|permit|trusted|whitelist|ipv4[_-]?range|api[_-]?ip|client[_-]?ip|remote_addr", _ln):
                    continue
                for _m in re.finditer(r"\b(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b", _ln):
                    if not _m.group(0).endswith("/8"):
                        _acl.append((_f.relative_to(root).as_posix(), _m.group(0)))
            if re.search(r"(?i)ipv4[_-]?range|ERROR_NOT_ALLOWED_IP|allowed[_-]?ip", _t):
                _acl.append((_f.relative_to(root).as_posix(), "numeric ipv4_range / allowed-ip logic"))
    _comp = root / "environment" / "docker-compose.yaml"
    if _ipr is not None:
        _comp = root / "environment" / "__qc_handled__"
    _fixed_subnet = bool(re.search(r"(?m)^\s*subnet:", _comp.read_text(errors="replace"))) if _comp.exists() else False
    if _acl:
        print("  !! MUST-CONFIRM EN4: client-IP allowlist(s) found (local heuristic, qc not loaded); compose has fixed subnet: %s" % _fixed_subnet)
        for _rel, _h in _acl[:10]:
            print("      %s: %s" % (_rel, _h))
        if not _fixed_subnet:
            print("      backend has NO fixed `subnet:` -> Docker assigns per boot; if it lands OUTSIDE the allowlist")
            print("      the stage is unwinnable (glpi EN4). Confirm the allowlist covers ALL RFC1918 (10/8+172.16/12+192.168/16).")
    elif _ipr is None:
        print("  no hardcoded client-IP allowlist found -> ok (or the ACL lives in app config; confirm by eye)")

    # ---- VU3 TIER MONOTONICITY (v1.3f): L2 must KEEP every fact L1 gave ----
    print("\n## VU3 TIER MONOTONICITY (v1.3f) — L1 sentences that look DROPPED from L2 (non-monotonic candidate)")
    def _sents(p):
        if not p.exists():
            return []
        t = re.sub(r"\s+", " ", p.read_text(errors="replace"))
        return [s.strip() for s in re.split(r"(?<=[.!?])\s+", t) if len(s.strip()) >= 25]
    def _norm(s):
        return re.sub(r"[^a-z0-9 ]", " ", s.lower())
    _l1s = _sents(root / "instruction_L1.md")
    _l2p = root / "instruction_L2.md"
    _l2n = _norm(re.sub(r"\s+", " ", _l2p.read_text(errors="replace"))) if _l2p.exists() else ""
    _dropped = []
    if _l1s and _l2n:
        for s in _l1s:
            words = [w for w in _norm(s).split() if len(w) > 3]
            if not words:
                continue
            if sum(1 for w in words if w in _l2n) / len(words) < 0.6:  # most content words absent from L2
                _dropped.append(s[:140])
    if _dropped:
        print(f"  !! {len(_dropped)} L1 sentence(s) look DROPPED from L2 -> VU3 [Fail - Non-Monotonic Hint Progression] candidate (v1.3f);")
        print("     a reworded superset is fine (confirm by eye); a genuinely dropped fact fails ('a higher tier drops a fact a lower tier gave').")
        for s in _dropped[:6]:
            print(f"       L1-only: {s}")
    elif _l1s and _l2n:
        print(f"  ok: all {len(_l1s)} L1 sentences have strong word-overlap in L2 (superset holds; spot-check by eye)")
    else:
        print("  (instruction_L1.md or instruction_L2.md missing -- read the tiers by hand)")

    # ---- VU2 PARSER-DIFFERENTIAL (V13 blind-spot #2): gateway guard decode layer vs backend ----
    print("\n## VU2 PARSER-DIFFERENTIAL (gateway guard decode layer vs backend decode)")
    _gw = root / "environment" / "gateway" / "app.py"
    if _gw.exists():
        _g = _gw.read_text(errors="replace")
        _guard = sorted(set(re.findall(r"(?i)unquote|percent|urldecode|\.lower\(\)|b64|url(?:lib)?\.parse", _g)))
        _fwd = bool(re.search(r"(?i)requests?\.(get|post|request)\(|proxy|forward", _g))
        _json = bool(re.search(r"(?i)json_decode|json\.loads|get_json|APIRest|based_config", _g))
        print("  gateway guard decode ops: %s ; forwards to backend: %s ; json-decode present: %s" % (_guard or "none", _fwd, _json))
        if _fwd and not any("json" in _d.lower() for _d in _guard):
            print("  red-team prompt (NOT a finding -- fires broadly): guard inspects raw/percent-decoded text but the backend")
            print("     may json_decode (expands \\u escapes) AFTER the guard -> a JSON \\u-escaped payload can pass a")
            print("     string guard and inject at the backend (glpi VU2). Test JSON \\u + multipart, not just percent-")
            print("     encoding; a string guard is NOT genuine VU2 resistance -- root-cause the sink in the app.")
    else:
        print("  (no environment/gateway/app.py)")

    # ================================================================ v1.3 FIELD-LESSON FACT SECTIONS
    _passk = root / "trajectories" / "pass@k"
    _trials = [Path(r[0]) for r in _QC.passk_trials(_QCX)] if _QC is not None else \
        (sorted({p.parent.parent for p in _passk.glob("**/agent/trajectory.json")}) if _passk.exists() else [])
    def _trial_text(tr):
        # the pane, else trajectory.json DECODED to observation text (qc's reader: bounded, observation-only)
        if _QC is not None:
            src, txt = _QC._trial_obs_text(_QCX, str(tr))
            return txt, os.path.relpath(src, str(tr))
        for rel in ("agent/terminus_2.pane", "agent/trajectory.json"):
            f = tr / rel
            if f.is_file() and f.stat().st_size < 64 * 1024 * 1024:
                return f.read_text(errors="replace"), rel
        return "", ""
    def _behavior(tr):
        f = tr / "verifier" / "reward.json"
        try:
            if f.is_file() and f.stat().st_size < 1024 * 1024:
                d = json.loads(f.read_text())
                return d.get("behavior", d.get("reward"))
        except Exception:
            pass
        return None

    # ---- EN2 RUNTIME EGRESS (glpi-idor): success evidence only -- qc's scanner, so both tools agree ----
    print("\n## EN2 RUNTIME EGRESS + SANDBOX HOST ESCAPE — did any pass@k trial reach the external internet or 10.0.2.2:8080?")
    if _QC is not None and getattr(_QCX, "mode", "post") == "pre":
        print("  DEFERRED (pre-pass@k): grep the trials after the pass@5 run -- external SUCCESS evidence and any contact with")
        print("  10.0.2.2:8080 / /internal/genai/sandbox (the sandbox host control API; report a contact to the platform owners)")
    if _QC is None:
        print("  (qc_selfcheck not loadable -- grep every pass@k pane for SUCCESSFUL external fetches and 10.0.2.2 by hand)")
    else:
        _esc_shown, _esc_tried = _QC._host_escape_hits(_QCX)
        for x in _esc_shown:
            print(f"  !! HOST ESCAPE {x} -> EN2 [Fail - Isolation / Shortcut Route] [Tier C - demonstrated]; EV2/VU5 if it reached the value")
        for x in _esc_tried:
            print(f"  !! sandbox-host mention {x} -> read it; a response is an EN2 fail")
        _sure, _prob = _QC._runtime_egress_hits(_QCX)
        for x in _sure:
            print(f"  !! {x} -> EN2 [Fail - Isolation / Shortcut Route] (agent has external internet) [Tier C - demonstrated]")
        for x in _prob:
            print(f"  !! {x} -> PROBABLE: read it; if it succeeded, EN2 [Fail - Isolation / Shortcut Route]")
        if _trials and not _sure and not _prob:
            print(f"  no external-success signature in {len(_trials)} trial(s) (a 'could not resolve' line elsewhere does NOT prove isolation)")
    print("  (only the agent's OWN fetch counts -- not a parameter value, header, request body, loop value, a link echoed in")
    print("   an app response, or a transcript the agent cats; internal compose names/aliases with public TLDs are excluded)")
    try:
        import yaml as _y
        _cd = _y.safe_load((root / "environment" / "docker-compose.yaml").read_text()) or {}
        _nets = _cd.get("networks") or {}
        _main = _cd.get("services", {}).get("main") or {}
        _mn = _main.get("networks")
        if _mn is None:
            print("  main has no networks: key -> on `default`; the platform's egress sidecar enforces [agent] allowed_hosts")
        else:
            _mn = list(_mn) if isinstance(_mn, (list, dict)) else []
            print(f"  !! main declares networks: {_mn} -> EN2 fail: REMOVE main's networks: key (guidelines §1.4). The platform")
            print("     fails `docker compose up` ('mutually exclusive network_mode and networks'), and Harbor 0.18/0.23's sidecar")
            print("     skips such a main, so it has NAT internet on a non-internal bridge. (v13's 'set internal: true on main's")
            print("     network' advice is retired: it breaks boot under the allowlist.)")
    except Exception as _e:
        print(f"  (compose network topology not parsed: {_e}; read docker-compose.yaml by eye)")

    # ---- EN4 IP-ACL DEMONSTRATED BY THE TRIALS (v1.3f) ----
    print("\n## EN4 IP-ACL DEMONSTRATED BY TRIALS (v1.3f) — did the shipped pass@k trials hit the allowlist rejection?")
    _acl_err = re.compile(r"NOT_ALLOWED_IP|ERROR_NOT_ALLOWED|active API client|isn't an active API client", re.I)
    _acl_hits = []
    for tr in _trials:
        txt, src = _trial_text(tr)
        if txt and _acl_err.search(txt):
            _acl_hits.append((os.path.basename(str(tr)), src))
    if _acl_hits:
        print(f"  !! {len(_acl_hits)} trial(s) print the client-IP allowlist's own rejection -> the reproducibility failure is")
        print("     DEMONSTRATED in the shipped bundle -> EN4 [Fail - Reproducibility] [Tier A - demonstrated] (v1.3f), NOT MUST-CONFIRM.")
        print("     (The IP-ACL vs Docker-subnet nondeterminism actually broke the intended chain in these trials -- SKILL.md Step 1.5 #12.)")
        for _n, _s in _acl_hits[:6]:
            print(f"       {_n}: {_s}")
    elif _trials:
        print(f"  no allowlist-rejection signature in {len(_trials)} trial(s) (an IP-ACL, if present, stays MUST-CONFIRM per #12, not demonstrated)")
    else:
        print("  (no pass@k trials read)")

    # ---- CVE IDS TO VERIFY (massassign: a Gitea CVE sat in 12 places of a Dolibarr task) ----
    print("\n## CVE IDs NAMED BY THE BUNDLE — verify EACH at https://cveawg.mitre.org/api/cve/<ID> (vendor/product/flaw must match)")
    _cves = {}
    for p in root.rglob("*"):
        if not p.is_file() or "vendor-wheels" in p.parts or "trajectories" in p.parts or p.suffix in (".whl", ".png", ".jpg", ".gz", ".zip"):
            continue
        try:
            _tx = p.read_text(errors="replace")
        except Exception:
            continue
        for m in re.finditer(r"CVE-\d{4}-\d{4,7}", _tx):
            _cves.setdefault(m.group(0), set()).add(p.relative_to(root).as_posix())
    if not _cves:
        print("  (no CVE ID named)")
    for cid, files in sorted(_cves.items()):
        print(f"  {cid}  in {sorted(files)[:5]}{' ...' if len(files) > 5 else ''}")
    if _cves:
        print(f"  task.toml says cwe={grab('cwe')}, kind={grab('vulnerability_kind')} -> a CVE for ANOTHER product/flaw is a factual error:")
        print("  a wrong CVE ID is a MUST-FIX; it is a VU3 fail only if L2's class statement or a reproduction step rests on it.")
        print("  A RESERVED or unverifiable ID is a MUST-FIX, and MUST-CONFIRM when it cannot be verified (never assume it is right).")
        print("  v14 (item 35): every CVE for the pinned version must also be in unintended_findings.json with how it was closed")
        print("  (guidelines §2.6) -- qc GL-cve-ledger fails a named CVE that is missing there.")

    # ---- STOCK UPSTREAM APP + VERSION (glpi-idor: live upstream CVEs reached the secret) ----
    print("\n## STOCK UPSTREAM APP + VERSION — enumerate its known CVEs before passing VU5 / VU2 / EV2")
    _APPS = r"dolibarr|glpi|gitea|gogs|wordpress|drupal|joomla|nextcloud|owncloud|mediawiki|moodle|magento|prestashop|opencart|" \
            r"mantis|redmine|odoo|jenkins|grafana|gitlab|phpmyadmin|roundcube|limesurvey|osticket|matomo|suitecrm|httpd|tomcat|keycloak|strapi|ghost"
    _found = []
    for p in list(root.glob("environment/**/Dockerfile")) + [root / "environment" / "docker-compose.yaml"]:
        if not p.exists():
            continue
        for i, ln in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if re.search(r"(?i)\b(" + _APPS + r")\b", ln) and re.search(r"\d+\.\d+(?:\.\d+)?", ln) and \
               re.search(r"(?i)^\s*(FROM|ARG|ENV|RUN|image:|-?\s*image:)|\.(tgz|tar\.gz|zip)|releases/download", ln):
                _found.append(f"{p.relative_to(root).as_posix()}:{i}: {ln.strip()[:120]}")
    if not _found:
        print("  (no stock upstream app/version line detected -- a first-party app; skip the upstream-CVE enumeration)")
    for x in _found[:8]:
        print("  " + x)
    if _found:
        print("  -> For the shipped product+version: list its CVEs (NVD keywordSearch=<product>, MITRE) up to the first fixed release;")
        print("     for each ADJACENT CVE (Step 1.5 #5; unrelated low-privilege XSS/CSRF/DoS are out of scope), show patched / dead-ended / unreachable-by-the-foothold. One the agent can reach that yields the secret OR app")
        print("     privileges that let it read the credential = VU5 [Decoy Reaches Scored Secret] / [Fake or Stubbed Decoy], VU2, and EV2")
        print("     if the credit can then be satisfied. Cannot enumerate (offline)? VU5/VU2/EV2 are UNVERIFIED -> MUST-CONFIRM, never a default 5.")

    # ---- DIFFICULTY_EXPLANATION CLAIMS (glpi-idor VU3: 'the one restricted matter' vs two seeded) ----
    print("\n## DIFFICULTY_EXPLANATION CLAIMS — verify EVERY exclusivity/quantity claim against the code + seed (VU3 per-claim)")
    _de = re.search(r'difficulty_explanation\s*=\s*"""(.*?)"""', toml, re.S) or re.search(r'difficulty_explanation\s*=\s*"([^"\n]*)"', toml)
    if not _de:
        print("  (difficulty_explanation not found in task.toml)")
    else:
        _claim_rx = re.compile(r"(?i)\b(only|exactly|single|sole|solely|never|cannot|can't|not by|no other|indistinguishable|identical|"
                               r"the one|one restricted|unless|neither|both|two|three|four|five|six)\b|\b\d+\b")
        _sents = [s.strip() for s in re.split(r"(?<=[.;])\s+", re.sub(r"\s+", " ", _de.group(1))) if s.strip()]
        _claims = [s for s in _sents if _claim_rx.search(s)]
        for i, s in enumerate(_claims[:15], 1):
            print(f"  [{i}] {s[:220]}")
        print(f"  ({len(_claims)} claim sentence(s)) -> for each, cite the file:line that proves or disproves it; ANY false step, count,")
        print("  endpoint or 'only/never' claim that the reproduction depends on = VU3 [Fail - Inconsistent Difficulty Explanation].")

    # ---- CROSS-DIMENSION EVIDENCE (glpi-idor: an off-path trial noted under EV5 never reached the VU/EV auditors) ----
    print("\n## CROSS-DIMENSION EVIDENCE per trial — route every hit to VU5 / EV2 / VU2 / EN2 in the integration pass (Step 6.9)")
    _pref = set()
    for rel in ("solution/solve.sh", "solution/solve.py", "unintended_findings.json"):
        f = root / rel
        if f.exists():
            for m in re.finditer(r"([a-z][a-z0-9]*(?:[-_][a-z0-9]+)*[-_])\[0-9a-f\]", f.read_text(errors="replace")):
                _pref.add(m.group(1))
    # EXECUTION evidence (output only an achieved foothold produces) vs MENTIONS (an agent merely reasoning about
    # exploits -- present in QC-PASS bundles too, e.g. calibration case 7). Only execution evidence is a lead.
    _esc = re.compile(r"(?im)uid=\d+\((?:www-data|apache|nginx|root|http)\)|^(?:www-data|apache|nginx|root)@[\w.-]+:[^\n]*[$#]|"
                      r"glpwnme|msfconsole|meterpreter|Command shell session \d+ opened|webshell[^\n]{0,40}(?:uploaded|written|created)")
    _ment = re.compile(r"(?i)\bRCE\b|\bpoc\b|exploit-?db|searchsploit|privilege escalat|reverse shell|web ?shell|super-?admin")
    print(f"  credential prefix(es) from the solve/unintended_findings: {sorted(_pref) or '(none found)'}")
    print("  trial                         behavior  cred-hits  48hex-hits  EXECUTION-evidence (lead)            mentions")
    for tr in _trials:
        txt, _ = _trial_text(tr)
        ch = sum(len(re.findall(re.escape(px) + r"[0-9a-f]{8,}", txt)) for px in _pref)
        hx = len(re.findall(r"(?<![0-9a-f])[0-9a-f]{48}(?![0-9a-f])", txt))
        es = sorted({m.group(0).strip()[:28] for m in _esc.finditer(txt)})[:4]
        mn = len(_ment.findall(txt))
        print(f"  {tr.name[:30]:30s}  {str(_behavior(tr)):8s}  {ch:9d}  {hx:10d}  {str(es or '-'):35s}  {mn}")
    if form:
        _mfr = str(_fk.get("model_failure_reason") or "") if "_fk" in dir() else ""
        _off = sorted({m.group(0).lower() for m in re.finditer(r"(?i)\bRCE\b|exploit|CVE-\d{4}|admin|escalat|another (?:path|route)|bypass|off-path|decoy", _mfr)})
        if _off:
            print(f"  form model_failure_reason mentions {_off} -> read it: a described off-path success is VU5/EV2/VU2 evidence")
    print("  EXECUTION evidence in ANY trial (a web-server/root shell, an exploit framework session) means an undesigned path ran:")
    print("  read that trial before scoring VU5/EV2/VU2/EN2. Mentions alone are reasoning noise (QC-PASS case 7 has them too).")
    print("  A behavior-0 trial that shows the credential or a 48-hex value, or execution evidence, is NOT proof the decoys held --")
    print("  'behavior 0/5' counts only CREDITED solves. Read those trials before scoring VU5/EV2/VU2.")

    print("\n  Reminder: exactly ONE body-spread should exist (the intended sink). Secret/seed access should")
    print("  be the single intended disclosure route. File reads must use hardcoded paths. Any other hit is a finding.")

if __name__ == "__main__":
    main()
