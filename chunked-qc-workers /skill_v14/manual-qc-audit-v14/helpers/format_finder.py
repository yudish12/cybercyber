#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
format_finder.py  --  static FINDER for the FORMAT group (F1-F5).

Mostly mechanical (presence/parse/exec/consistency); the reader confirms the few judgment
bits (F3 prefix-implies-class, F4 metadata-vs-solve alignment, F5 narration location).

  F1 Structure & Artifacts   [Fail - Required Structure]
  F2 Compose Contract        [Fail - ... main service]
  F3 Flag/Marker Format      [Fail - Flag Consistency] / [Fail - Prefix Vulnerability Leakage]
  F4 Metadata Consistency    [Fail - ... CWE/kind]
  F5 Packaging Hygiene       [Fail - Packaging Hygiene]

trajectories/pass@k presence is DEFERRED (pre-pass@k) and noted, never failed here.

Usage:  python3 -I format_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import en4_finder  # reuse image collection for F5 mutable tags

_REQUIRED = [
    "task.toml", "instruction.md", "instruction_L0.md", "instruction_L1.md", "instruction_L2.md",
    "fresh_state.json", "environment/docker-compose.yaml", "environment/NOTICE.md",
    "solution/solve.sh", "tests/test.sh", "tests/isolation_test.sh",
]
_SCRIPTS = ["solution/solve.sh", "tests/test.sh", "tests/isolation_test.sh"]
_CLASS_WORDS = re.compile(r"sqli|sql|idor|lfi|rfi|ssrf|rce|xxe|csrf|xss|traversal|bfla|bola|"
                          r"inject|deserial|massassign|xss", re.I)


def _read(p):
    try:
        with io.open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _f1(task_dir):
    cands = []
    for rel in _REQUIRED:
        full = os.path.join(task_dir, rel)
        if not os.path.exists(full):
            cands.append({"file": rel, "why": "required file missing"}); continue
        if os.path.getsize(full) == 0:
            cands.append({"file": rel, "why": "required file empty"})
        # parse checks
        if rel.endswith(".json"):
            try:
                json.loads(_read(full))
            except Exception as e:
                cands.append({"file": rel, "why": f"invalid JSON: {e}"})
        if rel == "task.toml":
            try:
                import tomllib
            except Exception:
                tomllib = None
            if tomllib is not None:
                try:
                    tomllib.loads(_read(full))
                except Exception as e:
                    cands.append({"file": rel, "why": f"invalid TOML: {e}"})
            elif not re.search(r"(?m)^\s*\[task\]", _read(full)):
                cands.append({"file": rel, "why": "task.toml has no [task] table"})
    for rel in _SCRIPTS:
        full = os.path.join(task_dir, rel)
        if not os.path.exists(full):
            continue
        first = _read(full).splitlines()[:1]
        has_shebang = bool(first) and first[0].startswith("#!")
        has_exec = os.access(full, os.X_OK)
        if not (has_shebang or has_exec):
            cands.append({"file": rel, "why": "script has neither a shebang nor an executable bit"})
    return {"label": "[Fail - Required Structure]", "candidates": cands,
            "deferred": "trajectories/pass@k presence + >=3 non-errored trials is a pass@k check (DEFERRED)",
            "files_to_read": _REQUIRED}


def _service_block(text, name):
    m = re.search(r"(?m)^\s{2}" + re.escape(name) + r":\s*$", text)
    if not m:
        return ""
    rest = text[m.end():]
    # stop at the next service (2-space key) OR a top-level section (column-0 key)
    nxt = re.search(r"(?m)^(?:\S|\s{2}[A-Za-z0-9_-]+:\s*$)", rest)
    return rest[:nxt.start()] if nxt else rest


def _f2(task_dir):
    """Full F2 compose contract — calibrated to cyber_quality_check (6 fail-modes +
    subnet/IP literals), matching the Nov guidelines (timeout_sec=36000, cpus=2, no
    shorthand resources / networks: / static ports on main, allowlist not no-network)."""
    comp = os.path.join(task_dir, "environment", "docker-compose.yaml")
    if not os.path.exists(comp):
        comp = os.path.join(task_dir, "environment", "docker-compose.yml")
    text = _read(comp)
    toml = _read(os.path.join(task_dir, "task.toml"))
    cands = []
    if not text:
        return {"label": "[Fail - Compose Contract]", "candidates": [], "files_to_read": ["environment/docker-compose.yaml", "task.toml"]}
    services = re.findall(r"(?m)^\s{2}([A-Za-z0-9_-]+):\s*$", _service_block(text, "") or text)
    # service names: parse under services:
    svc_names = re.findall(r"(?m)^\s{2}([A-Za-z0-9_-]+):\s*$",
                           re.split(r"(?m)^(networks|volumes):", text)[0])
    if "main" not in svc_names:
        cands.append({"file": "environment/docker-compose.yaml", "why": "no service named exactly `main`", "label": "[Fail - No `main` Service]"})
    # static host ports
    if re.search(r"(?m)^\s*-?\s*[\"']?\d{2,5}:\d{2,5}", text) or re.search(r"ports:\s*\[?\s*[\"']?\d{2,5}:\d{2,5}", text):
        cands.append({"file": "environment/docker-compose.yaml", "why": "static host:container port mapping(s) present", "label": "[Fail - Static Ports/IPs]"})
    main_block = _service_block(text, "main")
    if main_block and re.search(r"(?m)^[ \t]+networks:", main_block):
        cands.append({"file": "environment/docker-compose.yaml", "why": "main declares its own `networks:` — conflicts with Harbor's egress sidecar network_mode", "label": "[Fail - Sidecar Network Conflict]"})
    if main_block and re.search(r"(?m)^[ \t]+(cpus|mem_limit|pids_limit):", main_block):
        cands.append({"file": "environment/docker-compose.yaml", "why": "main sets shorthand resource field(s) (cpus/mem_limit/pids_limit) — conflicts with Harbor's long-form override", "label": "[Fail - Compose Shorthand/Long-Form Resource Conflict]"})
    others = [s for s in svc_names if s != "main"]
    if re.search(r'network_mode\s*=\s*"no-network"', toml) and others:
        cands.append({"file": "task.toml", "why": "network_mode=\"no-network\" but other in-compose services exist — use allowlist", "label": "[Fail - No-Network Blocks In-Compose Target]"})
    m = re.search(r"(?s)\[agent\].*?timeout_sec\s*=\s*(\d+)", toml)
    if not m or int(m.group(1)) != 36000:
        cands.append({"file": "task.toml", "why": f"[agent].timeout_sec = {m.group(1) if m else 'MISSING'}, expected exactly 36000", "label": "[Fail - Missing/Wrong agent.timeout_sec]"})
    m = re.search(r"(?s)\[environment\].*?\bcpus\s*=\s*(\d+)", toml)
    if not m or int(m.group(1)) != 2:
        cands.append({"file": "task.toml", "why": f"[environment].cpus = {m.group(1) if m else 'MISSING'}, expected exactly 2", "label": "[Fail - Missing/Wrong environment.cpus]"})
    subnet = re.findall(r"(?i)(subnet|ipv4_address):\s*[\"']?(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)", text)
    review = [{"file": "environment/docker-compose.yaml", "why": f"pinned subnet/IP literal {s[1]} — reader confirms it doesn't trip Docker's pool", "label": "[Fail - Static Ports/IPs]"} for s in subnet]
    return {"label": "[Fail - Compose Contract]", "candidates": cands, "review": review,
            "files_to_read": ["environment/docker-compose.yaml", "task.toml"]}


def _markers(text):
    """Return list of (prefix, fmt) marker specs found in a tier."""
    out = []
    for m in re.finditer(r"\b([A-Z][A-Z0-9_]{1,20})\s*=\s*(\[[^\]\n]+\]\{?\d*\}?|[0-9a-fx\-]{6,})", text):
        out.append((m.group(1), m.group(2)))
    return out


def _f3(task_dir):
    cands = []
    tiers = {n: _read(os.path.join(task_dir, n))
             for n in ("instruction.md", "instruction_L0.md", "instruction_L1.md", "instruction_L2.md")}
    per_file = {n: _markers(t) for n, t in tiers.items() if t}
    # prefix names the class?
    for n, specs in per_file.items():
        for pref, fmt in specs:
            if _CLASS_WORDS.search(pref):
                cands.append({"file": n, "why": f"marker prefix {pref!r} names/implies the vulnerability class",
                              "label": "[Fail - Prefix Vulnerability Leakage]"})
    # format consistency: distinct format strings stated across tiers
    fmts = {fmt for specs in per_file.values() for (_p, fmt) in specs}
    if len(fmts) > 1:
        cands.append({"why": f"marker format differs across tiers: {sorted(fmts)}",
                      "label": "[Fail - Flag Consistency]"})
    return {"label": "[Fail - Flag Consistency] / [Fail - Prefix Vulnerability Leakage]",
            "candidates": cands,
            "files_to_read": ["instruction.md", "instruction_L0.md", "instruction_L1.md", "instruction_L2.md"]}


def _f4(task_dir):
    cands = []
    cwe, kind = en4_finder.parse_task_class(task_dir) if False else (None, None)
    text = _read(os.path.join(task_dir, "task.toml"))
    try:
        import tomllib
        data = tomllib.loads(text)
        task = data.get("task", data)
        cwe = str(task.get("cwe", "") or data.get("cwe", ""))
        kind = str(task.get("vulnerability_kind", "") or data.get("vulnerability_kind", ""))
    except Exception:
        cwe = (re.search(r'(?mi)^\s*cwe\s*=\s*["\']?([^"\'\n]+)', text) or [None, ""])
        cwe = cwe.group(1) if hasattr(cwe, "group") else ""
        kind = (re.search(r'(?mi)^\s*vulnerability_kind\s*=\s*["\']?([^"\'\n]+)', text))
        kind = kind.group(1) if kind else ""
    if not cwe:
        cands.append({"why": "task.toml has no `cwe`"})
    if not kind:
        cands.append({"why": "task.toml has no `vulnerability_kind`"})
    return {"label": "[Fail - Metadata Consistency]", "candidates": cands,
            "cwe": cwe, "vulnerability_kind": kind,
            "files_to_read": ["task.toml", "solution/solve.sh"],
            "note": "reader confirms cwe/kind/name/archive align with what solve.sh actually exploits."}


def _f5(task_dir):
    cands = []
    # mutable base tags (cross-ref EN4)
    for im in en4_finder.collect_images(task_dir):
        if not im["pinned"]:
            cands.append({"file": im["source"], "why": f"mutable base tag {im['ref']} (no digest pin)"})
    # [agent] user present + non-root
    text = _read(os.path.join(task_dir, "task.toml"))
    agent_user = None
    m = re.search(r"(?s)\[agent\].*?user\s*=\s*['\"]([^'\"]+)['\"]", text)
    if m:
        agent_user = m.group(1)
    if agent_user is None:
        cands.append({"file": "task.toml", "why": "no non-root [agent] user identity"})
    elif agent_user.strip().lower() == "root":
        cands.append({"file": "task.toml", "why": "[agent] user = 'root' (must be non-root)"})
    # fresh_state.json valid
    fs = os.path.join(task_dir, "fresh_state.json")
    if os.path.exists(fs):
        try:
            json.loads(_read(fs))
        except Exception as e:
            cands.append({"file": "fresh_state.json", "why": f"invalid JSON: {e}"})
    return {"label": "[Fail - Packaging Hygiene]", "candidates": cands,
            "files_to_read": ["task.toml", "fresh_state.json"],
            "note": "reader also checks exploit narration is not in the agent-readable tree."}


def find(task_dir):
    return {"task_dir": os.path.abspath(task_dir),
            "checks": {"f1_structure": _f1(task_dir), "f2_compose": _f2(task_dir),
                       "f3_flag": _f3(task_dir), "f4_metadata": _f4(task_dir),
                       "f5_packaging": _f5(task_dir)}}


def _summary(r):
    o = [f"FORMAT FINDER (F1-F5) — {r['task_dir']}"]
    labels = {"f1_structure": "F1", "f2_compose": "F2", "f3_flag": "F3",
              "f4_metadata": "F4", "f5_packaging": "F5"}
    for k, short in labels.items():
        c = r["checks"][k]["candidates"]
        o.append(f"  {short} {r['checks'][k]['label']}: {len(c)} candidate(s)")
        for x in c[:8]:
            o.append(f"     FAIL?  {x.get('file','-')}  — {x['why']}")
    o.append("  NOTE: finder checks mechanics. Reader confirms F3 class-implication, F4 solve alignment, F5 narration.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: format_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
