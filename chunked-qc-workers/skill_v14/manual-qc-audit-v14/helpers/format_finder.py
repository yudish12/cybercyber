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


def _f2(task_dir):
    comp = os.path.join(task_dir, "environment", "docker-compose.yaml")
    if not os.path.exists(comp):
        comp = os.path.join(task_dir, "environment", "docker-compose.yml")
    text = _read(comp)
    cands = []
    has_services = re.search(r"(?m)^services:\s*$", text)
    has_main = re.search(r"(?m)^\s{2,}main:\s*$", text)
    if text and not has_main:
        cands.append({"file": "environment/docker-compose.yaml",
                      "why": "compose does not name a `main` service (F2 contract)"})
    return {"label": "[Fail - Compose Contract]", "candidates": cands,
            "files_to_read": ["environment/docker-compose.yaml"]}


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
