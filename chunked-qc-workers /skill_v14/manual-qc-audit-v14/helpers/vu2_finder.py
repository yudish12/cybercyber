#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vu2_finder.py  --  static FINDER layer of the VU2 eval
(Vulnerability: Decoy & Patch Coverage).

VU2 is reader-dominant. The finder provides COVERAGE so the reader misses no sibling:

  * route inventory: enumerate every route/handler in the author app, GROUPED by resource,
    so the reader can check the documented fix closes EVERY sibling, not just the named one
    ([Fail - Survives Documented Fix]: a sibling verb/adjacent path still reaches the secret).
  * documented fix / resisting decoy: locate the remediation and resisting-sibling
    descriptions, so the reader can check a genuine decoy resists and no decoy yields the
    secret ([Fail - Missing or Leaking Decoy]).

The reader opens the grouped handlers + the fix and renders the verdict. The finder makes
no FAIL call -- whether a sibling survives the fix is a reading judgment.

Usage:  python3 -I vu2_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io

_ROUTE_RES = [
    re.compile(r"@(?:app|router|bp|blueprint|api)\.(get|post|put|patch|delete|route)\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"Route::(get|post|put|patch|delete|any|match)\(\s*['\"]([^'\"]+)['\"]", re.I),
]
_ENDPOINT_DIRS = {"custom", "htdocs", "api", "endpoints", "public", "www", "routes", "pages"}
_AUTHOR_SEGS = {"gateway", "custom", "operator", "operator-init", "agent", "ledger-service"}
_SRC_EXT = (".py", ".php", ".ts", ".tsx", ".js", ".jsx", ".rb", ".go")
_FIX_RE = re.compile(
    r"resist|enforc|escap|reject|remediat|documented fix|ownership|parameteriz|the fix|"
    r"\bpatch\b|sanitiz|validates?|allowlist|guard", re.I)


def _read(p):
    try:
        with io.open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _is_author(rel):
    segs = rel.replace("\\", "/").split("/")
    for s in segs:
        if s in _AUTHOR_SEGS or s.endswith("-init") or s.endswith("-service"):
            return True
    return False


def _routes(task_dir):
    env = os.path.join(task_dir, "environment")
    routes, files = [], set()
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _SRC_EXT:
                continue
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, task_dir)
            if not _is_author(rel):
                continue
            text = _read(full)
            found_route = False
            for i, line in enumerate(text.splitlines(), 1):
                for rx in _ROUTE_RES:
                    m = rx.search(line)
                    if m:
                        routes.append({"file": rel, "line": i,
                                       "method": m.group(1).upper(), "path": m.group(2)})
                        found_route = True
                        break   # one route per line (avoid double-match across patterns)
            # a .php file inside an endpoint dir IS an endpoint, even with no route decorator
            if ext == ".php" and any(seg in _ENDPOINT_DIRS for seg in rel.split("/")):
                routes.append({"file": rel, "line": 1, "method": "PHP-FILE", "path": rel})
                found_route = True
            if found_route:
                files.add(rel)
    # de-dup exact (file,line,method,path)
    seen, uniq = set(), []
    for rt in routes:
        k = (rt["file"], rt["line"], rt["method"], rt["path"])
        if k not in seen:
            seen.add(k); uniq.append(rt)
    return uniq, sorted(files)


def _group(routes):
    groups = {}
    for rt in routes:
        p = rt["path"]
        if p.startswith("/"):
            segs = [s for s in p.split("/") if s and not s.startswith(("<", ":", "{", "*"))]
            stem = "/" + "/".join(segs[:2]) if segs else "/"
        else:
            stem = os.path.dirname(p)
        groups.setdefault(stem, []).append(rt)
    return groups


def _documented_fix(task_dir):
    located, files = [], set()
    # difficulty_explanation
    toml = _read(os.path.join(task_dir, "task.toml"))
    m = re.search(r'(?is)difficulty_explanation\s*=\s*("""|\'\'\')(.*?)\1', toml)
    if m:
        files.add("task.toml")
        for j, seg in enumerate(re.split(r'(?<=[.;])\s+', m.group(2))):
            if _FIX_RE.search(seg):
                located.append({"file": "task.toml", "line": None, "text": seg.strip()[:200]})
    # remediation / report rubric / solution comments
    for rel in ("tests/report/judge_prompt.md", "tests/report/rubric.toml",
                "solution/solve.sh", "instruction_L2.md", "operator/notes.md"):
        p = os.path.join(task_dir, rel)
        if not os.path.exists(p):
            continue
        for i, line in enumerate(_read(p).splitlines(), 1):
            if _FIX_RE.search(line) and re.search(r"resist|enforc|escap|reject|remediat|ownership|sanitiz", line, re.I):
                located.append({"file": rel, "line": i, "text": line.strip()[:200]})
                files.add(rel)
    return {"label": "[Fail - Missing or Leaking Decoy]", "located": located,
            "files_to_read": sorted(files),
            "note": "reader confirms a genuine resisting sibling exists AND no decoy/adjacent path "
                    "reaches the scored secret."}


def find(task_dir):
    routes, files = _routes(task_dir)
    groups = _group(routes)
    return {
        "task_dir": os.path.abspath(task_dir),
        "checks": {
            "route_inventory": {
                "label": "[Fail - Survives Documented Fix]",
                "routes": routes,
                "resource_groups": groups,
                "multi_sibling_groups": {g: v for g, v in groups.items() if len(v) >= 2},
                "files_to_read": files,
                "note": "reader checks the documented fix closes EVERY sibling in each resource group "
                        "(a sibling verb/adjacent path must not still reach the secret)."},
            "documented_fix": _documented_fix(task_dir),
        },
    }


def _summary(r):
    inv = r["checks"]["route_inventory"]
    o = [f"VU2 FINDER — {r['task_dir']}",
         f"  routes: {len(inv['routes'])}  resource groups: {len(inv['resource_groups'])}  "
         f"multi-sibling groups: {len(inv['multi_sibling_groups'])}"]
    for g, items in inv["multi_sibling_groups"].items():
        o.append(f"  group {g!r}: {len(items)} siblings")
        for it in items[:8]:
            o.append(f"     {it['method']:8} {it['path']}   ({it['file']}:{it['line']})")
    fx = r["checks"]["documented_fix"]
    o.append(f"  [Documented fix / resisting decoy] located {len(fx['located'])} description(s)")
    for c in fx["located"][:8]:
        o.append(f"     fix?  {c['file']}:{c['line']}  — {c['text'][:120]}")
    o.append("  NOTE: finder enumerates. The reader checks the fix closes every sibling and a decoy resists.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: vu2_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
