#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vu1_finder.py  --  static FINDER for VU1 (Secret Authenticity).

[Fail - Baked or Static Secret]: the scored value must be disclosed through the REAL vuln,
not baked/static in served source nor minted by a harness and served off-path. Static leads:
  - where the scored value is GENERATED (secrets.*/urandom/uuid) -> dynamic is a good sign;
  - a hardcoded marker/secret LITERAL in served (author) source -> baked candidate.
The reader confirms the disclosure path (through the exploit, not a direct serve).

Usage:  python3 -I vu1_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io

_AUTHOR_SEGS = {"gateway", "custom", "operator", "operator-init", "agent", "ledger-service"}
_SRC_EXT = (".py", ".php", ".ts", ".tsx", ".js", ".jsx", ".go", ".rb")
_GEN_RE = re.compile(r"secrets\.(token_hex|token_urlsafe|token_bytes)|os\.urandom|uuid4|randbytes|token_hex\(", re.I)
# a baked marker literal: a long hex/alnum run assigned to a flag/marker/secret-ish name
_BAKED_RE = re.compile(r"(flag|marker|secret|scored|answer)\w*\s*[:=]\s*['\"]([0-9a-fA-F]{24,}|FLAG\w*=\S+)['\"]", re.I)


def _read(p):
    try:
        return io.open(p, "r", encoding="utf-8", errors="replace").read()
    except Exception:
        return ""


def _is_author(rel):
    segs = rel.split("/")
    return any(s in _AUTHOR_SEGS or s.endswith("-init") or s.endswith("-service") for s in segs)


def find(task_dir):
    env = os.path.join(task_dir, "environment")
    gen, baked, files = [], [], set()
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if not fn.endswith(_SRC_EXT):
                continue
            rel = os.path.relpath(os.path.join(dp, fn), task_dir)
            if not _is_author(rel):
                continue
            for i, line in enumerate(_read(os.path.join(dp, fn)).splitlines(), 1):
                if _GEN_RE.search(line):
                    gen.append({"file": rel, "line": i, "text": line.strip()[:160]}); files.add(rel)
                if _BAKED_RE.search(line):
                    baked.append({"file": rel, "line": i, "text": line.strip()[:160],
                                  "why": "scored secret appears hardcoded (baked/static) in served source"})
                    files.add(rel)
    return {"task_dir": os.path.abspath(task_dir),
            "checks": {"secret_authenticity": {
                "label": "[Fail - Baked or Static Secret]",
                "generation_sites": gen, "baked_candidates": baked,
                "files_to_read": sorted(files) or ["environment"],
                "note": "reader confirms the scored value is disclosed THROUGH the exploit path, "
                        "not baked in source nor minted by a harness and served off the vuln."}}}


def _summary(r):
    c = r["checks"]["secret_authenticity"]
    o = [f"VU1 FINDER — {r['task_dir']}",
         f"  secret generation sites: {len(c['generation_sites'])}  baked candidates: {len(c['baked_candidates'])}"]
    for b in c["baked_candidates"][:8]:
        o.append(f"     FAIL?  {b['file']}:{b['line']}  — {b['why']}")
    for g in c["generation_sites"][:4]:
        o.append(f"     gen    {g['file']}:{g['line']}  {g['text']}")
    o.append("  NOTE: reader confirms the disclosure path (through the vuln, not a direct serve).")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: vu1_finder.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    r = find(argv[0])
    if "--json" in argv:
        json.dump(r, open(argv[argv.index("--json") + 1], "w"), indent=2)
    print(_summary(r)); return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
