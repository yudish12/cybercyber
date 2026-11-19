#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
partition.py  --  split a task bundle into READ-FULL (the small decisive surface the reader
reads 100%) vs SCAN-ONLY (pristine vendored tree, grep only), plus the two data-flow seeds.

Rationale: grep overlooks novel/semantic issues, but those live in a small decisive surface
(author code, the credit/reward chain, tiers, solve, tests, the vendored overlay). Read THAT
fully; scan the untouched vendored bulk. Fast + no overlook where it matters.
"""
import os, re, sys, json, io

AUTHOR_SEGS = {"gateway", "custom", "operator", "operator-init", "agent", "ledger-service",
               "canary-init", "docker-init.d"}
_SRC_EXT = (".py", ".php", ".ts", ".tsx", ".js", ".jsx", ".go", ".rb", ".java", ".sh", ".sql")
_SKIP_EXT = (".whl", ".deb", ".pyc", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".db",
             ".tar", ".gz", ".zip", ".cast", ".bin", ".so", ".ico", ".woff", ".woff2")
_ALWAYS = ["task.toml", "instruction.md", "instruction_L0.md", "instruction_L1.md",
           "instruction_L2.md", "fresh_state.json", "unintended_findings.json",
           "environment/NOTICE.md", "environment/docker-compose.yaml", "environment/docker-compose.yml",
           "solution/solve.sh", "solution/solve.py", "tests/test.sh", "tests/isolation_test.sh"]
_ALWAYS_DIRS = ["tests/behavior", "tests/stages", "tests/report", "operator"]
_OVERLAY_SEGS = ("custom", "docker-init.d")          # author overlay inside a vendored app
_AUTHOR_HINT = ("gateway", "ledger-service", "operator-init", "canary-init")  # standalone author services


def _read(p):
    try: return io.open(p, "r", encoding="utf-8", errors="replace").read()
    except Exception: return ""


def _is_author_path(rel):
    segs = rel.split("/")
    return any(s in AUTHOR_SEGS or s.endswith("-init") or s.endswith("-service") for s in segs)


def partition(task_dir):
    read_full, scan_only, overlay, vendored_dirs = [], [], [], set()
    for rel in _ALWAYS:
        if os.path.isfile(os.path.join(task_dir, rel)):
            read_full.append(rel)
    for d in _ALWAYS_DIRS:
        for dp, _s, fns in os.walk(os.path.join(task_dir, d)):
            for fn in fns:
                if not fn.endswith(_SKIP_EXT):
                    read_full.append(os.path.relpath(os.path.join(dp, fn), task_dir))
    env = os.path.join(task_dir, "environment")
    # detect vendored app dirs: a top-level env dir that is NOT a standalone author service
    for name in (os.listdir(env) if os.path.isdir(env) else []):
        full = os.path.join(env, name)
        if os.path.isdir(full) and name not in _AUTHOR_HINT and not name.endswith(("-init", "-service")):
            # likely a vendored app (dolibarr/glpi/...) or db
            vendored_dirs.add(name)
    for dp, _s, fns in os.walk(env):
        for fn in fns:
            rel = os.path.relpath(os.path.join(dp, fn), task_dir)
            if rel in read_full:
                continue
            ext = os.path.splitext(fn)[1].lower()
            if ext in _SKIP_EXT:
                continue
            top = rel.split("/")[1] if rel.startswith("environment/") and len(rel.split("/")) > 1 else ""
            is_overlay = any(seg in _OVERLAY_SEGS for seg in rel.split("/")) or fn == "Dockerfile" or fn.endswith("entrypoint.sh")
            if _is_author_path(rel) or (top not in vendored_dirs) or is_overlay:
                read_full.append(rel)
                if is_overlay and top in vendored_dirs:
                    overlay.append(rel)
            elif ext in _SRC_EXT or fn.endswith((".conf", ".ini", ".yaml", ".yml", ".md", ".txt", ".json")):
                scan_only.append(rel)
    read_full = sorted(set(read_full))
    # flow seeds
    secret_sources, reward_setters = [], []
    for rel in read_full:
        txt = _read(os.path.join(task_dir, rel))
        if re.search(r"secrets\.token|os\.urandom|token_hex|SystemRandom", txt):
            secret_sources.append(rel)
        if re.search(r"reward\.(json|txt)|reward\s*=\s*1\b|[\"']reward[\"']\s*:\s*1", txt):
            reward_setters.append(rel)
    total = sum(os.path.getsize(os.path.join(task_dir, f)) for f in read_full if os.path.isfile(os.path.join(task_dir, f)))
    return {
        "task_dir": os.path.abspath(task_dir),
        "read_full": read_full,
        "read_full_bytes": total,
        "overlay_in_vendored": sorted(set(overlay)),
        "vendored_dirs": sorted(vendored_dirs),
        "scan_only_count": len(scan_only),
        "scan_only_sample": sorted(scan_only)[:20],
        "flows": {
            "scored_secret_sources": sorted(set(secret_sources)),
            "reward_setters": sorted(set(reward_setters)),
        },
    }


def _summary(r):
    o = [f"AUDIT PARTITION — {r['task_dir']}",
         f"  READ-FULL: {len(r['read_full'])} files, {r['read_full_bytes']//1024} KB (read these 100%)",
         f"  vendored apps (scan-only tree): {r['vendored_dirs']}",
         f"  overlay-in-vendored (read-full): {len(r['overlay_in_vendored'])} files",
         f"  SCAN-ONLY: {r['scan_only_count']} vendored source files (grep + targeted checks)",
         f"  FLOW 1 scored-secret sources: {r['flows']['scored_secret_sources']}",
         f"  FLOW 2 reward setters: {r['flows']['reward_setters']}",
         "  Reader: read every READ-FULL file in full; trace both flows end-to-end; grep the scan-only tree."]
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: partition.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    r = partition(argv[0])
    if "--json" in argv: json.dump(r, open(argv[argv.index("--json")+1], "w"), indent=2)
    print(_summary(r)); return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
