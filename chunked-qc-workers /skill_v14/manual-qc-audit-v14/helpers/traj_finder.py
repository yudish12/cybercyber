#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
traj_finder.py  --  static FINDER for the TRAJECTORY group (TR2, TR3).

Decidable from the shipped oracle/noop trajectories (always present pre-pass@k):
  TR2 Noop Earns Nothing   [Fail - Noop Scores]     : the noop trajectory reward must be 0.
  TR3 Solve Is Wired       [Fail - Oracle Unwired]  : the oracle trajectory reward must be 1,
                                                       AND the oracle solve must use the intended
                                                       path (reader reads the oracle trajectory).

Usage:  python3 -I traj_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io
HERE = os.path.dirname(os.path.abspath(__file__))


def _read(p):
    try:
        with io.open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _reward(task_dir, which):
    """Return (value|None, path) for a trajectory's reward."""
    base = os.path.join(task_dir, "trajectories", which)
    for rel in ("reward.txt", "verifier/reward.txt", "reward.json", "verifier/reward.json"):
        p = os.path.join(base, rel)
        if os.path.exists(p):
            t = _read(p).strip()
            if rel.endswith(".json"):
                try:
                    return int(json.loads(t).get("reward")), os.path.relpath(p, task_dir)
                except Exception:
                    continue
            m = re.search(r"-?\d+", t)
            if m:
                return int(m.group(0)), os.path.relpath(p, task_dir)
    return None, f"trajectories/{which}/reward.txt"


def _tr2(task_dir):
    val, path = _reward(task_dir, "noop")
    cands = []
    if val is None:
        cands.append({"file": path, "why": "noop trajectory reward not found (shipped noop required)"})
    elif val != 0:
        cands.append({"file": path, "why": f"noop earns reward {val} (must be 0)"})
    return {"label": "[Fail - Noop Scores]", "noop_reward": val, "candidates": cands,
            "files_to_read": ["trajectories/noop/reward.txt", "trajectories/noop/test.log",
                              "trajectories/noop/agent/trajectory.json"]}


_REQ_LINE_RE = re.compile(r"https?://|\$\{?BASE\}?|\bcurl\b|\bwget\b|post_json|get_json", re.I)
_ASSERT_RE = re.compile(r"grep\s+-q|assert|\bfail\b|\bdie\b|\|\|\s*(fail|die|exit)", re.I)
_URLPATH_RE = re.compile(r"(?:\$\{?BASE\}?|https?://[^/\s\"']+)(/[A-Za-z0-9_\-/.]+)")
_DISC_NOISE = {"logs", "verifier", "tmp", "api", "dev", "etc", "work", "opt", "bin", "var",
               "www", "health", "credentials", "index"}


def _unverified_discovery(task_dir):
    """Ported oracle_discoverability_gaps: each later-hop request literal (beyond the entry
    point) must have an earlier discovery-assertion (grep -q/assert/fail/die) naming it."""
    out = []
    for name in ("solve.sh", "solve.py"):
        p = os.path.join(task_dir, "solution", name)
        if not os.path.exists(p):
            continue
        lines = _read(p).splitlines()
        seen, uncovered = [], []
        for idx, line in enumerate(lines):
            if not _REQ_LINE_RE.search(line):
                continue
            for m in _URLPATH_RE.finditer(line):
                for seg in [s for s in m.group(1).strip("/").split("/") if len(s) >= 3 and not s.isdigit() and s.lower() not in _DISC_NOISE]:
                    if seg in seen:
                        continue
                    entry = not seen
                    seen.append(seg)
                    if entry:
                        continue
                    prior = "\n".join(lines[:idx])
                    if not any(_ASSERT_RE.search(l) and seg in l for l in prior.splitlines()):
                        uncovered.append((seg, idx + 1))
        has_assert = any(_ASSERT_RE.search(l) for l in lines)
        if len(uncovered) >= 2 and not has_assert:
            out.append({"file": "solution/" + name,
                        "why": f"{len(uncovered)} later-hop literal(s) with NO discovery-assertion: "
                               + ", ".join(f"{s!r}(L{ln})" for s, ln in uncovered[:6]),
                        "label": "[Fail - Unverified Discovery]"})
    return out


def _tr3(task_dir):
    val, path = _reward(task_dir, "oracle")
    cands = []
    if val is None:
        cands.append({"file": path, "why": "oracle trajectory reward not found (shipped oracle required)"})
    elif val != 1:
        cands.append({"file": path, "why": f"oracle earns reward {val} (must be 1 — solve not wired)"})
    # TR3 [Fail - No Write]: solve.sh must write the submission file (> file or tee file)
    solve = _read(os.path.join(task_dir, "solution", "solve.sh")) + "\n" + _read(os.path.join(task_dir, "solution", "solve.py"))
    if solve.strip() and not (re.search(r">\s*\S+", solve) or re.search(r"\btee\s+\S+", solve)):
        cands.append({"file": "solution/solve.sh", "why": "no submission-file write (`> file`/`tee`) found in solve.sh",
                      "label": "[Fail - No Write]"})
    # TR3 [Fail - Unverified Discovery]: later-hop request literals with no prior discovery-assertion
    cands += _unverified_discovery(task_dir)
    return {"label": "[Fail - Oracle Unwired]", "oracle_reward": val, "candidates": cands,
            "files_to_read": ["trajectories/oracle/reward.txt", "trajectories/oracle/test.log", "solution/solve.sh",
                              "trajectories/oracle/agent/trajectory.json", "solution/solve.sh"],
            "note": "reader reads the oracle trajectory to confirm the solve uses the INTENDED path."}


def find(task_dir):
    return {"task_dir": os.path.abspath(task_dir),
            "checks": {"tr2_noop": _tr2(task_dir), "tr3_oracle": _tr3(task_dir)}}


def _summary(r):
    o = [f"TRAJECTORY FINDER (TR2/TR3) — {r['task_dir']}"]
    t2 = r["checks"]["tr2_noop"]; t3 = r["checks"]["tr3_oracle"]
    o.append(f"  TR2 noop reward={t2['noop_reward']}  candidates={len(t2['candidates'])}")
    for c in t2["candidates"]:
        o.append(f"     FAIL?  {c['file']}  — {c['why']}")
    o.append(f"  TR3 oracle reward={t3['oracle_reward']}  candidates={len(t3['candidates'])}")
    for c in t3["candidates"]:
        o.append(f"     FAIL?  {c['file']}  — {c['why']}")
    o.append("  NOTE: rewards are decidable statically; the reader confirms the oracle used the intended path.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: traj_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
