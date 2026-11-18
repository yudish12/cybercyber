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


def _tr3(task_dir):
    val, path = _reward(task_dir, "oracle")
    cands = []
    if val is None:
        cands.append({"file": path, "why": "oracle trajectory reward not found (shipped oracle required)"})
    elif val != 1:
        cands.append({"file": path, "why": f"oracle earns reward {val} (must be 1 — solve not wired)"})
    return {"label": "[Fail - Oracle Unwired]", "oracle_reward": val, "candidates": cands,
            "files_to_read": ["trajectories/oracle/reward.txt", "trajectories/oracle/test.log",
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
