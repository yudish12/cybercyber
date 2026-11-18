#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""traj_reader.py -- READER for the TRAJECTORY group (TR2, TR3)."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import traj_finder

RULEBOOK = r"""
# TRAJECTORY READER — TR2 & TR3 (V14 dimensions 15-16)

Score ONE task against TR2 and TR3 ONLY. No other task is in context; do not compare to one.
Decide from the shipped oracle/noop trajectories you OPEN AND READ. Cite file:line.

TR2 [Fail - Noop Scores]: the noop trajectory (agent does nothing) must earn reward 0. If it
    earns 1, the reward is gameable by inaction — FAIL.
TR3 [Fail - Oracle Unwired]: the oracle trajectory must earn reward 1, AND it must do so via
    the INTENDED path. Read trajectories/oracle/agent/trajectory.json and solve.sh: the oracle
    must perform the intended exploit, not a shortcut. FAIL if reward != 1 or the path is wrong.

## Output contract — return ONLY this JSON:
{
  "group": "TRAJECTORY",
  "verdicts": [
    {"dimension": "TR2|TR3", "verdict": "FAIL|PASS|REVIEW",
     "citations": [{"file": "<rel>", "line": <int|null>, "quote": "<exact>"}],
     "reason": "<one sentence; names NO other task>"}
  ],
  "traj_score": 2 | 5,
  "open_items": []
}
""".strip()


def build_reader_packet(task_dir):
    found = traj_finder.find(task_dir)
    files = {}
    for ch in found["checks"].values():
        for f in ch.get("files_to_read", []):
            files.setdefault(f, {"abs": os.path.join(found["task_dir"], f), "for": []})["for"].append(ch["label"])
    return {"rulebook": RULEBOOK, "task_dir": found["task_dir"],
            "finder_candidates": found["checks"], "files_to_open": files,
            "instructions": "Read the oracle/noop rewards and the oracle trajectory; confirm noop=0 and "
                            "oracle=1 via the intended path. Return the JSON in the output contract."}


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: traj_reader.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    pkt = build_reader_packet(argv[0])
    if "--json" in argv:
        json.dump(pkt, open(argv[argv.index("--json") + 1], "w"), indent=2); return 0
    print(pkt["rulebook"]); print("\n# ---- READER PACKET ----")
    print(f"# noop reward: {pkt['finder_candidates']['tr2_noop']['noop_reward']}  "
          f"oracle reward: {pkt['finder_candidates']['tr3_oracle']['oracle_reward']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
