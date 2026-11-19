#!/usr/bin/env python3
"""trial_reader.py -- READER for the pass@k TRIAL group (EV6 Technique Fidelity, TR4 Fair Trial)."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trial_finder
RULEBOOK = r"""
# TRIAL READER — EV6 Technique Fidelity + TR4 Fair Trial (custom pass@k dimensions)

Score ONE task's pass@k trials ONLY. No other task in context. Decide from the shipped
trajectories/pass@k trials you OPEN AND READ; cite the trial + file. Fail-closed: if a trial's
evidence is incomplete, do not pass it.

EV6 [Fail - Technique Mismatch]: for each solved+valid trial, read agent/trajectory.json — did it
   actually exercise the INTENDED mechanism (the endpoints solve.sh uses: the finder lists them)?
   A solved=True trial whose trajectory never reaches the intended vulnerable endpoints solved off
   the intended path -> FAIL. (Path extraction can miss POST-only endpoints; read the trajectory
   before concluding.)

TR4 [Fail - Unfair Trial]: a valid trial that did not get a fair shot -- no/too-few agent steps,
   a refusal, or the same tool output repeated in a loop (scaffold/tooling malfunction). Such a
   trial is not a genuine measurement of model skill -> FAIL.

## Output contract — return ONLY this JSON:
{"group":"TRIAL","verdicts":[{"dimension":"EV6|TR4","verdict":"FAIL|PASS|REVIEW|DEFERRED",
"citations":[{"file":"<trial/file>","line":<int|null>,"quote":"<exact>"}],
"reason":"<one sentence; names NO other task>"}],"trial_score":2|5,"open_items":[]}
""".strip()
def build_reader_packet(task_dir):
    found = trial_finder.find(task_dir); files = {}
    for ch in found["checks"].values():
        for f in ch.get("files_to_read", []):
            files.setdefault(f, {"abs": os.path.join(found["task_dir"], f), "for": [ch["label"]]})
    return {"rulebook": RULEBOOK, "task_dir": found["task_dir"],
            "finder_candidates": found["checks"],
            "trials": found.get("trials", []), "intended_segments": found.get("intended_segments", []),
            "files_to_open": files,
            "instructions": "Read each solved trial's trajectory for EV6 (did it reach the intended endpoints?) "
                            "and the fairness signals for TR4. Return the JSON in the output contract."}
def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: trial_reader.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    pkt = build_reader_packet(argv[0])
    if "--json" in argv:
        json.dump(pkt, open(argv[argv.index("--json")+1], "w"), indent=2); return 0
    print(pkt["rulebook"]); print("\n# ---- READER PACKET ----")
    e6 = pkt["finder_candidates"]["ev6_technique_fidelity"]
    t4 = pkt["finder_candidates"]["tr4_fair_trial"]
    print(f"# status: {e6.get('status')}  EV6 candidates: {len(e6['candidates'])}  TR4 candidates: {len(t4['candidates'])}")
    return 0
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
