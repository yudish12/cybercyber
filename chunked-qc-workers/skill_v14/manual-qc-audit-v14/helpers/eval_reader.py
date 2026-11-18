#!/usr/bin/env python3
"""eval_reader.py -- READER for the EVALUATION remainder (EV1, EV5)."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_finder
RULEBOOK = r"""
# EVALUATION READER — EV1 & EV5 (V14 dimensions 17, 19)
Score ONE task against EV1 and EV5 ONLY. No other task in context. Decide from files you OPEN AND READ; cite file:line.
EV1 [Fail - Vacuous Anti-Cheat]: FAIL if no endpoint/technique match gates the reward, or the match runs AFTER
    ground-truth re-derivation / the golden exploit (so any path to a valid secret scores 1). Read the reward path
    and confirm the technique gate runs FIRST.
EV5 [Fail - Difficulty Too Low]: pre-pass@k this is DEFERRED (do not score). Post-pass@k: FAIL if the model solves
    5/5 (too easy), fewer than 3 trials ran without erroring, or NO non-solve is genuine (every non-solve is a
    refusal / infra abort / mis-grade / broken env). A 0/5 PASSES once >=3 non-errored trials and >=1 genuine
    non-solve are verified and the tier is recorded. Read the shipped trials.
## Output contract — return ONLY this JSON:
{"group":"EVALUATION","verdicts":[{"dimension":"EV1|EV5","verdict":"FAIL|PASS|REVIEW|LIVE|DEFERRED",
"citations":[{"file":"<rel>","line":<int|null>,"quote":"<exact>"}],"reason":"<one sentence; names NO other task>"}],
"eval_score":2|5,"open_items":[]}
""".strip()
def build_reader_packet(task_dir):
    found = eval_finder.find(task_dir); files = {}
    for ch in found["checks"].values():
        for f in ch.get("files_to_read", []):
            files.setdefault(f, {"abs": os.path.join(found["task_dir"], f), "for": [ch["label"]]})
    return {"rulebook": RULEBOOK, "task_dir": found["task_dir"],
            "finder_candidates": found["checks"], "files_to_open": files,
            "instructions": "Read the reward path (EV1 gate order) and the shipped trials (EV5). Return the JSON."}
def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: eval_reader.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    pkt = build_reader_packet(argv[0])
    if "--json" in argv:
        json.dump(pkt, open(argv[argv.index("--json")+1], "w"), indent=2); return 0
    print(pkt["rulebook"]); print("\n# ---- READER PACKET ----")
    print(f"# EV5 status: {pkt['finder_candidates']['ev5_difficulty'].get('status')}")
    return 0
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
