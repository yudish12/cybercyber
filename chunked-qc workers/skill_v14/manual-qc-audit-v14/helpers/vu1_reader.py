#!/usr/bin/env python3
"""vu1_reader.py -- READER for VU1 (Secret Authenticity)."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vu1_finder
RULEBOOK = r"""
# VU1 READER — Secret Authenticity (V14 dimension 10)
Score ONE task against VU1 ONLY. No other task in context. Decide from files you OPEN AND READ; cite file:line.
[Fail - Baked or Static Secret]: FAIL if the scored value is a hardcoded/static literal in served source, or is
minted by a harness and served OFF the vuln path (not disclosed through the real exploit). Read the generation
sites and the disclosure path: the scored value must be reachable ONLY by performing the intended exploit.
## Output contract — return ONLY this JSON:
{"dimension":"VU1","verdicts":[{"sub_label":"[Fail - Baked or Static Secret]","verdict":"FAIL|PASS|REVIEW",
"citations":[{"file":"<rel>","line":<int|null>,"quote":"<exact>"}],"reason":"<one sentence; names NO other task>"}],
"vu1_score":2|5,"disclosure_path":"<how the scored value is disclosed>","open_items":[]}
""".strip()
def build_reader_packet(task_dir):
    found = vu1_finder.find(task_dir); files = {}
    for ch in found["checks"].values():
        for f in ch.get("files_to_read", []):
            files.setdefault(f, {"abs": os.path.join(found["task_dir"], f), "for": [ch["label"]]})
    return {"rulebook": RULEBOOK, "task_dir": found["task_dir"],
            "finder_candidates": found["checks"], "files_to_open": files,
            "instructions": "Read the generation sites and the disclosure path; confirm the scored value is only "
                            "reachable via the intended exploit. Return the JSON in the output contract."}
def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: vu1_reader.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    pkt = build_reader_packet(argv[0])
    if "--json" in argv:
        json.dump(pkt, open(argv[argv.index("--json")+1], "w"), indent=2); return 0
    print(pkt["rulebook"]); print("\n# ---- READER PACKET ----")
    print(f"# baked candidates: {len(pkt['finder_candidates']['secret_authenticity']['baked_candidates'])}")
    return 0
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
