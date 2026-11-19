#!/usr/bin/env python3
"""spam_reader.py -- READER for the SPAM CHECK (dimension 21)."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spam_finder
RULEBOOK = r"""
# SPAM READER — Explanations Spam Check (V14 dimension 21)
Score ONE task against the Spam Check ONLY. No other task in context. Decide from the explanation fields you
OPEN AND READ; cite the field. [Fail - Spam]: FAIL if an explanation field (difficulty_explanation,
model_failure_reason, report/operator notes) is spam/filler/boilerplate rather than substantive reasoning —
empty, padding, copy-paste, or disconnected from the actual task. Read each field and judge substance.
## Output contract — return ONLY this JSON:
{"dimension":"SPAM","verdicts":[{"sub_label":"[Fail - Spam]","verdict":"FAIL|PASS|REVIEW",
"citations":[{"file":"<rel>","line":<int|null>,"quote":"<exact>"}],"reason":"<one sentence; names NO other task>"}],
"spam_score":2|5,"open_items":[]}
""".strip()
def build_reader_packet(task_dir):
    found = spam_finder.find(task_dir); files = {}
    for ch in found["checks"].values():
        for f in ch.get("files_to_read", []):
            files.setdefault(f, {"abs": os.path.join(found["task_dir"], f), "for": [ch["label"]]})
    return {"rulebook": RULEBOOK, "task_dir": found["task_dir"],
            "finder_candidates": found["checks"], "files_to_open": files,
            "instructions": "Read each explanation field and judge substance vs spam. Return the JSON."}
def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: spam_reader.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    pkt = build_reader_packet(argv[0])
    if "--json" in argv:
        json.dump(pkt, open(argv[argv.index("--json")+1], "w"), indent=2); return 0
    print(pkt["rulebook"]); print("\n# ---- READER PACKET ----")
    print(f"# spam candidates: {len(pkt['finder_candidates']['spam_check']['candidates'])}")
    return 0
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
