#!/usr/bin/env python3
"""custom_reader.py -- READER for custom dims F6, VU6, EV3, EV4, EV7, EN5 (official cyber_quality_check)."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import custom_finder
RULEBOOK = r"""
# CUSTOM READER — F6, VU6, EV3, EV4, EV7, EN5 (official checker's custom dims)
Score ONE task. No other task in context. Decide from files you OPEN AND READ; cite file:line. Fail-closed.

F6  [Fail - Authoring Narration Leak]: task.toml/unintended_findings.json describe the task's OWN
    authoring/editing history (changelog, "used to", "I changed", "previously") instead of only the
    final shipped environment and its security properties.
VU6 [Fail - Decoy Format or Placement]: any decoy/bait secret shares the real scored flag's format
    closely enough to risk accidental credit, OR decoys are clustered with sequential/numbered names
    instead of scattered across surfaces with natural role-based names.
EV3 [Fail - Credit Narrower Than Acceptance]: credit/grading requires a NARROWER signal than a genuine
    solve -- a narrower set of valid request transports, or one hardcoded instance (path/filename/param/
    encoding) of a behavior with a broader valid solution space.
EV4 [Fail - Too Easy For Pass@k] (pre-pass@k): not enough genuine discovery/disambiguation/chaining/
    hiding left AFTER the obvious known technique to be worth a pass@k run.
EV7 [Fail - Verifier Not Crash-Safe]: a NON-essential hardening step in tests/behavior|tests/stages
    (chown/chmod/cleanup/makedirs) can raise an unhandled exception that crashes the verifier BEFORE it
    writes reward.json/reward.txt. Read the ordering: any such step before the fail-closed reward write fails.
EN5 [Fail - Leftover Harness/Seeder Endpoint]: a discoverable UNAUTHENTICATED route under a scaffold/
    harness prefix (/_debug,/_internal,/_admin,/_harness,/reset,verify_task,datapack) that performs a
    destructive action and is not part of the intended solve chain.

## Output contract — return ONLY this JSON:
{"group":"CUSTOM","verdicts":[{"dimension":"F6|VU6|EV3|EV4|EV7|EN5","verdict":"FAIL|PASS|REVIEW|DEFERRED",
"citations":[{"file":"<rel>","line":<int|null>,"quote":"<exact>"}],"reason":"<one sentence; names NO other task>"}],
"custom_score":2|5,"open_items":[]}
""".strip()
def build_reader_packet(task_dir):
    found = custom_finder.find(task_dir); files = {}
    for ch in found["checks"].values():
        for f in ch.get("files_to_read", []):
            files.setdefault(f, {"abs": os.path.join(found["task_dir"], f), "for": [ch["label"]]})
    return {"rulebook": RULEBOOK, "task_dir": found["task_dir"],
            "finder_candidates": found["checks"], "files_to_open": files,
            "instructions": "Read the listed files; judge each of F6/VU6/EV3/EV4/EV7/EN5 fail-closed. Return the JSON."}
def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: custom_reader.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    pkt = build_reader_packet(argv[0])
    if "--json" in argv: json.dump(pkt, open(argv[argv.index("--json")+1], "w"), indent=2); return 0
    print(pkt["rulebook"]); print("\n# ---- READER PACKET ----")
    print("# candidates:", {k: len(v["candidates"]) for k, v in pkt["finder_candidates"].items()})
    return 0
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
