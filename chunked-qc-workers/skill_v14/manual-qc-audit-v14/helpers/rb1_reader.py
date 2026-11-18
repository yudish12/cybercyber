#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rb1_reader.py  --  READER layer of the RB1 eval (the fenced RB1 worker).

The finder (rb1_finder.py) POINTS; this builds the READER PACKET an agent executes:
a task-agnostic, de-anecdoted RB1 rulebook + the exact files to OPEN AND READ
(tests/stages/rubric.toml, the stage code, the reward wiring) + the finder's signals
+ the read-and-cite output contract. RB1 is semantic -- the reader does most of the
deciding, which is the whole point: it reads tests/stages/ (the files a broken judge
never receives), so it both renders the certain verdict AND refutes the documented
"rubric.toml not present" false positive with a citation.

The rulebook names no sibling task, case, or version. If the reader's reasoning names
one, that is a contamination leak and the run is void.

Usage:  python3 -I rb1_reader.py <task_dir> [--json OUT]
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rb1_finder

RULEBOOK = r"""
# RB1 READER — Staged-Rubric Quality (V14 dimension 20)

You score ONE task bundle against RB1 ONLY. You have NO other task in context and
MUST NOT reason by analogy to any other task, case, or version. Decide from THIS
bundle's files that you OPEN AND READ. Every verdict cites file:line. If you did not
read it, you cannot score it.

FIRST, refute the common false positive: OPEN tests/stages/rubric.toml and the stage
code yourself. If they are present and readable, a prior verdict of "rubric.toml not
present / rubric missing" is a FALSE POSITIVE -- say so and cite the path. Only score
a missing-rubric fail if the file is genuinely absent.

Calibration: a false REVIEW/FAIL is acceptable; a MISSED fail is not. Unsure after
reading -> REVIEW, never a vacuous PASS.

Read, don't skim: open rubric.toml (every [[stage]] + its criterion), the stage code
(how each stage's credit is actually derived), and the reward wiring (tests/test.sh,
tests/behavior/verify.py). The finder's signals are leads to confirm or clear.

Score the two RB1 sub-labels:

1. [Fail - Intended-Path Not Modeled]
   A technique_fidelity or outcome stage must credit the scored disclosure/submission
   step, so a solving and a non-solving trial are DISTINGUISHABLE on that step. FAIL if
   every stage is "process" (or no stage credits the discriminating step).

2. [Fail - Spoofable or Gating Rubric]
   FAIL if a decisive stage is creditable from the agent's NARRATION / report text, or
   from a LATER stage firing (prerequisite-collapse), or from a whole-trajectory
   SUBSTRING match; OR if the staged rubric GATES the official reward (the reward comes
   from the stage score rather than from the independent exploit/behavior check).
   - Read how each decisive stage derives credit. Credit from PROTECTED/OBSERVABLE
     evidence (an endpoint+response, bound audit events, a cryptographic proof) is GOOD.
   - A comment that DISCLAIMS narration use, or report-text handling that belongs to a
     SEPARATE report judge (not the scored behavior gate), is NOT a fail -- confirm by
     reading which path feeds the official reward.

## Output contract — return EXACTLY this JSON, nothing else:
{
  "dimension": "RB1",
  "rubric_present": true | false,
  "rubric_path": "<path or null>",
  "verdicts": [
    {"sub_label": "<one of the two labels>",
     "verdict": "FAIL" | "PASS" | "REVIEW",
     "citations": [{"file": "<rel path>", "line": <int|null>, "quote": "<exact text>"}],
     "reason": "<one sentence, grounded in what you read; names NO other task>"}
  ],
  "rb1_score": 2 | 5,          // 2 if any sub_label is FAIL, else 5
  "false_positive_refuted": "<e.g. 'rubric.toml present at tests/stages/rubric.toml' or null>",
  "open_items": ["<REVIEW items a human must still settle>"]
}
""".strip()


def build_reader_packet(task_dir):
    found = rb1_finder.find(task_dir)
    files = {}
    for ch in found["checks"].values():
        for f in ch.get("files_to_read", []):
            files.setdefault(f, {"abs": os.path.join(found["task_dir"], f), "for": []})["for"].append(ch["label"])
    return {
        "rulebook": RULEBOOK,
        "task_dir": found["task_dir"],
        "rubric": found["rubric"],
        "stage_count": found["stage_count"],
        "files_to_open": files,
        "finder_signals": found["checks"],
        "instructions": "Open tests/stages/rubric.toml and the stage code and READ them. First confirm "
                        "the rubric is present (refute any 'not present' FP). Treat finder_signals as leads "
                        "to confirm or clear by reading how credit is derived and how the reward is wired. "
                        "Return the JSON in the rulebook's output contract.",
    }


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: rb1_reader.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    pkt = build_reader_packet(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(pkt, f, indent=2)
        print(f"wrote {argv[argv.index('--json') + 1]}")
        return 0
    print(pkt["rulebook"])
    print("\n# ---- READER PACKET ----")
    print(f"# task_dir: {pkt['task_dir']}")
    print(f"# rubric present: {pkt['rubric']['present']}  ({pkt['rubric']['path']})  stages: {pkt['stage_count']}")
    print(f"# OPEN AND READ these {len(pkt['files_to_open'])} files:")
    for f in sorted(pkt["files_to_open"]):
        print(f"#   {f}")
    sp = pkt["finder_signals"]["spoofable"]["signals"]
    rg = pkt["finder_signals"]["reward_gating"]["signals"]
    print(f"# finder leads: spoof-signals={len(sp)} gating-signals={len(rg)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
