#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
en4_reader.py  --  READER layer of the EN4 eval (the fenced EN4 worker).

*** V19 NOTE: Provenance/Licensing moved to en5_reader.py / en5_finder.py ***
(its own numbered dimension now -- see en5_finder.py's module docstring for the
EN5 naming-collision warning). EN4 is now Unpinned + Reproducibility only.

The finder (en4_finder.py) POINTS. This builds the READER PACKET an agent
executes: a task-agnostic, de-anecdoted EN4 rulebook + the exact files to OPEN
AND READ (every Dockerfile, compose, entrypoints) + the finder's candidates +
the read-and-cite output contract. Certainty comes from the reader opening each
file -- never the grep alone.

The rulebook names no sibling task, case, or version. A correctly-fenced reader
cannot produce such a name; if it does, the run is a contamination leak and void.

Usage:  python3 -I en4_reader.py <task_dir> [--json OUT]
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import en4_finder

RULEBOOK = r"""
# EN4 READER — Operational & Reproducibility (V19 dimension)

You score ONE task bundle against EN4 ONLY. You have NO other task in context and
MUST NOT reason by analogy to any other task, case, or version. Decide from THIS
bundle's files that you OPEN AND READ. Every verdict cites file:line or an exact
value. If you did not read it, you cannot score it.

NOTE: Provenance/Licensing is NOT scored here -- it is its own dimension, EN5
(en5_reader.py). Score only the two labels below.

Calibration: a false FAIL/REVIEW is acceptable; a MISSED fail is not. When reading
leaves you unsure, return REVIEW; runtime-only facts return LIVE. Never a vacuous PASS.

Read, don't skim: open every Dockerfile, the compose file, and every entrypoint script.
Confirm or clear each finder candidate by reading.

Score the two EN4 sub-labels:

1. [Fail - Unbounded or Unpinned]
   Any base image using a mutable tag with no @sha256 digest pin -> FAIL (cite the
   Dockerfile/compose line).

2. [Fail - Reproducibility]
   FAIL if the runtime needs the public internet, boots are flaky, service discovery
   drifts (the verifier/solver is less patient than the agent -> a false infra_error),
   a service restart desyncs the scored marker, the report-judge needs the public
   internet, or a client-IP allowlist excludes the Docker-allocated subnet. Read the
   entrypoints/compose/timeouts now; confirm the rest with a boot (LIVE): run twice,
   restart main and re-check the marker, and confirm no external network is required.
   TIMEOUT BUDGET (read finder_candidates.timeout_budget, then re-derive every number from
   the files -- the finder parses heuristically). Each wait must fit inside whatever waits
   on it, else FAIL:
     a. verifier wait and solver wait >= the agent's own service wait (compose main loop);
     b. a caller's timeout (check.py `timeout=`, `timeout N bash x.sh`) > the callee script's
        own wait -- attempts x sleep at minimum; a retry fix that lengthens a loop without
        raising its caller's timeout is the classic regression;
     c. behavior caller + stage/report judge timeouts <= task.toml [verifier] timeout_sec.
   A worst-case-only overrun (per-try curl timeouts stacking) is a REVIEW, not a clean pass.

## Output contract — return EXACTLY this JSON, nothing else:
{
  "dimension": "EN4",
  "verdicts": [
    {"sub_label": "<one of the two labels>",
     "verdict": "FAIL" | "PASS" | "REVIEW" | "LIVE",
     "citations": [{"file": "<rel path>", "line": <int|null>, "quote": "<exact text/value>"}],
     "reason": "<one sentence, grounded in what you read; names NO other task>"}
  ],
  "en4_score": 2 | 5,          // 2 if any sub_label is FAIL, else 5 (REVIEW/LIVE do not auto-pass)
  "open_items": ["<REVIEW/LIVE items a human or a boot must still settle>"]
}
""".strip()


def build_reader_packet(task_dir):
    found = en4_finder.find(task_dir)
    files = {}
    for ch in found["checks"].values():
        for f in ch.get("files_to_read", []):
            ap = os.path.join(found["task_dir"], f)
            files.setdefault(f, {"abs": ap, "for": []})["for"].append(ch["label"])
    return {
        "rulebook": RULEBOOK,
        "task_dir": found["task_dir"],
        "images": found["images"],
        "files_to_open": files,
        "finder_candidates": found["checks"],
        "instructions": "Open every file in files_to_open and READ it. Treat finder_candidates "
                        "as leads to confirm or clear by reading. Return the JSON in the "
                        "rulebook's output contract.",
    }


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: en4_reader.py <task_dir> [--json OUT]", file=sys.stderr)
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
    print(f"# images: {len(pkt['images'])}")
    print(f"# OPEN AND READ these {len(pkt['files_to_open'])} files:")
    for f, meta in sorted(pkt["files_to_open"].items()):
        print(f"#   {f}")
    up = pkt["finder_candidates"]["unpinned_images"]["fail_candidates"]
    print(f"# finder leads: unpinned={len(up)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
