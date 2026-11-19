#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
en4_reader.py  --  READER layer of the EN4 eval (the fenced EN4 worker).

The finder (en4_finder.py) POINTS. This builds the READER PACKET an agent
executes: a task-agnostic, de-anecdoted EN4 rulebook + the exact files to OPEN
AND READ (NOTICE, every Dockerfile, compose, each vendored wheel's METADATA,
entrypoints) + the finder's candidates + the read-and-cite output contract.
Certainty comes from the reader opening each file -- never the grep alone.

The rulebook names no sibling task, case, or version. A correctly-fenced reader
cannot produce such a name; if it does, the run is a contamination leak and void.

Usage:  python3 -I en4_reader.py <task_dir> [--json OUT]
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import en4_finder

RULEBOOK = r"""
# EN4 READER — Operational & Reproducibility (V14 dimension 9)

You score ONE task bundle against EN4 ONLY. You have NO other task in context and
MUST NOT reason by analogy to any other task, case, or version. Decide from THIS
bundle's files that you OPEN AND READ. Every verdict cites file:line or an exact
value. If you did not read it, you cannot score it.

Calibration: a false FAIL/REVIEW is acceptable; a MISSED fail is not. When reading
leaves you unsure, return REVIEW; runtime-only facts return LIVE. Never a vacuous PASS.
A LITERAL provenance gap (a missing license line, an unpinned tag) is a FAIL even if
"it builds anyway" -- the rubric pins the requirement to NOTICE, not to runtime.

Read, don't skim: open the top-level NOTICE, every Dockerfile, the compose file,
and each vendored wheel's METADATA. Confirm or clear each finder candidate by reading.

Score the three EN4 sub-labels:

1. [Fail - Provenance / Licensing]
   The TOP-LEVEL environment/NOTICE.md (a nested environment/<app>/NOTICE.md does NOT
   count) must name EVERY base image (every Dockerfile FROM + every compose image:),
   EVERY vendored wheel, AND the first-party app -- each with a stated LICENSE, and each
   image with a digest pin. FAIL if any component is missing, has no license, or the
   NOTICE license CONTRADICTS the component's own source:
     - a digest pin is NOT a license;
     - verify each wheel's license against its OWN .dist-info/METADATA; a blanket
       "MIT/Apache/BSD" over a wheel that is actually MPL-2.0, CNRI-Python, PSF-2.0,
       GPL, or LGPL is a misstatement -> FAIL;
     - verify each base image's license at its real source (a copyleft base stated as
       permissive is a misstatement).

2. [Fail - Unbounded or Unpinned]
   Any base image using a mutable tag with no @sha256 digest pin -> FAIL (cite the
   Dockerfile/compose line).

3. [Fail - Reproducibility]
   FAIL if the runtime needs the public internet, boots are flaky, service discovery
   drifts (the verifier/solver is less patient than the agent -> a false infra_error),
   a service restart desyncs the scored marker, the report-judge needs the public
   internet, or a client-IP allowlist excludes the Docker-allocated subnet. Read the
   entrypoints/compose/timeouts now; confirm the rest with a boot (LIVE): run twice,
   restart main and re-check the marker, and confirm no external network is required.

## Output contract — return EXACTLY this JSON, nothing else:
{
  "dimension": "EN4",
  "verdicts": [
    {"sub_label": "<one of the three labels>",
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
    # always read the top-level NOTICE and each wheel's METADATA
    return {
        "rulebook": RULEBOOK,
        "task_dir": found["task_dir"],
        "notice": found["notice"],
        "images": found["images"],
        "wheel_count": found["wheel_count"],
        "files_to_open": files,
        "finder_candidates": found["checks"],
        "instructions": "Open every file in files_to_open and READ it (for wheels, read the "
                        "dist-info/METADATA inside the .whl). Treat finder_candidates as leads to "
                        "confirm or clear by reading. Return the JSON in the rulebook's output contract.",
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
    print(f"# NOTICE present: {pkt['notice']['present']}  images: {len(pkt['images'])}  wheels: {pkt['wheel_count']}")
    print(f"# OPEN AND READ these {len(pkt['files_to_open'])} files (+ each wheel's METADATA):")
    for f, meta in sorted(pkt["files_to_open"].items()):
        print(f"#   {f}")
    pv = pkt["finder_candidates"]["provenance_licensing"]["fail_candidates"]
    up = pkt["finder_candidates"]["unpinned_images"]["fail_candidates"]
    print(f"# finder leads: provenance={len(pv)} unpinned={len(up)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
