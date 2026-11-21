#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
en5_reader.py  --  READER layer of the OFFICIAL V19 EN5 eval
(Environment: {EN5} Provenance / Licensing).

*** NAMING COLLISION WARNING -- READ BEFORE RECONCILING cqc OUTPUT ***
This dimension is the official V19 "Provenance / Licensing" split out of EN4.
It is NOT cqc's (cyber_quality_check's) own custom "EN5 = Leftover Harness/
Seeder Endpoint Exposure" (checks/llm_checks.py), and NOT this skill's own
custom_finder.py/custom_reader.py (which still implements that Leftover-Harness
concept, unchanged). cqc has not been updated to V19 and still prints its
"EN5" row as Leftover-Harness-Endpoint. When reconciling tool output against
this skill (SKILL.md rule 7): a cqc row printed "EN5" is ALWAYS Leftover
Harness/Seeder Endpoint Exposure, never licensing. Do not conflate the two.

The finder (en5_finder.py) POINTS. This builds the READER PACKET: a task-
agnostic, de-anecdoted EN5 rulebook + the exact files to OPEN AND READ (NOTICE,
every Dockerfile, each vendored wheel's METADATA, the "credited elsewhere"
citation) + the finder's candidates + the read-and-cite output contract.

The rulebook names no sibling task, case, or version. A correctly-fenced reader
cannot produce such a name; if it does, the run is a contamination leak and void.

Usage:  python3 -I en5_reader.py <task_dir> [--json OUT]
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import en5_finder

RULEBOOK = r"""
# EN5 READER — Provenance / Licensing (V19 dimension, split out of EN4)

You score ONE task bundle against EN5 ONLY. You have NO other task in context and
MUST NOT reason by analogy to any other task, case, or version. Decide from THIS
bundle's files that you OPEN AND READ. Every verdict cites file:line or an exact
value. If you did not read it, you cannot score it.

NAMING: this is the OFFICIAL V19 "Provenance / Licensing" dimension. It has
nothing to do with "Leftover Harness/Seeder Endpoint Exposure" -- a different,
unrelated check that some tools/skills also label "EN5" under an older rubric
version. Do not import that concept here.

Calibration: a false FAIL/REVIEW is acceptable; a MISSED fail is not. When reading
leaves you unsure, return REVIEW. Never a vacuous PASS.

V19's bar is a TWO-TIER one (this is the key difference from the old EN4-era
rule, which only had a single flat FAIL):

  [Fail - Provenance / Licensing]  (score 2)
    - A component is not properly attributed ANYWHERE in the task files (not
      just missing from NOTICE.md -- missing everywhere), OR
    - A component cannot legally be used for commercial purposes, OR
    - NOTICE.md attributes the WRONG license (its stated license family
      contradicts the component's own source -- e.g. a wheel's own
      .dist-info/METADATA says MPL-2.0 but NOTICE blankets it as MIT; a
      copyleft base image stated as permissive). A wrong attribution is a
      FAIL, never downgradeable to Non-Fail -- "credited elsewhere" means
      correctly credited, not merely mentioned.

  [Non-Fail - Provenance / Licensing]  (score 3)
    - A component is missing from NOTICE.md specifically, but IS credited
      correctly somewhere ELSE in the task files (a vendored LICENSE file, a
      requirements.txt comment, a Dockerfile comment, etc.). Confirm the
      "elsewhere" citation the finder points at is a REAL license statement
      naming this exact component -- not a coincidental name match, and not a
      NESTED environment/<app>/NOTICE.md pretending to be the authoritative
      top-level notice (only the TOP-LEVEL environment/NOTICE.md counts as
      "NOTICE.md" for the Fail/clean split; a nested one is just "elsewhere").

  PASS (score 5)
    - Every third-party component (every base image, every vendored wheel,
      every OS package installed via apt-get/apk in any Dockerfile) is
      properly licensed within the top-level NOTICE.md.

Read, don't skim: open the top-level NOTICE.md, every Dockerfile (for both the
image FROM line and any apt-get/apk install block), the compose file's image:
lines, and each vendored wheel's own .dist-info/METADATA. Confirm or clear each
finder candidate by reading; first-party (self-written) code never needs
provenance.

## Output contract — return EXACTLY this JSON, nothing else:
{
  "dimension": "EN5",
  "verdicts": [
    {"component": "<image ref / wheel file / OS package name>",
     "verdict": "FAIL" | "NON-FAIL" | "PASS" | "REVIEW",
     "citations": [{"file": "<rel path>", "line": <int|null>, "quote": "<exact text/value>"}],
     "reason": "<one sentence, grounded in what you read; names NO other task>"}
  ],
  "en5_score": 2 | 3 | 5,   // 2 if any component is FAIL; else 3 if any is NON-FAIL; else 5
  "open_items": ["<REVIEW items a human must still settle>"]
}
""".strip()


def build_reader_packet(task_dir):
    found = en5_finder.find(task_dir)
    pv = found["checks"]["provenance_licensing"]
    files = {found["notice"]["path"]: {"for": ["all components"]}}
    for f in pv.get("files_to_read", []):
        files.setdefault(f, {"for": []})["for"].append(pv["label"])
    return {
        "rulebook": RULEBOOK,
        "task_dir": found["task_dir"],
        "notice": found["notice"],
        "images": found["images"],
        "wheel_count": found["wheel_count"],
        "os_package_count": found["os_package_count"],
        "files_to_open": files,
        "finder_candidates": found["checks"],
        "instructions": "Open every file in files_to_open and READ it (for wheels, read the "
                        "dist-info/METADATA inside the .whl; for OS packages, read the "
                        "Dockerfile's install line + the NOTICE for coverage). For each "
                        "non_fail_candidate, open the cited 'credited at' file:line and confirm "
                        "it is real. Return the JSON in the rulebook's output contract.",
    }


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: en5_reader.py <task_dir> [--json OUT]", file=sys.stderr)
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
    print(f"# NOTICE present: {pkt['notice']['present']}  images: {len(pkt['images'])}  "
          f"wheels: {pkt['wheel_count']}  OS packages: {pkt['os_package_count']}")
    print(f"# OPEN AND READ these {len(pkt['files_to_open'])} files (+ each wheel's METADATA):")
    for f in sorted(pkt["files_to_open"]):
        print(f"#   {f}")
    pv = pkt["finder_candidates"]["provenance_licensing"]
    print(f"# finder leads: fail={len(pv['fail_candidates'])} "
          f"non_fail={len(pv['non_fail_candidates'])} review={len(pv.get('review', []))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
