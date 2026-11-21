#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
format_reader.py  --  READER for the FORMAT group (F1-F5).

Format is mostly mechanical, so the reader confirms the finder's candidates and settles the
few judgment bits by reading: F3 (does the marker prefix imply the class?), F4 (do cwe/kind/
name match what solve.sh actually exploits?), F5 (is exploit narration in the agent-readable
tree?). Fenced + de-anecdoted like every worker.

Usage:  python3 -I format_reader.py <task_dir> [--json OUT]
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import format_finder

RULEBOOK = r"""
# FORMAT READER — F1-F5 (V14 dimensions 1-5)

You score ONE task bundle against the FORMAT dimensions ONLY. No other task is in context;
do not compare to any other task. Decide from THIS bundle's files that you OPEN AND READ.
Cite file:line. A LITERAL structural fail (a missing file, a wrong value) is a FAIL even if
"it works anyway" — the rubric pins these to specific files.

Confirm each finder candidate by reading, and settle the judgment bits:

F1 [Fail - Required Structure]: every required file present, non-empty, parseable, and each
   script executable (shebang or +x). (pass@k trajectory presence is DEFERRED pre-pass@k.)
F2 Compose Contract — FAIL on ANY of: no service named exactly `main`; a static host:container
   port mapping (`[Fail - Static Ports/IPs]`); `main` declaring its own `networks:` (`[Fail - Sidecar
   Network Conflict]`); `main` setting shorthand `cpus`/`mem_limit`/`pids_limit` (`[Fail - Compose
   Shorthand/Long-Form Resource Conflict]`); `task.toml` `network_mode="no-network"` with other
   in-compose services (`[Fail - No-Network Blocks In-Compose Target]`); `[agent].timeout_sec` != 36000;
   `[environment].cpus` != 2. A pinned subnet/IP literal is REVIEW (confirm vs Docker's pool).
F3 Flag/Marker Format:
   - [Fail - Prefix Vulnerability Leakage]: the marker prefix names/implies the vuln class
     (e.g. SQLI_FLAG=, IDOR_FLAG=).
   - [Fail - Flag Consistency]: the marker format string differs across instruction.md and
     the three tiers.
F4 [Fail - Metadata Consistency]: read solve.sh/solve.py — do `cwe`, `vulnerability_kind`,
   `[task] name`, and the archive name all match the vulnerability the solve actually
   exploits? A right-family-but-imprecise CWE is a score-3 Non-Fail, not a fail.
F5 [Fail - Packaging Hygiene]: a base image uses a mutable tag (no digest); `task.toml`
   omits a non-root `[agent] user`; `fresh_state.json` missing/invalid; OR exploit narration
   lives in the agent-readable tree (it belongs in operator/, not where the agent can read).

## Output contract — return EXACTLY this JSON, nothing else:
{
  "group": "FORMAT",
  "verdicts": [
    {"dimension": "F1|F2|F3|F4|F5",
     "verdict": "FAIL" | "PASS" | "REVIEW" | "NON_FAIL_3" | "DEFERRED",
     "citations": [{"file": "<rel>", "line": <int|null>, "quote": "<exact>"}],
     "reason": "<one sentence; names NO other task>"}
  ],
  "format_score": 2 | 3 | 5,   // 2 if any FAIL; else 3 if an imprecise-CWE Non-Fail; else 5
  "open_items": ["<DEFERRED pass@k items / anything to confirm>"]
}
""".strip()


def build_reader_packet(task_dir):
    found = format_finder.find(task_dir)
    files = {}
    for ch in found["checks"].values():
        for f in ch.get("files_to_read", []):
            files.setdefault(f, {"abs": os.path.join(found["task_dir"], f), "for": []})["for"].append(ch["label"])
    return {
        "rulebook": RULEBOOK,
        "task_dir": found["task_dir"],
        "finder_candidates": found["checks"],
        "files_to_open": files,
        "instructions": "Open each required file, the tiers, the compose file, and solve.sh and READ them. "
                        "Confirm the finder candidates and settle F3/F4/F5 judgment bits. Return the JSON "
                        "in the rulebook's output contract.",
    }


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: format_reader.py <task_dir> [--json OUT]", file=sys.stderr)
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
    tot = sum(len(c["candidates"]) for c in pkt["finder_candidates"].values())
    print(f"# finder candidates across F1-F5: {tot}")
    print(f"# OPEN AND READ these {len(pkt['files_to_open'])} files:")
    for f in sorted(pkt["files_to_open"]):
        print(f"#   {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
