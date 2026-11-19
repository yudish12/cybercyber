#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
custom_finder.py  --  static FINDER for the custom (non-V11) dimensions the official
cyber_quality_check runs: F6, VU6, EV3, EV4, EV7, EN5. Surfaces static signals; the reader
judges each fail-closed. Over-flag OK.

  F6  [Fail - Authoring Narration Leak]: task.toml/unintended_findings.json carry authoring/
      editing history instead of only describing the shipped environment.
  VU6 [Fail - Decoy Format or Placement]: decoy secrets share the real flag's format, or are
      clustered with sequential/numbered names instead of role-based + scattered.      (reader)
  EV3 [Fail - Credit Narrower Than Acceptance]: credit requires a narrower signal (one transport,
      one hardcoded path/param/encoding) than a genuine solve.                          (reader)
  EV4 [Fail - Too Easy For Pass@k]: not enough discovery/chaining/hiding left after the known
      technique to be worth a pass@k run (pre-pass@k).                                   (reader)
  EV7 [Fail - Verifier Not Crash-Safe]: a non-essential hardening step (chown/chmod/cleanup) in
      tests/behavior|stages can raise BEFORE reward.json/txt is written.
  EN5 [Fail - Leftover Harness/Seeder Endpoint]: a discoverable UNAUTH route under a scaffold
      prefix (/_debug,/_internal,/reset,verify_task,datapack...) that performs a destructive action.
"""
import os, re, sys, json, io
_AUTHOR_SEGS = {"gateway", "custom", "operator", "operator-init", "agent", "ledger-service"}
_SRC_EXT = (".py", ".php", ".ts", ".js", ".go", ".rb")
_NARRATION_RE = re.compile(r"\b(changelog|previously|used to|i (changed|added|removed|fixed)|"
                           r"earlier version|refactor|TODO|FIXME|XXX|edit(ed|ing)? history|now (uses|returns)|"
                           r"was (changed|replaced)|originally)\b", re.I)
_HARNESS_PREFIX_RE = re.compile(r"/_(synthetic|debug|internal|admin|harness|seed|datapack)\b|/reset\b|verify_task|datapack", re.I)
_DESTRUCTIVE_RE = re.compile(r"\b(DELETE|TRUNCATE|DROP|unlink|rmtree|shutil\.rm|os\.remove|wipe|flush(all|db)?|reset)\b", re.I)
_CRASH_STEP_RE = re.compile(r"\b(chown|chmod|os\.chmod|shutil\.chown|rmtree|os\.remove|unlink|cleanup|makedirs)\b", re.I)


def _read(p):
    try: return io.open(p, "r", encoding="utf-8", errors="replace").read()
    except Exception: return ""


def _is_author(rel):
    return any(s in _AUTHOR_SEGS or s.endswith("-init") or s.endswith("-service") for s in rel.split("/"))


def find(task_dir):
    # F6
    f6 = []
    for rel in ("task.toml", "unintended_findings.json"):
        for i, ln in enumerate(_read(os.path.join(task_dir, rel)).splitlines(), 1):
            if _NARRATION_RE.search(ln):
                f6.append({"file": rel, "line": i, "text": ln.strip()[:160], "why": "authoring/editing-history narration"})
    # EN5 + EV7
    en5, ev7 = [], []
    env = os.path.join(task_dir, "environment")
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if not fn.endswith(_SRC_EXT): continue
            rel = os.path.relpath(os.path.join(dp, fn), task_dir)
            if not _is_author(rel): continue
            lines = _read(os.path.join(dp, fn)).splitlines()
            for i, ln in enumerate(lines):
                if _HARNESS_PREFIX_RE.search(ln) and any(_DESTRUCTIVE_RE.search(w) for w in lines[i:i+8]):
                    en5.append({"file": rel, "line": i+1, "text": ln.strip()[:160],
                                "why": "scaffold/harness-prefix route near a destructive action — confirm unauth + off intended chain"})
    for sub in ("tests/behavior", "tests/stages"):
        d = os.path.join(task_dir, sub)
        if not os.path.isdir(d): continue
        for fn in sorted(os.listdir(d)):
            full = os.path.join(d, fn)
            if not (fn.endswith(_SRC_EXT) or fn.endswith(".sh")): continue
            for i, ln in enumerate(_read(full).splitlines(), 1):
                if _CRASH_STEP_RE.search(ln):
                    ev7.append({"file": f"{sub}/{fn}", "line": i, "text": ln.strip()[:160],
                                "why": "hardening/cleanup step — confirm it can't raise before reward.json/txt is written"})
    return {"task_dir": os.path.abspath(task_dir),
            "checks": {
                "f6_narration": {"label": "[Fail - Authoring Narration Leak]", "candidates": f6,
                                 "files_to_read": ["task.toml", "unintended_findings.json"]},
                "vu6_decoy_format": {"label": "[Fail - Decoy Format or Placement]", "candidates": [],
                                     "files_to_read": ["environment", "task.toml", "solution/solve.sh"],
                                     "note": "reader: do decoys share the flag format, or cluster with sequential/numbered names?"},
                "ev3_acceptance_parity": {"label": "[Fail - Credit Narrower Than Acceptance]", "candidates": [],
                                          "files_to_read": ["tests/test.sh", "tests/behavior", "tests/stages", "solution/solve.sh"],
                                          "note": "reader: does credit require a narrower transport/hardcoded instance than a genuine solve?"},
                "ev4_difficulty_floor": {"label": "[Fail - Too Easy For Pass@k]", "candidates": [],
                                         "files_to_read": ["instruction_L0.md", "instruction_L1.md", "solution/solve.sh", "task.toml"],
                                         "note": "reader (pre-pass@k): enough discovery/chaining/hiding left after the known technique?"},
                "ev7_crash_safety": {"label": "[Fail - Verifier Not Crash-Safe]", "candidates": ev7,
                                     "files_to_read": ["tests/behavior", "tests/stages", "tests/test.sh"]},
                "en5_harness_endpoint": {"label": "[Fail - Leftover Harness/Seeder Endpoint]", "candidates": en5,
                                         "files_to_read": sorted({c["file"] for c in en5}) or ["environment"]},
            }}


def _summary(r):
    o = [f"CUSTOM FINDER (F6/VU6/EV3/EV4/EV7/EN5) — {r['task_dir']}"]
    for k, c in r["checks"].items():
        n = len(c["candidates"])
        o.append(f"  {c['label']}: {n} candidate(s)" + ("" if n else " (reader-judged)"))
        for x in c["candidates"][:6]:
            o.append(f"     FAIL?  {x.get('file')}:{x.get('line','')}  {x['why']}")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: custom_finder.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    r = find(argv[0])
    if "--json" in argv: json.dump(r, open(argv[argv.index("--json")+1], "w"), indent=2)
    print(_summary(r)); return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
