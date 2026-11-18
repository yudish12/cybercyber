#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rb1_finder.py  --  static FINDER layer of the RB1 eval
(Evaluation: Staged-Rubric Quality).

READ-ONLY. It POINTS; the reader decides. RB1 is heavily semantic, so the finder
is mostly coverage + signals:

  * FP-KILLER: confirm tests/stages/rubric.toml and the stage code EXIST and are
    readable, with paths. The documented RB1 false positive is a judge that never
    received tests/stages/ and so reports "rubric.toml not present". The finder
    records the real path so that verdict is refutable with a citation.
  * intended-path modeled: parse the staged rubric; there must be a
    technique_fidelity/outcome stage on the scored step. A process-only rubric is a
    candidate for [Fail - Intended-Path Not Modeled].
  * spoofable signals: stage code that reads the report/trajectory/narration text, or
    does whole-trajectory substring credit, is SURFACED for the reader. It is NOT
    auto-failed -- a comment that says narration is NOT used must be cleared by reading.
  * reward gating: reward wiring that derives the OFFICIAL reward from the rubric/stage
    score is surfaced ([Fail - Spoofable or Gating Rubric], gating half).

Usage:  python3 -I rb1_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io

_NARRATION_RE = re.compile(
    r"report\.md|report_text|\btrajectory\b|transcript|narration|\.pane\b|stdout|agent[_-]?output", re.I)
_SUBSTRING_CREDIT_RE = re.compile(
    r"in\s+open\(|\.read\(\)|[\"'][^\"']+[\"']\s+in\s+\w*(report|trajectory|transcript|text|output)"
    r"|\bin\s+(trajectory|transcript|report)\b", re.I)
_GATE_RE = re.compile(
    r"reward\s*=\s*\$?\{?score|reward\b.*\b(stage|rubric)\b|\bscore\s*=.*run_stages"
    r"|reward\.(txt|json).*\$?\{?score", re.I)
_PY = (".py",)


def _read(p):
    try:
        with io.open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _stage_files(task_dir):
    """All stage/behavior python + the stage shell runners."""
    out = []
    for sub in ("tests/stages", "tests/behavior", "tests/report"):
        d = os.path.join(task_dir, sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            full = os.path.join(d, fn)
            if os.path.isfile(full) and (fn.endswith(_PY) or fn.endswith(".sh")):
                out.append(os.path.relpath(full, task_dir))
    return out


def _find_rubric(task_dir):
    p = os.path.join(task_dir, "tests", "stages", "rubric.toml")
    present = os.path.exists(p)
    return {"present": present, "path": "tests/stages/rubric.toml" if present else None,
            "abs": p if present else None}


def _parse_stages(task_dir, rubric):
    if not rubric["present"]:
        return []
    text = _read(rubric["abs"])
    stages = []
    try:
        import tomllib
        data = tomllib.loads(text)
        for s in data.get("stage", []):
            stages.append({"id": s.get("id") or s.get("stage_name"),
                           "category": (s.get("category") or "").lower(),
                           "weight": s.get("weight"),
                           "criterion": s.get("criterion", "")})
    except Exception:
        # regex fallback
        for blk in re.split(r"\[\[stage\]\]", text)[1:]:
            idm = re.search(r'id\s*=\s*"([^"]+)"', blk)
            cm = re.search(r'category\s*=\s*"([^"]+)"', blk)
            crm = re.search(r'criterion\s*=\s*"([^"]*)"', blk)
            stages.append({"id": idm.group(1) if idm else None,
                           "category": (cm.group(1).lower() if cm else ""),
                           "weight": None,
                           "criterion": crm.group(1) if crm else ""})
    return stages


def _intended_path(stages):
    cats = sorted({s["category"] for s in stages if s["category"]})
    modeled = any(c in ("technique_fidelity", "outcome") for c in cats)
    cands = []
    if stages and not modeled:
        cands.append({"issue": "no technique_fidelity/outcome stage — a solving and a "
                               "non-solving trial may be indistinguishable on the scored step",
                      "categories": cats})
    if not stages:
        cands.append({"issue": "no parseable [[stage]] entries in the staged rubric"})
    return {"label": "[Fail - Intended-Path Not Modeled]", "modeled": modeled,
            "categories": cats, "candidates": cands}


def _spoofable(task_dir, files):
    sigs = []
    for rel in files:
        if not rel.endswith(_PY):
            continue
        for i, line in enumerate(_read(os.path.join(task_dir, rel)).splitlines(), 1):
            narr = _NARRATION_RE.search(line)
            sub = _SUBSTRING_CREDIT_RE.search(line)
            if narr or sub:
                why = []
                if narr:
                    why.append(f"references {narr.group(0)!r}")
                if sub:
                    why.append("whole-text substring/read credit")
                sigs.append({"file": rel, "line": i, "text": line.strip()[:180],
                             "why": "; ".join(why)})
    return {"label": "[Fail - Spoofable or Gating Rubric] (spoof half)",
            "signals": sigs,
            "files_to_read": files,
            "note": "reader confirms each: is the decisive stage credited from protected/observable "
                    "evidence (endpoint+response, audit events) or from narration/substring? A comment "
                    "disclaiming narration use is NOT a fail."}


def _reward_gating(task_dir, files):
    sigs = []
    targets = [f for f in files if f.endswith(".sh")] + \
              [f for f in ("tests/behavior/verify.py", "tests/test.sh") if os.path.exists(os.path.join(task_dir, f))]
    for rel in dict.fromkeys(targets):
        for i, line in enumerate(_read(os.path.join(task_dir, rel)).splitlines(), 1):
            if _GATE_RE.search(line):
                sigs.append({"file": rel, "line": i, "text": line.strip()[:180]})
    return {"label": "[Fail - Spoofable or Gating Rubric] (gating half)",
            "signals": sigs,
            "files_to_read": list(dict.fromkeys(targets)),
            "note": "reader confirms the OFFICIAL reward comes from the exploit/behavior check, "
                    "not from the staged-rubric score."}


def find(task_dir):
    rubric = _find_rubric(task_dir)
    files = _stage_files(task_dir)
    stages = _parse_stages(task_dir, rubric)
    reader_files = ([rubric["path"]] if rubric["present"] else []) + files
    return {
        "task_dir": os.path.abspath(task_dir),
        "rubric": {"present": rubric["present"], "path": rubric["path"]},
        "stage_files": files,
        "stage_count": len(stages),
        "checks": {
            "intended_path": _intended_path(stages),
            "spoofable": _spoofable(task_dir, reader_files),
            "reward_gating": _reward_gating(task_dir, files),
        },
    }


def _summary(r):
    o = [f"RB1 FINDER — {r['task_dir']}",
         f"  stages/rubric.toml present: {r['rubric']['present']}  ({r['rubric']['path']})",
         f"  stages parsed: {r['stage_count']}  stage/behavior files: {len(r['stage_files'])}"]
    ip = r["checks"]["intended_path"]
    o.append(f"  [Intended-Path Not Modeled] modeled={ip['modeled']}  categories={ip['categories']}")
    for c in ip["candidates"]:
        o.append(f"     CANDIDATE  {c['issue']}")
    sp = r["checks"]["spoofable"]
    o.append(f"  [Spoofable] signals={len(sp['signals'])} (reader confirms)")
    for s in sp["signals"][:15]:
        o.append(f"     signal {s['file']}:{s['line']}  {s['why']}  — {s['text']}")
    rg = r["checks"]["reward_gating"]
    o.append(f"  [Gating] signals={len(rg['signals'])}")
    for s in rg["signals"][:10]:
        o.append(f"     GATE?  {s['file']}:{s['line']}  — {s['text']}")
    o.append("  NOTE: finder points. The reader opens rubric.toml + the stage code + the reward wiring and decides.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: rb1_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
