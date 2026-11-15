#!/usr/bin/env python3
"""Lock rubric.json to the authoritative QC_rubric_V13.csv.

The CSV (references/QC_rubric_V13.csv, the copy shipped inside the
cyber_quality_check tool) is the single source of truth for dimension ids,
titles, question + description text, error categories, answer-option text
and option scores. rubric.json is the scoring
surface the auditor reads. This script fails loudly if they have drifted, so a
stale or hand-edited rubric.json can never silently change a verdict.

Usage:
    python3 helpers/verify_rubric.py            # verify, exit 1 on drift
    python3 helpers/verify_rubric.py --rebuild  # regenerate rubric.json from CSV

Pure stdlib. Run with -I against any untrusted tree.
"""
import csv
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CSV = ROOT / "references" / "QC_rubric_V13.csv"
RUBRIC = ROOT / "rubric.json"


def load_csv(path):
    """Return OrderedDict[id] -> {title, question, description, error_categories, options:[{text,score}]}."""
    dims = OrderedDict()
    cur = None
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            rid = (row.get("id") or "").strip()
            if rid:
                cur = rid
                dims[cur] = {
                    "id": rid,
                    "title": (row.get("title") or "").strip(),
                    "question": (row.get("questionText") or "").strip(),
                    "description": (row.get("questionDescription") or "").strip(),
                    "error_categories": (row.get("errorCategories") or "").strip(),
                    "options": [],
                }
            opt = (row.get("answerOptionText") or "").strip()
            if opt and cur is not None:
                score = (row.get("answerOptionScore") or "").strip()
                try:
                    score = int(score)
                except ValueError:
                    pass
                dims[cur]["options"].append({"text": opt, "score": score})
    return dims


def _norm_title(t):
    # rubric.json drops the {F1} braces the CSV uses; compare on the bare id+name.
    return re.sub(r"[{}]", "", t).strip()


def verify(dims_csv, rubric):
    problems = []
    by_id = {d["id"]: d for d in rubric}
    if len(rubric) != len(dims_csv):
        problems.append(f"dimension count: rubric.json has {len(rubric)}, CSV has {len(dims_csv)}")
    for rid, cd in dims_csv.items():
        rd = by_id.get(rid)
        if rd is None:
            problems.append(f"{rid}: present in CSV, missing from rubric.json")
            continue
        if _norm_title(rd.get("title", "")) != _norm_title(cd["title"]):
            problems.append(f"{rid}: title drift\n    csv:    {cd['title']}\n    rubric: {rd.get('title')}")
        # the prose the auditor actually reads must match too, not just the labels
        for field in ("question", "description", "error_categories"):
            if (rd.get(field) or "").strip() != cd[field]:
                problems.append(f"{rid}: {field} drift\n    csv:    {cd[field][-160:]!r}\n    rubric: {(rd.get(field) or '')[-160:]!r}")
        csv_max = max((o["score"] for o in cd["options"] if isinstance(o["score"], int)), default=None)
        if rd.get("max_score") != csv_max:
            problems.append(f"{rid}: max_score csv={csv_max} rubric={rd.get('max_score')}")
        csv_opts = [(o["text"], o["score"]) for o in cd["options"]]
        rub_opts = [(o["text"], o.get("score")) for o in rd.get("options", [])]
        if len(csv_opts) != len(rub_opts):
            problems.append(f"{rid}: option count csv={len(csv_opts)} rubric={len(rub_opts)}")
        for i, (co, ro) in enumerate(zip(csv_opts, rub_opts)):
            if co[1] != ro[1]:
                problems.append(f"{rid} opt[{i}]: score csv={co[0][:40]!r}->{co[1]} rubric->{ro[1]}")
            # option text: first line (the [Fail - X] label) must match exactly
            if co[0].splitlines()[0].strip() != ro[0].splitlines()[0].strip():
                problems.append(
                    f"{rid} opt[{i}]: label drift\n    csv:    {co[0].splitlines()[0]}\n    rubric: {ro[0].splitlines()[0]}"
                )
    return problems


def rebuild(dims_csv):
    out = []
    for i, (rid, cd) in enumerate(dims_csv.items(), start=1):
        out.append(
            {
                "_id": i,
                "id": rid,
                "title": _norm_title(cd["title"]),
                "question": cd["question"],
                "description": cd["description"],
                "options": [{"text": o["text"], "score": o["score"]} for o in cd["options"]],
                "max_score": max((o["score"] for o in cd["options"] if isinstance(o["score"], int)), default=None),
                "error_categories": cd["error_categories"],
            }
        )
    RUBRIC.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"rebuilt {RUBRIC} from {CSV.name}: {len(out)} dimensions")


def main(argv):
    if not CSV.exists():
        print(f"FATAL: authoritative CSV not found at {CSV}", file=sys.stderr)
        return 2
    dims_csv = load_csv(CSV)
    if "--rebuild" in argv:
        rebuild(dims_csv)
        return 0
    rubric = json.loads(RUBRIC.read_text())
    problems = verify(dims_csv, rubric)
    if problems:
        print("RUBRIC DRIFT — rubric.json does not match the authoritative CSV:\n", file=sys.stderr)
        for p in problems:
            print("  - " + p, file=sys.stderr)
        print("\nRun `python3 helpers/verify_rubric.py --rebuild` to regenerate.", file=sys.stderr)
        return 1
    print(f"rubric.json is LOCKED to {CSV.name}: {len(rubric)} dimensions; titles, question/description text, "
          "error categories, option labels and scores all match.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
