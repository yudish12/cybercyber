#!/usr/bin/env python3
"""
Emit the exact `args` JSON for the qc-audit Workflow call.

Usage:
  make_args.py --pack pack.json --label NAME [--task-root DIR] [--dims 3,5,7,8,19]

Prints a single JSON object. Paste it as the Workflow tool's `args`.
Dimensions 22/24 are included automatically only when the pack carries form fields.
"""
import json, os, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
# Single source of truth. The same fact used to live in four places (tiers.json,
# JUDGMENT_DEFAULT, report.NOT_ASSESSABLE, workflow.js's fallback) and one had already
# drifted: dimension 14 is scored mechanically, but the workflow still sent it to an agent.
_TIERS = {int(k): v for k, v in json.load(open(os.path.join(HERE, "tiers.json"))).items()}
JUDGMENT_DEFAULT = sorted(i for i, t in _TIERS.items() if t == "judgment")
FORM_DIMS = sorted(i for i, t in _TIERS.items() if t == "form-field")
HIGH_RISK = [4, 14, 15, 16, 23, 24, 27, 28, 29]  # BR: F4, VU3, VU4, VU5, EV2, EV3, EV6, RB1(behavior-catalog), RB2(report-rubric) -- EV*/RB* shifted +1 by TR5 insertion at _id 21


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", required=True)
    ap.add_argument("--task-root", default=None,
                    help="defaults to the task_root recorded in the pack")
    ap.add_argument("--label", required=True)
    ap.add_argument("--dims", default=None, help="comma-separated dimension ids")
    a = ap.parse_args()

    rubric = json.load(open(os.path.join(HERE, "rubric.json")))
    pack = json.load(open(a.pack))
    task_root = a.task_root or pack.get("task_root")
    if not task_root:
        raise SystemExit("no --task-root given and pack has no task_root")
    if not os.path.isdir(task_root):
        raise SystemExit(f"taskRoot {task_root} does not exist. Every judgment agent would "
                         "be pointed at a dead path and would score from the pack alone.")
    ff = (pack.get("evidence") or {}).get("form_fields") or {}
    # D22 needs the Vulnerability Type radio; D24 needs the three explanation
    # fields. One all-or-nothing boolean let a dimension be scored with its own
    # input absent.
    has_d22 = "vulnerability_type" in ff
    has_d24 = any(k in ff for k in ("vulnerability_explanation",
                                    "complexity_increase", "model_failure_reason"))

    if a.dims:
        try:
            dims = [int(x) for x in a.dims.split(",") if x.strip()]
        except ValueError:
            raise SystemExit(f"--dims must be comma-separated integers, got {a.dims!r}")
        valid = {d["_id"] for d in rubric}
        unknown = [d for d in dims if d not in valid]
        if unknown:
            raise SystemExit(f"--dims contains ids not in the rubric: {unknown} "
                             f"(valid ids are 1-{max(valid)})")
    else:
        dims = list(JUDGMENT_DEFAULT)
        dims += [i for i in FORM_DIMS if (has_d22 if i == 22 else has_d24)]

    # Every mechanically-scored dimension also gets an INDEPENDENT agent read, so a
    # regex that silently did not fire cannot masquerade as a verified pass.
    confirm = sorted(i for i, t in _TIERS.items() if t == "deterministic")
    sel = [{"_id": d["_id"], "title": d["title"], "question": d["question"],
            "description": d["description"], "options": d["options"]}
           for d in rubric if d["_id"] in set(dims) | set(confirm)]

    args = {
        "tasks": [{"label": a.label,
                   "packPath": os.path.abspath(a.pack),
                   "taskRoot": os.path.abspath(task_root)}],
        "dims": dims,
        "rubric": sel,
        "confirmDims": confirm,
        "highRisk": HIGH_RISK,
        # absolute so the workflow's prompts resolve regardless of cwd
        "refDir": os.path.join(HERE, "references"),
    }
    print(json.dumps(args))


if __name__ == "__main__":
    main()
