#!/usr/bin/env python3
"""
Data-free self-test for the V9 (approach A) qc-audit wiring.

Validates, without any task corpus:
  * rubric.json is the 30-dimension V9 sheet, well-formed (ids, options, categories,
    the required closing sentence on every description).
  * tiers.json covers exactly those ids and only uses tiers A supports.
  * make_args.py emits valid Workflow args: all judgment dims, no deterministic
    confirm tier, the form dim gated on form fields, rubric text verbatim.
  * report.py renders all 30 dimensions and computes PASS / FAIL / NOT ASSESSABLE
    from judgment verdicts alone.

Run:  .venv/bin/python selftest.py
"""
import json, os, re, sys, tempfile, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
CLOSING = "For all options except the last, apply the error category."
fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


def main():
    rubric = json.load(open(os.path.join(HERE, "rubric.json")))
    tiers = {int(k): v for k, v in json.load(open(os.path.join(HERE, "tiers.json"))).items()}

    # ---- rubric structure ----
    check(len(rubric) == 30, f"rubric.json has {len(rubric)} dims, expected 30")
    ids = [d["_id"] for d in rubric]
    check(ids == list(range(1, 31)), f"_id must be 1..30 in order, got {ids}")
    check(len({d["id"] for d in rubric}) == 30, "dimension UUIDs are not unique")
    for d in rubric:
        t = d["title"]
        opts = d["options"]
        check(bool(opts), f"{t}: no options")
        check(opts[-1]["score"] == 5, f"{t}: last option is not the score-5 pass option")
        check(not opts[-1]["text"].lstrip().startswith("[Fail"),
              f"{t}: last option looks like a fail option")
        for o in opts[:-1]:
            check(o["score"] in (2, 3), f"{t}: non-pass option score {o['score']} not in (2,3)")
            check(re.match(r"\[(?:Non-)?Fail - ", o["text"].lstrip()),
                  f"{t}: fail option missing '[Fail - ...]' / '[Non-Fail - ...]' prefix")
        check(d["description"].rstrip().endswith(CLOSING),
              f"{t}: description does not end with the required closing sentence")
        check(bool(d.get("error_categories")), f"{t}: no error_categories")

    # ---- tiers consistency ----
    check(set(tiers) == set(ids), "tiers.json ids do not match rubric ids")
    check(set(tiers.values()) <= {"judgment", "form-field"},
          f"approach A allows only judgment/form-field tiers, got {set(tiers.values())}")
    check(tiers.get(30) == "form-field", "dim 30 (Spam Check) should be form-field")

    # ---- make_args.py: no form fields ----
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "task"); os.makedirs(root)
        pack = {"task_root": root, "deterministic": [], "evidence": {"form_fields": {}}}
        pp = os.path.join(td, "pack.json"); json.dump(pack, open(pp, "w"))
        r = subprocess.run([PY, os.path.join(HERE, "make_args.py"), "--pack", pp,
                            "--label", "selftest"], capture_output=True, text=True)
        check(r.returncode == 0, f"make_args (no fields) failed: {r.stderr.strip()}")
        if r.returncode == 0:
            a = json.loads(r.stdout)
            judg = sorted(i for i, t in tiers.items() if t == "judgment")
            check(a["dims"] == judg, f"dims should be the judgment set {judg}, got {a['dims']}")
            check(a["confirmDims"] == [], f"confirmDims should be empty in approach A, got {a['confirmDims']}")
            check(30 not in a["dims"], "Spam Check (30) must be excluded without form fields")
            check(len(a["rubric"]) == len(set(a["dims"]) | set(a["confirmDims"])),
                  "rubric selection size mismatch")
            titles = {x["title"] for x in a["rubric"]}
            check(any("RB1" in x for x in titles), "RB1 missing from args rubric")

        # ---- make_args.py: with form fields ----
        pack2 = {"task_root": root, "deterministic": [], "evidence": {"form_fields": {
            "vulnerability_type": "SQLi", "vulnerability_explanation": "x",
            "complexity_increase": "y", "model_failure_reason": "z"}}}
        pp2 = os.path.join(td, "pack2.json"); json.dump(pack2, open(pp2, "w"))
        r2 = subprocess.run([PY, os.path.join(HERE, "make_args.py"), "--pack", pp2,
                             "--label", "selftest"], capture_output=True, text=True)
        check(r2.returncode == 0, f"make_args (with fields) failed: {r2.stderr.strip()}")
        if r2.returncode == 0:
            check(30 in json.loads(r2.stdout)["dims"], "Spam Check (30) must be included with form fields")

        # ---- report.py: all-pass verdicts -> PASS, all 29 rows ----
        verd = {"verdicts": [{"task": "selftest", "dimension_id": d["_id"],
                              "title": d["title"], "final_score": 5,
                              "final_option": d["options"][-1]["text"],
                              "justification": "ok", "evidence": ["selftest"]}
                             for d in rubric if tiers[d["_id"]] != "form-field"]}
        vp = os.path.join(td, "verd.json"); json.dump(verd, open(vp, "w"))
        rr = subprocess.run([PY, os.path.join(HERE, "report.py"), "--pack", pp2,
                             "--verdicts", vp, "--label", "selftest", "--relay"],
                            capture_output=True, text=True)
        check(rr.returncode == 0, f"report.py failed: {rr.stderr.strip()}")
        out = rr.stdout
        for d in rubric:
            check(d["title"] in out, f"report relay is missing dimension: {d['title']}")

    if fails:
        print(f"SELFTEST FAILED ({len(fails)} problem(s)):")
        for f in fails:
            print("  -", f)
        sys.exit(1)
    print("SELFTEST PASSED — V9 (approach A) wiring is consistent: 30 dims, tiers, make_args, report.")


if __name__ == "__main__":
    main()
