#!/usr/bin/env python3
"""
Compare auditor output against the human-auditor ground truth.

Usage:
  calibrate.py --packs DIR --verdicts workflow_verdicts.json [--ground ground_truth.json]

Merges the deterministic verdicts (from each evidence pack) with the judgment
verdicts (from the workflow) and scores them against ground_truth.json.
Exit code 0 only if every labelled verdict matches.
"""
import json, os, glob, argparse, sys

LABEL_TO_ATTEMPT = {
    "A_sqli_pass":       "6aa46932df3c3e50b8e623a0",
    "B_traversal_pass":  "6aa52b72b5404a42e0b59012",
    "C_massassign_pass": "6aa56882b52c541c627ec38f",
    "D_sqli_FAIL":       "6aa58cc5246730f172ea4875",
    # Scored by a human under the 23-dimension sheet that preceded V6. Every one of
    # those 23 survives into V6 verbatim, so all of them count for these two and no
    # comparability filter applies. V6's new dimension 23 has no human verdict.
    "6aa0578411b328360a727688": "6aa0578411b328360a727688",
    "6aa4219af13d451666f8427f": "6aa4219af13d451666f8427f",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packs", required=True)
    ap.add_argument("--verdicts", required=True)
    ap.add_argument("--ground", default=os.path.join(os.path.dirname(__file__), "ground_truth.json"))
    a = ap.parse_args()

    ground = json.load(open(a.ground))
    # The 56 labelled verdicts were scored under the older 16-dimension rubric. The
    # current sheet changed or added 13 dimensions. Only dimensions whose text is
    # IDENTICAL in both can still be validated against them; the rest are reported as
    # UNCALIBRATED, not as passes.
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        v4 = json.load(open(os.path.join(here, "rubric.json")))
        v2 = {d["id"]: d for d in json.load(open(os.path.join(here, "rubric.v2.json")))}
        # rubric.json carries extra per-option keys (requires_justification) that
        # rubric.v2.json predates; compare only the scored text, not the whole object.
        # rubric.json carries extra per-option keys (requires_justification) that
        # rubric.v2.json predates, and v2 was stored with newlines collapsed to
        # spaces. Compare only the scored text, whitespace-normalised.
        norm = lambda t: " ".join(t.split())
        opt = lambda d: [(norm(o["text"]), o["score"]) for o in d["options"]]
        comparable = {d["title"] for d in v4 if d["id"] in v2
                      and norm(v2[d["id"]]["description"]) == norm(d["description"])
                      and opt(v2[d["id"]]) == opt(d)}
    except Exception:
        comparable = None
    wf = json.load(open(a.verdicts))
    jv = wf.get("verdicts", wf) if isinstance(wf, dict) else wf

    # predicted[label][title] = score
    predicted = {}
    for f in sorted(glob.glob(os.path.join(a.packs, "*.json"))):
        label = os.path.basename(f)[:-5]
        pack = json.load(open(f))
        predicted.setdefault(label, {})
        for d in pack.get("deterministic", []):
            predicted[label][d["title"]] = {"score": d["score"], "src": "deterministic",
                                            "option": d["option"], "why": d.get("evidence")}
    for v in jv:
        predicted.setdefault(v["task"], {})[v["title"]] = {
            "score": v["final_score"], "src": "judgment",
            "option": v.get("final_option"), "why": v.get("justification"),
            "initial": v.get("initial_score"), "verification": v.get("verification")}

    rows, wrong = [], []
    for att, g in ground.items():
        label = next((k for k, v in LABEL_TO_ATTEMPT.items() if v == att), None)
        if not label:
            continue
        # An attempt scored under the current sheet needs no comparability filter:
        # every one of its 23 verdicts is directly checkable.
        current = g.get("rubric") in ("current-23dim", "human-23dim-pre-v6")
        for comp in g["components"]:
            title, exp = comp["component"], comp["score"]
            if not current and comparable is not None and title not in comparable:
                rows.append((label, title, exp, None, "UNCALIBRATED", True))
                continue
            p = predicted.get(label, {}).get(title)
            got = p["score"] if p else None
            ok = (got == exp)
            rows.append((label, title, exp, got, p["src"] if p else "MISSING", ok))
            if not ok:
                wrong.append((label, title, exp, got, p))

    det = [r for r in rows if r[4] == "deterministic"]
    jud = [r for r in rows if r[4] == "judgment"]
    miss = [r for r in rows if r[4] == "MISSING"]
    unc = [r for r in rows if r[4] == "UNCALIBRATED"]

    print("=" * 96)
    print("CALIBRATION vs HUMAN AUDITOR GROUND TRUTH")
    print("=" * 96)
    cur = None
    for label, title, exp, got, src, ok in rows:
        if label != cur:
            cur = label
            print(f"\n── {label} " + "─" * (88 - len(label)))
        mark = "-- " if src == "UNCALIBRATED" else ("OK " if ok else "XX ")
        print(f"  {mark} exp={exp}/5 got={str(got):>4}  [{src[:11]:<11}] {title}")

    scored_rows = [r for r in rows if r[4] != "UNCALIBRATED"]
    n, good = len(scored_rows), sum(1 for r in scored_rows if r[5])
    print("\n" + "=" * 96)
    print(f"  deterministic : {sum(1 for r in det if r[5])}/{len(det)}")
    print(f"  judgment      : {sum(1 for r in jud if r[5])}/{len(jud)}")
    if miss:
        print(f"  MISSING       : {len(miss)}  -> {[ (r[0], r[1]) for r in miss ][:6]}")
    if unc:
        print(f"  UNCALIBRATED  : {len(unc)}  (the current sheet changed/added these; no human verdict exists yet)")
    print(f"  TOTAL SCORED  : {good}/{n}  ({100.0*good/n:.1f}%)  <- comparable dimensions only")
    print("=" * 96)

    if wrong:
        print("\nMISMATCHES:")
        for label, title, exp, got, p in wrong:
            print(f"\n  {label} :: {title}")
            print(f"    expected {exp}/5, got {got}/5   src={p['src'] if p else 'MISSING'}")
            if p:
                if p.get("initial") is not None and p["initial"] != p["score"]:
                    print(f"    (initial {p['initial']}/5, flipped by verification)")
                print(f"    option: {str(p.get('option'))[:150]}")
                print(f"    why:    {str(p.get('why'))[:400]}")
                if p.get("verification"):
                    print(f"    verify: {json.dumps(p['verification'])[:400]}")
    else:
        print("\n  PERFECT — every labelled verdict reproduced.")
    sys.exit(0 if not wrong else 1)


if __name__ == "__main__":
    main()
