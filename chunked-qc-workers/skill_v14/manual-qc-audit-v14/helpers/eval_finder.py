#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eval_finder.py  --  static FINDER for the EVALUATION remainder (EV1, EV5).

  EV1 Anti-Cheat Order  [Fail - Vacuous Anti-Cheat]: there must be an endpoint/technique match
      that GATES the reward, running BEFORE any ground-truth re-derivation / golden exploit.
      Static lead: is a technique/endpoint gate present in the reward path?
  EV5 Pass@5 Difficulty [Fail - Difficulty Too Low]: 5/5 solves (too easy), <3 non-errored
      trials, or no genuine non-solve. DEFERRED pre-pass@k; post-pass@k reads the shipped trials.

Usage:  python3 -I eval_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io

_GATE_RE = re.compile(r"technique|_INTENDED|_is_decoy|endpoint.*match|match\(.*path|validate_behavior|"
                      r"intended[_-]?path|credited|proof_valid", re.I)
_REDERIVE_RE = re.compile(r"golden|re-?deriv|ground[_-]?truth|reference.?solv", re.I)


def _read(p):
    try:
        return io.open(p, "r", encoding="utf-8", errors="replace").read()
    except Exception:
        return ""


def _ev1(task_dir):
    files = [f for f in ("tests/test.sh", "tests/behavior/verify.py", "tests/behavior/check.py")
             if os.path.exists(os.path.join(task_dir, f))]
    gate = False
    rederive = False
    for rel in files:
        t = _read(os.path.join(task_dir, rel))
        if _GATE_RE.search(t):
            gate = True
        if _REDERIVE_RE.search(t):
            rederive = True
    cands = []
    if files and not gate:
        cands.append({"why": "no endpoint/technique match gating the reward found — anti-cheat may be vacuous"})
    return {"label": "[Fail - Vacuous Anti-Cheat]", "technique_gate_present": gate,
            "rederivation_present": rederive, "candidates": cands, "files_to_read": files,
            "note": "reader confirms the technique/endpoint gate runs BEFORE any golden re-derivation."}


def _ev5(task_dir):
    trials_dir = os.path.join(task_dir, "trajectories", "pass@k", "trials")
    alt = os.path.join(task_dir, "trajectories", "pass@k")
    base = trials_dir if os.path.isdir(trials_dir) else alt
    if not os.path.isdir(base):
        return {"label": "[Fail - Difficulty Too Low]", "status": "DEFERRED",
                "note": "no pass@k shipped — EV5 is DEFERRED pre-pass@k (never fail here).",
                "files_to_read": []}
    rewards, errored = [], 0
    trial_dirs = [os.path.join(base, d) for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
    for td in trial_dirs:
        rp = None
        for cand in ("verifier/reward.txt", "reward.txt", "verifier/reward.json"):
            p = os.path.join(td, cand)
            if os.path.exists(p):
                rp = p; break
        if not rp:
            errored += 1; continue
        t = _read(rp).strip()
        m = re.search(r"-?\d+", t)
        rewards.append(int(m.group(0)) if m else None)
    solves = sum(1 for r in rewards if r == 1)
    non_errored = len([r for r in rewards if r is not None])
    cands = []
    if non_errored and solves == non_errored and non_errored >= 5:
        cands.append({"why": f"{solves}/{non_errored} trials solve — difficulty too low (model solves every trial)"})
    if non_errored < 3:
        cands.append({"why": f"only {non_errored} non-errored trials (<3 required)"})
    return {"label": "[Fail - Difficulty Too Low]", "status": "POST-PASS@K",
            "trials": len(trial_dirs), "solves": solves, "non_errored": non_errored,
            "candidates": cands,
            "files_to_read": ["trajectories/pass@k/"],
            "note": "reader verifies >=1 GENUINE non-solve (engaged the target, not a refusal/infra abort) "
                    "and the tier is recorded."}


def find(task_dir):
    return {"task_dir": os.path.abspath(task_dir),
            "checks": {"ev1_anticheat": _ev1(task_dir), "ev5_difficulty": _ev5(task_dir)}}


def _summary(r):
    e1 = r["checks"]["ev1_anticheat"]; e5 = r["checks"]["ev5_difficulty"]
    o = [f"EVALUATION FINDER (EV1/EV5) — {r['task_dir']}",
         f"  EV1 technique_gate={e1['technique_gate_present']} rederive={e1['rederivation_present']} candidates={len(e1['candidates'])}"]
    for c in e1["candidates"]:
        o.append(f"     FAIL?  {c['why']}")
    o.append(f"  EV5 status={e5.get('status')} " + (f"solves={e5.get('solves')}/{e5.get('non_errored')} candidates={len(e5.get('candidates',[]))}" if e5.get('status') == 'POST-PASS@K' else "(DEFERRED)"))
    for c in e5.get("candidates", []):
        o.append(f"     FAIL?  {c['why']}")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: eval_finder.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    r = find(argv[0])
    if "--json" in argv:
        json.dump(r, open(argv[argv.index("--json")+1], "w"), indent=2)
    print(_summary(r)); return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
