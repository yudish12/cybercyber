#!/usr/bin/env python3
"""TDD tests for eval_finder.py."""
import os, sys, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_finder
def _w(p, c):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(c)
P = F = 0
def ck(n, c):
    global P, F; P += c; F += (not c); print(f"  {'ok  ' if c else 'FAIL'} {n}")
def main():
    dirs = []
    try:
        g = tempfile.mkdtemp(); dirs.append(g); t = os.path.join(g, "task")
        _w(os.path.join(t, "tests/behavior/verify.py"), "proof_valid = validate_behavior_proof(x)\nreward = 1 if proof_valid else 0\n")
        for i in range(5):
            _w(os.path.join(t, f"trajectories/pass@k/trials/t{i}/verifier/reward.txt"), "1\n" if i < 2 else "0\n")
        gr = eval_finder.find(t)
        ck("EV1: technique gate present -> no candidate", len(gr["checks"]["ev1_anticheat"]["candidates"]) == 0)
        ck("EV5: 2/5 solve -> not too-easy", len(gr["checks"]["ev5_difficulty"]["candidates"]) == 0)

        b = tempfile.mkdtemp(); dirs.append(b); tb = os.path.join(b, "task")
        _w(os.path.join(tb, "tests/test.sh"), "cat submission > reward.txt\n")  # no gate
        for i in range(5):
            _w(os.path.join(tb, f"trajectories/pass@k/trials/t{i}/verifier/reward.txt"), "1\n")  # 5/5
        br = eval_finder.find(tb)
        ck("EV1: no gate -> vacuous candidate", len(br["checks"]["ev1_anticheat"]["candidates"]) >= 1)
        ck("EV5: 5/5 solve -> too-easy candidate", len(br["checks"]["ev5_difficulty"]["candidates"]) >= 1)

        d = tempfile.mkdtemp(); dirs.append(d); td = os.path.join(d, "task")
        _w(os.path.join(td, "tests/behavior/verify.py"), "technique match\n")
        dr = eval_finder.find(td)
        ck("EV5: no pass@k -> DEFERRED", dr["checks"]["ev5_difficulty"]["status"] == "DEFERRED")

        print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
    finally:
        for x in dirs:
            shutil.rmtree(x, ignore_errors=True)
if __name__ == "__main__":
    main()
