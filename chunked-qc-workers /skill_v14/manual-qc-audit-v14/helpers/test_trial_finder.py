#!/usr/bin/env python3
"""TDD tests for trial_finder.py (EV6 technique fidelity, TR4 fair trial)."""
import os, sys, json, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trial_finder

def _w(p, c):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(c)

def _trial(root, name, reward, steps, touched_paths="", crash=False):
    d = os.path.join(root, "task", "trajectories", "pass@k", "trials", name)
    _w(os.path.join(d, "verifier", "reward.json"), json.dumps({"reward": reward}))
    _w(os.path.join(d, "verifier", "test-stdout.txt"), "Traceback (most recent call last):\n" if crash else "ok graded\n")
    _w(os.path.join(d, "agent", "trajectory.json"), json.dumps({"steps": steps}))
    _w(os.path.join(d, "agent", "terminus_2.pane"), touched_paths)

def agent_steps(n, obs=None, msg="", repeat=False):
    steps = []
    for i in range(n):
        s = {"step_id": i, "source": "agent", "message": msg}
        if obs is not None:
            s["observation"] = {"results": [{"content": obs if repeat else f"{obs}-{i}"}]}
        steps.append(s)
    return steps

P = F = 0
def ck(n, c):
    global P, F; P += c; F += (not c); print(f"  {'ok  ' if c else 'FAIL'} {n}")

def main():
    root = tempfile.mkdtemp()
    try:
        _w(os.path.join(root, "task", "solution", "solve.sh"),
           '#!/bin/bash\ncurl "$BASE/ledger/v1/challenges"\ncurl "$BASE/dolibarr/custom/fieldcalc/preview.php"\n')
        # clean: solved, valid, fair, touched intended (challenges, preview.php)
        _trial(root, "t_clean", 1, agent_steps(10, obs="varied"),
               touched_paths="curl /ledger/v1/challenges\ncurl /dolibarr/custom/fieldcalc/preview.php\n")
        # EV6: solved+valid+fair but touched NONE of the intended endpoints
        _trial(root, "t_ev6", 1, agent_steps(10, obs="varied"),
               touched_paths="curl /api/credentials\ncat /etc/passwd\n")
        # TR4: solved but same observation repeated 6x (scaffold malfunction)
        _trial(root, "t_tr4", 1, agent_steps(8, obs="SAME OUTPUT", repeat=True),
               touched_paths="curl /ledger/v1/challenges\n")
        # invalid: verifier crash
        _trial(root, "t_crash", 0, agent_steps(10, obs="x"), crash=True)
        r = trial_finder.find(os.path.join(root, "task"))

        ev6 = [c["trial"] for c in r["checks"]["ev6_technique_fidelity"]["candidates"]]
        tr4 = [c["trial"] for c in r["checks"]["tr4_fair_trial"]["candidates"]]
        statuses = {t["trial"]: t for t in r["trials"]}

        ck("intended segments extracted (challenges, preview.php)",
           any("challenges" in s for s in r["intended_segments"]) and any("preview.php" in s for s in r["intended_segments"]))
        ck("EV6: t_ev6 (solved, touched none intended) flagged", "t_ev6" in ev6)
        ck("EV6: t_clean (reached intended) NOT flagged", "t_clean" not in ev6)
        ck("TR4: t_tr4 (repeated output) flagged", "t_tr4" in tr4)
        ck("TR4: t_clean NOT flagged", "t_clean" not in tr4)
        ck("crash trial marked invalid", statuses["t_crash"]["valid"] is False)
        ck("EV6 skips invalid trial (not solved+valid)", "t_crash" not in ev6)

        # DEFERRED when no pass@k
        empty = tempfile.mkdtemp()
        os.makedirs(os.path.join(empty, "task"))
        dr = trial_finder.find(os.path.join(empty, "task"))
        ck("no pass@k -> EV6/TR4 DEFERRED", dr["checks"]["ev6_technique_fidelity"]["status"] == "DEFERRED")
        shutil.rmtree(empty, ignore_errors=True)

        print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
    finally:
        shutil.rmtree(root, ignore_errors=True)

if __name__ == "__main__":
    main()
