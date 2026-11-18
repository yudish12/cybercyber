#!/usr/bin/env python3
"""TDD tests for traj_finder.py (TR2 noop=0, TR3 oracle=1)."""
import os, sys, tempfile, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import traj_finder  # noqa: E402


def _w(p, c):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(c)


def build(root, noop="0", oracle="1"):
    t = os.path.join(root, "task")
    _w(os.path.join(t, "trajectories", "noop", "reward.txt"), noop + "\n")
    _w(os.path.join(t, "trajectories", "oracle", "reward.txt"), oracle + "\n")
    return t


PASS = FAIL = 0


def check(n, c):
    global PASS, FAIL
    PASS += c; FAIL += (not c)
    print(f"  {'ok  ' if c else 'FAIL'} {n}")


def main():
    dirs = []
    try:
        g = tempfile.mkdtemp(); dirs.append(g); gr = traj_finder.find(build(g))
        check("GOOD: noop=0 -> no TR2 candidate", len(gr["checks"]["tr2_noop"]["candidates"]) == 0)
        check("GOOD: oracle=1 -> no TR3 candidate", len(gr["checks"]["tr3_oracle"]["candidates"]) == 0)

        b = tempfile.mkdtemp(); dirs.append(b); br = traj_finder.find(build(b, noop="1", oracle="0"))
        check("BAD: noop=1 -> TR2 candidate", len(br["checks"]["tr2_noop"]["candidates"]) >= 1)
        check("BAD: oracle=0 -> TR3 candidate", len(br["checks"]["tr3_oracle"]["candidates"]) >= 1)

        m = tempfile.mkdtemp(); dirs.append(m)  # missing rewards
        os.makedirs(os.path.join(m, "task"))
        mr = traj_finder.find(os.path.join(m, "task"))
        check("MISSING: no reward files -> both flagged",
              len(mr["checks"]["tr2_noop"]["candidates"]) >= 1 and len(mr["checks"]["tr3_oracle"]["candidates"]) >= 1)

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
