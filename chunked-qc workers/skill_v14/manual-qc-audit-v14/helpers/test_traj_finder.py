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

        # TR3 Unverified Discovery: later-hop literals, no assertion
        u = tempfile.mkdtemp(); dirs.append(u); ut = os.path.join(u, "task")
        _w(os.path.join(ut, "trajectories", "noop", "reward.txt"), "0\n")
        _w(os.path.join(ut, "trajectories", "oracle", "reward.txt"), "1\n")
        _w(os.path.join(ut, "solution", "solve.sh"),
           '#!/bin/bash\ncurl "$BASE/app/login" > /logs/verifier/submission.txt\ncurl "$BASE/ledger/secretpath"\ncurl "$BASE/vault/disposition"\n')
        ur = traj_finder.find(ut)
        check("TR3: later-hop literals w/o assertion -> Unverified Discovery",
              any(c.get("label") == "[Fail - Unverified Discovery]" for c in ur["checks"]["tr3_oracle"]["candidates"]))
        # CALIBRATION vs official cyber_quality_check TR3:
        # (a) helper idiom get("/x")/post("/x") + a SINGLE cold hop (>=1) must fire.
        h = tempfile.mkdtemp(); dirs.append(h); ht = os.path.join(h, "task")
        _w(os.path.join(ht, "trajectories", "oracle", "reward.txt"), "1\n")
        _w(os.path.join(ht, "solution", "solve.sh"),
           '#!/bin/bash\npython3 - <<PY\n'
           '_,r = get("/portal/")\n'
           'code, body = post("/admin-console/login", {"u":1})\n'  # cold hop, no prior assertion
           'PY\n')
        hr = traj_finder.find(ht)
        unc = [c for c in hr["checks"]["tr3_oracle"]["candidates"] if c.get("label") == "[Fail - Unverified Discovery]"]
        check("TR3: helper idiom get()/post() detected (was curl-only)", len(unc) >= 1)
        check("TR3: a SINGLE cold hop fires (threshold >=1, not >=2)",
              any("admin-console" in c["why"] for c in unc))

        # (b) `X not in resp: die` idiom + extraction-into-variable must NOT be flagged (no FP,
        #     even though the file also has other assertions).
        c2 = tempfile.mkdtemp(); dirs.append(c2); ct = os.path.join(c2, "task")
        _w(os.path.join(ct, "trajectories", "oracle", "reward.txt"), "1\n")
        _w(os.path.join(ct, "solution", "solve.sh"),
           '#!/bin/bash\npython3 - <<PY\n'
           '_, landing = get("/portal/")\n'
           'if "/admin-console/login" not in landing:\n'
           '    die(11, "not advertised")\n'
           'code, body = post("/admin-console/login", {"u":1})\n'   # covered by the `not in landing` above
           'mset = re.search(r"(/[a-z/]+/data)", body)\n'
           'route = mset.group(1)\n'
           'code, body = get(route)\n'                               # variable, not a literal -> ignored
           'PY\n')
        cr = traj_finder.find(ct)
        unc2 = [c for c in cr["checks"]["tr3_oracle"]["candidates"] if c.get("label") == "[Fail - Unverified Discovery]"]
        check("TR3: `not in resp` idiom covers the hop -> NO false positive", len(unc2) == 0)

        # TR3 [Fail - Shortcut Solve] (V19): a local seed/config/state read, or docker
        # exec/cp into a sibling container, instead of the intended HTTP-facing technique.
        sc = tempfile.mkdtemp(); dirs.append(sc); sct = os.path.join(sc, "task")
        _w(os.path.join(sct, "trajectories", "noop", "reward.txt"), "0\n")
        _w(os.path.join(sct, "trajectories", "oracle", "reward.txt"), "1\n")
        _w(os.path.join(sct, "solution", "solve.sh"),
           '#!/bin/bash\n'
           'secret=$(cat /opt/service-accounts/registry.json)\n'  # local shortcut read
           'echo "$secret" > /logs/verifier/submission.txt\n')
        scr = traj_finder.find(sct)
        sccands = scr["checks"]["tr3_oracle"]["candidates"]
        check("TR3: local seed/config path read -> Shortcut Solve surfaced",
              any(c.get("label") == "[Fail - Shortcut Solve]" and "service-accounts" in c.get("path", "")
                  for c in sccands))

        # same path reached THROUGH an HTTP call on the same line -> NOT a shortcut
        ok = tempfile.mkdtemp(); dirs.append(ok); okt = os.path.join(ok, "task")
        _w(os.path.join(okt, "trajectories", "noop", "reward.txt"), "0\n")
        _w(os.path.join(okt, "trajectories", "oracle", "reward.txt"), "1\n")
        _w(os.path.join(okt, "solution", "solve.sh"),
           '#!/bin/bash\n'
           'curl "$BASE/opt/service-accounts/registry.json" > /logs/verifier/submission.txt\n')
        okr = traj_finder.find(okt)
        check("TR3: HTTP-reached path (curl) is NOT flagged as a local shortcut",
              not any(c.get("label") == "[Fail - Shortcut Solve]"
                      for c in okr["checks"]["tr3_oracle"]["candidates"]))

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
