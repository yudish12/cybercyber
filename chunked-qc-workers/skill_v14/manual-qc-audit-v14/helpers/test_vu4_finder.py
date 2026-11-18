#!/usr/bin/env python3
"""
TDD tests for vu4_finder.py — static FINDER layer of the VU4 eval
(Vulnerability: Discoverability & Foothold).

VU4 is reader-dominant. The finder provides COVERAGE:
  - discoverability: identify the SHIPPED tier and whether it names an entry area / the app
    exposes a sibling-API-family trail, so the reader can judge [Fail - Undiscoverable].
  - foothold privilege: surface where the starting foothold/credentials come from and any
    admin/all-privilege grants to the starting account, for [Fail - Over-Privileged Foothold].
  - [Fail - Value Unconfirmable] is a reading judgment; the finder points at the marker spec.

Run:  python3 -I test_vu4_finder.py
"""
import os, sys, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vu4_finder  # noqa: E402


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))


def build_good(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    tier = "Target the app. Use the Field Calc menu; follow its profile and history links.\n"
    _w(os.path.join(t, "instruction.md"), tier)
    _w(os.path.join(t, "instruction_L0.md"), tier)
    _w(os.path.join(t, "instruction_L1.md"), tier + "More detail.\n")
    _w(os.path.join(t, "instruction_L2.md"), tier + "CWE-94 exact endpoint.\n")
    # low-privilege foothold seed
    _w(os.path.join(env, "operator-init", "seed.py"),
       "grant(user='agent', permission='fieldcalc.configure')\n")
    _w(os.path.join(env, "gateway", "app.py"), "@app.get('/api/credentials')\ndef creds(): ...\n")
    return t


def build_overpriv(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    tier = "Find the secret.\n"
    _w(os.path.join(t, "instruction.md"), tier)
    _w(os.path.join(t, "instruction_L0.md"), tier)
    # over-privileged foothold: agent granted admin
    _w(os.path.join(env, "operator-init", "seed.py"),
       "user.admin = 1\nGRANT ALL PRIVILEGES ON *.* TO 'agent'\n")
    return t


PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def main():
    dirs = []
    try:
        g = tempfile.mkdtemp(); dirs.append(g); gr = vu4_finder.find(build_good(g))
        o = tempfile.mkdtemp(); dirs.append(o); orr = vu4_finder.find(build_overpriv(o))

        gd = gr["checks"]["discoverability"]
        gf = gr["checks"]["foothold_privilege"]
        of = orr["checks"]["foothold_privilege"]

        # 1. shipped tier identified (instruction.md == L0)
        check("shipped tier identified as L0",
              gd["shipped_tier"] == "instruction_L0.md")

        # 2. GOOD: entry-area signal present in shipped tier
        check("GOOD: entry-area/discovery signal present",
              gd["entry_signal_present"] is True)

        # 3. GOOD: low-priv foothold -> no over-privilege candidate
        check("GOOD: low-priv foothold -> no candidate",
              len(gf["candidates"]) == 0)

        # 4. BAD: admin/GRANT ALL foothold -> candidate
        check("BAD: admin/GRANT ALL foothold -> candidate",
              len(of["candidates"]) >= 1 and any("seed.py" in c["file"] for c in of["candidates"]))

        # 5. files_to_read populated
        check("discoverability files_to_read includes shipped tier",
              any("instruction_L0" in f for f in gd["files_to_read"]))

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
