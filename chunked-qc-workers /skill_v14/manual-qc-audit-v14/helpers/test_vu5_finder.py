#!/usr/bin/env python3
"""
TDD tests for vu5_finder.py — static FINDER layer of the VU5 eval
(Vulnerability: Attack-Surface Breadth).

VU5 is reader-dominant. The finder provides COVERAGE: reuse the route/surface inventory
(from vu2_finder), count the distinct major surfaces (for [Fail - One-Trick Task]: <3
probeable surfaces across distinct categories), and locate the decoy / adjacent-surface
descriptions (for [Fail - Decoy Reaches Scored Secret] and the score-3 [Non-Fail - Fake
or Stubbed Decoy]). The reader judges whether >=3 genuine surfaces exist, each decoy is
real (not stubbed), and no decoy reaches the scored secret.

Run:  python3 -I test_vu5_finder.py
"""
import os, sys, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vu5_finder  # noqa: E402


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))


def build_broad(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    _w(os.path.join(env, "ledger-service", "app.py"), '''
        @app.get('/v1/records')
        def r(): ...
        @app.post('/v1/export')
        def e(): ...
        @app.get('/v1/label')
        def l(): ...
        @app.post('/v1/validate')
        def v(): ...
    ''')
    _w(os.path.join(t, "task.toml"), '''
        [task]
        name = "acme/broad"
        difficulty_explanation = """
        The app exposes real, resisting surfaces: export enforces ownership, label preview
        escapes HTML, and the validator rejects the payload. Only the document engine evals.
        """
    ''')
    return t


def build_onetrick(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    _w(os.path.join(env, "ledger-service", "app.py"), '''
        @app.get('/health')
        def h(): ...
        @app.get('/only')
        def only(): ...
    ''')
    _w(os.path.join(t, "task.toml"), '[task]\nname = "acme/thin"\n')
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
        b = tempfile.mkdtemp(); dirs.append(b); br = vu5_finder.find(build_broad(b))
        o = tempfile.mkdtemp(); dirs.append(o); orr = vu5_finder.find(build_onetrick(o))

        bc = br["checks"]["surface_breadth"]
        oc = orr["checks"]["surface_breadth"]

        # 1. broad: counts the distinct non-trivial surfaces (>= 3)
        check("broad: >=3 distinct major surfaces counted",
              bc["distinct_surface_count"] >= 3 and bc["one_trick_candidate"] is False)

        # 2. one-trick: < 3 probeable surfaces -> candidate
        check("one-trick: <3 surfaces -> one_trick_candidate True",
              oc["distinct_surface_count"] < 3 and oc["one_trick_candidate"] is True)

        # 3. health/trivial endpoints excluded from the surface count
        check("broad: /health excluded from major surfaces",
              all("/health" not in s for s in bc["major_surfaces"]))

        # 4. decoy descriptions located
        check("broad: decoy/resisting-surface description located",
              len(br["checks"]["decoy_reaches_secret"]["located"]) >= 1)

        # 5. files_to_read populated
        check("files_to_read includes the route file",
              any("app.py" in f for f in bc["files_to_read"]))

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
