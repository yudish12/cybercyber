#!/usr/bin/env python3
"""
TDD tests for format_finder.py — the FORMAT group (F1-F5), mostly mechanical:
  F1 Structure & Artifacts   — required files present/parseable/executable
  F2 Compose Contract        — compose names a `main` service
  F3 Flag/Marker Format      — marker format identical across tiers; prefix must not name the class
  F4 Metadata Consistency    — cwe/vulnerability_kind present (reader checks alignment with solve)
  F5 Packaging Hygiene       — mutable base tag, [agent] non-root user, valid fresh_state.json

Run:  python3 -I test_format_finder.py
"""
import os, sys, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import format_finder  # noqa: E402


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))


FLAG = "The scored marker format is exactly FLAG1=[0-9a-f]{48}\n"


def build_good(root):
    t = os.path.join(root, "task")
    for n in ("instruction.md", "instruction_L0.md", "instruction_L1.md", "instruction_L2.md"):
        _w(os.path.join(t, n), "Target the app.\n" + FLAG)
    _w(os.path.join(t, "task.toml"), '''
        [task]
        name = "acme/sqli"
        cwe = "CWE-89"
        vulnerability_kind = "SQL injection"
        [agent]
        user = "agent"
    ''')
    _w(os.path.join(t, "fresh_state.json"), '{"ok": true}')
    _w(os.path.join(t, "environment", "docker-compose.yaml"), '''
        services:
          main:
            build: ./app
        ''')
    _w(os.path.join(t, "environment", "app", "Dockerfile"), "FROM python:3.12-slim@sha256:abc\n")
    _w(os.path.join(t, "environment", "NOTICE.md"), "notice")
    _w(os.path.join(t, "solution", "solve.sh"), "#!/bin/bash\necho hi\n")
    _w(os.path.join(t, "tests", "test.sh"), "#!/bin/bash\n")
    _w(os.path.join(t, "tests", "isolation_test.sh"), "#!/bin/bash\n")
    return t


PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def cands(r, key):
    return r["checks"][key]["candidates"]


def main():
    dirs = []
    try:
        g = tempfile.mkdtemp(); dirs.append(g); gr = format_finder.find(build_good(g))

        # 1. GOOD: no F1 structure fails
        check("GOOD: no missing required files (F1)", len(cands(gr, "f1_structure")) == 0)
        # 2. GOOD: main service present (F2)
        check("GOOD: compose names main (F2)", len(cands(gr, "f2_compose")) == 0)
        # 3. GOOD: flag consistent, prefix clean (F3)
        check("GOOD: flag format consistent (F3)", len(cands(gr, "f3_flag")) == 0)
        # 4. GOOD: [agent] non-root + valid fresh_state (F5)
        check("GOOD: F5 packaging clean", len(cands(gr, "f5_packaging")) == 0)

        # BAD: missing fresh_state.json
        b = tempfile.mkdtemp(); dirs.append(b); bt = build_good(b)
        os.remove(os.path.join(bt, "fresh_state.json"))
        br = format_finder.find(bt)
        check("BAD: missing fresh_state.json -> F1 candidate",
              any("fresh_state" in str(c) for c in cands(br, "f1_structure")))

        # BAD: compose without main
        c = tempfile.mkdtemp(); dirs.append(c); ct = build_good(c)
        _w(os.path.join(ct, "environment", "docker-compose.yaml"), "services:\n  web:\n    build: ./app\n")
        cr = format_finder.find(ct)
        check("BAD: compose lacks main -> F2 candidate", len(cands(cr, "f2_compose")) >= 1)

        # BAD: flag prefix names the class
        d = tempfile.mkdtemp(); dirs.append(d); dt = build_good(d)
        for n in ("instruction.md", "instruction_L0.md", "instruction_L1.md", "instruction_L2.md"):
            _w(os.path.join(dt, n), "Target.\nThe marker is SQLI_FLAG=[0-9a-f]{48}\n")
        dr = format_finder.find(dt)
        check("BAD: SQLI_FLAG prefix names class -> F3 candidate",
              any("prefix" in str(c).lower() or "class" in str(c).lower() for c in cands(dr, "f3_flag")))

        # BAD: [agent] user = root
        e = tempfile.mkdtemp(); dirs.append(e); et = build_good(e)
        _w(os.path.join(et, "task.toml"),
           '[task]\nname="x"\ncwe="CWE-89"\nvulnerability_kind="SQLi"\n[agent]\nuser = "root"\n')
        er = format_finder.find(et)
        check("BAD: [agent] user=root -> F5 candidate",
              any("root" in str(c).lower() or "non-root" in str(c).lower() for c in cands(er, "f5_packaging")))

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        for x in dirs:
            shutil.rmtree(x, ignore_errors=True)


if __name__ == "__main__":
    main()
