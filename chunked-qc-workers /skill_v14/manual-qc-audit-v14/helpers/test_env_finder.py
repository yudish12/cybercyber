#!/usr/bin/env python3
"""TDD tests for env_finder.py (EN1 scale/seed, EN2 isolation signals)."""
import os, sys, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import env_finder  # noqa: E402


def _w(p, c):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(textwrap.dedent(c))


def build_good(root):
    t = os.path.join(root, "task"); env = os.path.join(t, "environment")
    _w(os.path.join(env, "gateway", "app.py"), "x=1\n")
    _w(os.path.join(env, "ledger-service", "app.py"), "y=1\n")
    _w(os.path.join(env, "dolibarr", "custom", "fc", "home.php"), "<?php\n")
    _w(os.path.join(env, "dolibarr", "docker-init.d", "00-seed.sh"), "#!/bin/sh\n")
    _w(os.path.join(env, "docker-compose.yaml"), '''
        services:
          main:
            networks: [backend]
        networks:
          backend:
            internal: true
        ''')
    return t


def build_thin(root):
    t = os.path.join(root, "task"); env = os.path.join(t, "environment")
    _w(os.path.join(env, "gateway", "app.py"), "x=1\n")  # 1 author file, no seed
    _w(os.path.join(env, "docker-compose.yaml"), "services:\n  main:\n    networks: [web]\nnetworks:\n  web: {}\n")
    return t


PASS = FAIL = 0


def check(n, c):
    global PASS, FAIL
    PASS += c; FAIL += (not c); print(f"  {'ok  ' if c else 'FAIL'} {n}")


def main():
    dirs = []
    try:
        g = tempfile.mkdtemp(); dirs.append(g); gr = env_finder.find(build_good(g))
        check("GOOD: enough files + seed -> no EN1 candidate", len(gr["checks"]["en1_scale"]["candidates"]) == 0)
        check("GOOD: backend internal:true recorded", gr["checks"]["en2_isolation"]["networks"].get("backend") is True)

        b = tempfile.mkdtemp(); dirs.append(b); br = env_finder.find(build_thin(b))
        check("THIN: <3 files + no seed -> EN1 candidates", len(br["checks"]["en1_scale"]["candidates"]) >= 1)
        check("EN2: non-internal 'web' network + main on it -> signal",
              any(s["service"] == "main" for s in br["checks"]["en2_isolation"]["signals"]))

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
