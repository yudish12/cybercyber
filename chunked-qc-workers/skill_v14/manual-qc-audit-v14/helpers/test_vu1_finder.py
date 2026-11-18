#!/usr/bin/env python3
"""TDD tests for vu1_finder.py."""
import os, sys, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vu1_finder


def _w(p, c):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(c)


P = F = 0
def ck(n, c):
    global P, F; P += c; F += (not c); print(f"  {'ok  ' if c else 'FAIL'} {n}")


def main():
    dirs = []
    try:
        g = tempfile.mkdtemp(); dirs.append(g)
        _w(os.path.join(g, "task/environment/gateway/app.py"), "scored = secrets.token_hex(24)\n")
        gr = vu1_finder.find(os.path.join(g, "task"))
        ck("GOOD: dynamic generation, no baked -> clean",
           len(gr["checks"]["secret_authenticity"]["baked_candidates"]) == 0 and
           len(gr["checks"]["secret_authenticity"]["generation_sites"]) >= 1)

        b = tempfile.mkdtemp(); dirs.append(b)
        _w(os.path.join(b, "task/environment/gateway/app.py"),
           "SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef'\n")
        br = vu1_finder.find(os.path.join(b, "task"))
        ck("BAD: baked hex secret in served source -> candidate",
           len(br["checks"]["secret_authenticity"]["baked_candidates"]) >= 1)

        v = tempfile.mkdtemp(); dirs.append(v)  # baked in VENDORED source -> not author -> not flagged
        _w(os.path.join(v, "task/environment/dolibarr/lib/x.php"),
           "$SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef';\n")
        vr = vu1_finder.find(os.path.join(v, "task"))
        ck("vendored baked literal -> not author-scoped, not flagged",
           len(vr["checks"]["secret_authenticity"]["baked_candidates"]) == 0)

        print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
