#!/usr/bin/env python3
"""TDD tests for partition.py."""
import os, sys, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import partition
def _w(p,c):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p,"w").write(c)
P=F=0
def ck(n,c):
    global P,F; P+=c; F+=(not c); print(f"  {'ok  ' if c else 'FAIL'} {n}")
def main():
    d=tempfile.mkdtemp()
    try:
        t=os.path.join(d,"task")
        _w(os.path.join(t,"task.toml"),'[task]\ncwe="CWE-94"\n')
        _w(os.path.join(t,"solution","solve.sh"),"#!/bin/bash\ncurl x > out\n")
        _w(os.path.join(t,"tests","test.sh"),"exec verify\n")
        _w(os.path.join(t,"tests","behavior","verify.py"),"reward=1 if ok else 0\nopen('reward.json','w')\n")
        _w(os.path.join(t,"environment","gateway","app.py"),"scored=secrets.token_hex(16)\n")  # author+secret
        _w(os.path.join(t,"environment","dolibarr","lib","core.php"),"<?php // pristine vendored\n")  # scan-only
        _w(os.path.join(t,"environment","dolibarr","custom","fc","preview.php"),"<?php eval($x);\n")  # overlay->read-full
        _w(os.path.join(t,"environment","dolibarr","Dockerfile"),"FROM dolibarr\n")  # overlay
        _w(os.path.join(t,"environment","agent","vendor-wheels","x.whl"),"binary")  # skip
        r=partition.partition(t)
        rf=set(r["read_full"])
        ck("author gateway/app.py -> read_full", "environment/gateway/app.py" in rf)
        ck("vendored overlay custom/preview.php -> read_full", any("custom/fc/preview.php" in f for f in rf))
        ck("pristine dolibarr/lib/core.php -> scan_only (not read_full)",
           "environment/dolibarr/lib/core.php" not in rf and r["scan_only_count"]>=1)
        ck(".whl skipped entirely", not any(".whl" in f for f in rf))
        ck("flow: secret source found", "environment/gateway/app.py" in r["flows"]["scored_secret_sources"])
        ck("flow: reward setter found", "tests/behavior/verify.py" in r["flows"]["reward_setters"])
        ck("read_full includes task.toml + solve.sh + test.sh",
           {"task.toml","solution/solve.sh","tests/test.sh"} <= rf)
        print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)
if __name__=="__main__":
    main()
