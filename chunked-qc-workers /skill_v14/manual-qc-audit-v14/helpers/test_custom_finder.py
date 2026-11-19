#!/usr/bin/env python3
"""TDD tests for custom_finder.py (F6, EV7, EN5 static signals)."""
import os, sys, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import custom_finder
def _w(p, c):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(c)
P=F=0
def ck(n,c):
    global P,F; P+=c; F+=(not c); print(f"  {'ok  ' if c else 'FAIL'} {n}")
def main():
    d=tempfile.mkdtemp()
    try:
        t=os.path.join(d,"task")
        _w(os.path.join(t,"task.toml"), 'difficulty_explanation = "Previously this used md5; I changed it to sha256."\n')
        _w(os.path.join(t,"environment","gateway","app.py"),
           "@app.post('/_debug/reset')\ndef r():\n    db.execute('TRUNCATE records')\n")
        _w(os.path.join(t,"tests","behavior","verify.py"), "os.chmod('/logs', 0o777)\natomic('reward.json','0')\n")
        r=custom_finder.find(t)
        ck("F6: authoring narration in task.toml flagged", len(r["checks"]["f6_narration"]["candidates"])>=1)
        ck("EN5: /_debug/reset + TRUNCATE flagged", len(r["checks"]["en5_harness_endpoint"]["candidates"])>=1)
        ck("EV7: chmod before reward write flagged", len(r["checks"]["ev7_crash_safety"]["candidates"])>=1)
        # clean control
        d2=tempfile.mkdtemp()
        _w(os.path.join(d2,"task","task.toml"), 'difficulty_explanation = "The agent injects via the preview."\n')
        r2=custom_finder.find(os.path.join(d2,"task"))
        ck("clean: no F6 narration", len(r2["checks"]["f6_narration"]["candidates"])==0)
        shutil.rmtree(d2, ignore_errors=True)
        print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)
if __name__=="__main__":
    main()
