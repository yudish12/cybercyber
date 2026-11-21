#!/usr/bin/env python3
"""TDD tests for chain_finder.py."""
import os,sys,tempfile,shutil
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import chain_finder
def _w(p,c):
    os.makedirs(os.path.dirname(p),exist_ok=True); open(p,"w").write(c)
P=F=0
def ck(n,c):
    global P,F; P+=c; F+=(not c); print(f"  {'ok  ' if c else 'FAIL'} {n}")
def main():
    d=tempfile.mkdtemp()
    try:
        t=os.path.join(d,"task")
        _w(os.path.join(t,"solution","solve.sh"),
           '#!/bin/bash\ncurl "$BASE/index.php?option=com_content&view=category"\ncurl "$BASE/secretpivot/login"\n')
        _w(os.path.join(t,"instruction_L0.md"),"target only\n")
        # app serves 'category' (discoverable) but NOT 'secretpivot'; robots over-serves nothing
        _w(os.path.join(t,"environment","gateway","app.py"),
           "def f():\n    return jsonify(sort='category view')\ndef g():\n    x='secretpivot internal'\n")
        _w(os.path.join(t,"environment","gateway","robots.py"),"def r():\n    return 'Disallow: /admin'\n")
        r=chain_finder.find(t)
        segs=[c['seg'] for c in r['chain']]
        ck("com_content extracted as hop", "com_content" in segs)
        ck("payload tokens not hops", "extractvalue" not in segs)
        ck("undiscoverable list populated for unserved hop", isinstance(r['vu4_undiscoverable_hops'],list))
        # over-served case
        d2=tempfile.mkdtemp()
        _w(os.path.join(d2,"task","solution","solve.sh"),'curl "$BASE/portal/home"\ncurl "$BASE/nw-ops/login"\n')
        _w(os.path.join(d2,"task","instruction_L0.md"),"t\n")
        _w(os.path.join(d2,"task","environment","gateway","app.py"),"def robots():\n    return 'Disallow: /nw-ops/'\n")
        r2=chain_finder.find(os.path.join(d2,"task"))
        ck("over-served-at-L0 detected (nw-ops in robots)", "nw-ops" in r2['vu3_overserved_at_L0_hops'] or "login" in r2['vu3_overserved_at_L0_hops'])
        shutil.rmtree(d2,ignore_errors=True)
        print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
    finally:
        shutil.rmtree(d,ignore_errors=True)
if __name__=="__main__":
    main()
