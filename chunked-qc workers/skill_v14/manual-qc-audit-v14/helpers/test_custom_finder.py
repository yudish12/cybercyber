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

        # ---- EV3 acceptance parity (v1.6) ----
        PROXY = ('@app.route("/<path:path>", methods=["GET", "POST"])\n'
                 'def proxy(path):\n'
                 '    _inj = detect(path, request.query_string.decode()%s)\n'
                 '    resp = req_lib.request(request.method, url, data=request.get_data())\n'
                 '    return resp\n')
        DETECT_Q = ('def detect(path, qs):\n'
                    '    q = parse_qs(qs)\n'
                    '    blob = " ".join(q.get("sort", []))\n'
                    '    if any(m in blob for m in ("/ops", "ops-")):\n'
                    '        _mark_audit("credential_recovered")\n'
                    '    return bool(blob)\n')
        DETECT_QB = ('def detect(path, qs, form_pairs=None):\n'
                     '    q = parse_qs(qs)\n'
                     '    for k, v in (form_pairs or []):\n'
                     '        q.setdefault(k, []).append(v)\n'
                     '    blob = " ".join(q.get("sort", []))\n'
                     '    if (any(m in blob for m in ("/ops", "ops-"))\n'
                     '            or re.search(r"\\bmessage\\b", blob)):\n'
                     '        _mark_audit("credential_recovered")\n'
                     '    if "computed_value" in blob:\n'
                     '        AUDIT_LOG["F"]["sink_used"] = True\n'
                     '        _event(actor, "POST /x", "sink", {})\n'
                     '    return bool(blob)\n')
        DIAG = ('@app.route("/internal/diag/audit")\n'
                'def diag():\n'
                '    _event(actor, "GET /internal/diag/audit", "verifier_audit", {"authorized": True})\n'
                '    return jsonify(a=request.args.get("x"))\n')
        d3 = tempfile.mkdtemp()
        _w(os.path.join(d3, "task", "environment", "gateway", "app.py"), DETECT_Q + PROXY % "" + DIAG)
        e3 = custom_finder.find(os.path.join(d3, "task"))["checks"]["ev3_acceptance_parity"]["candidates"]
        ck("EV3: query-only credit + POST-forwarding proxy -> transport candidate",
           any("reads only the query string" in c["why"] and c["tier"] == "candidate" for c in e3))
        ck("EV3: credit gated on value literals ('/ops', 'ops-') -> literal candidate",
           any(c.get("credit_key") == "credential_recovered" and c["tier"] == "candidate"
               and "hardcoded literal" in c["why"] for c in e3))
        ck("EV3: verifier diag _event (harness logging) is never a credit setter",
           not any(c.get("credit_fn") == "diag" for c in e3))
        shutil.rmtree(d3, ignore_errors=True)

        d4 = tempfile.mkdtemp()
        _w(os.path.join(d4, "task", "environment", "gateway", "app.py"),
           DETECT_QB + PROXY % ", form_pairs=list(request.form.items(multi=True))" + DIAG)
        e4 = custom_finder.find(os.path.join(d4, "task"))["checks"]["ev3_acceptance_parity"]["candidates"]
        ck("EV3: detector that also reads form_pairs -> no transport candidate",
           not any("reads only the query string" in c["why"] for c in e4))
        ck("EV3: literal guard OR'd with a column-read branch -> REVIEW, not FAIL",
           any(c.get("credit_key") == "credential_recovered" and c["tier"] == "review" for c in e4))
        ck("EV3: identifier-only literal ('computed_value') -> REVIEW, one entry per guard",
           sum(1 for c in e4 if c.get("guard", "").startswith('if "computed_value"')) == 1
           and all(c["tier"] == "review" for c in e4 if c.get("guard", "").startswith('if "computed_value"')))
        shutil.rmtree(d4, ignore_errors=True)
        print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)
if __name__=="__main__":
    main()
