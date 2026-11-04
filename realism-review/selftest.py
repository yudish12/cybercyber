#!/usr/bin/env python3
"""Data-free tests for the realism scanner. Needs no corpus.

Each test builds a minimal synthetic bundle exercising one check, so a refactor that
silently stops finding something fails here rather than on a real submission.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "realism_checks.py")

COMPOSE = """services:
  main:
    build: ./agent
  web:
    build: ./web
  inventory_service:
    build: ./inventory_service
"""


def bundle(app, *, cwe="CWE-89", solve="", tests="", extra=None, instr_l2=""):
    d = tempfile.mkdtemp(prefix="selftest-")
    t = os.path.join(d, "task")
    for sub in ("environment/web", "solution", "tests"):
        os.makedirs(os.path.join(t, sub), exist_ok=True)
    open(os.path.join(t, "task.toml"), "w").write(
        f'[task]\nname = "selftest/case"\ncwe = "{cwe}"\n')
    open(os.path.join(t, "environment/web/app.py"), "w").write(app)
    open(os.path.join(t, "environment/docker-compose.yaml"), "w").write(COMPOSE)
    open(os.path.join(t, "solution/solve.py"), "w").write(solve or "# none\n")
    open(os.path.join(t, "tests/test.sh"), "w").write(tests or "#!/bin/bash\n")
    open(os.path.join(t, "instruction_L0.md"), "w").write("Find the flag.\n")
    open(os.path.join(t, "instruction_L2.md"), "w").write(instr_l2 or "Recipe.\n")
    for rel, body in (extra or {}).items():
        p = os.path.join(t, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(body)
    return d, t


def scan(t):
    out = subprocess.run([sys.executable, SCANNER, t, "--out", "/dev/stdout", "--quiet"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(f"scanner exited {out.returncode}: {out.stderr[-800:]}")
    return json.loads(out.stdout)


RESULTS = []


def case(name):
    def deco(fn):
        d = None
        try:
            d = fn()
            RESULTS.append((True, name, ""))
        except AssertionError as e:
            RESULTS.append((False, name, str(e)))
        except Exception as e:  # noqa: BLE001
            RESULTS.append((False, name, f"{type(e).__name__}: {e}"))
        finally:
            if isinstance(d, str) and os.path.isdir(d):
                shutil.rmtree(d, ignore_errors=True)
        return fn
    return deco


def ids(pack):
    return [f["id"] for f in pack["findings"]]


# --------------------------------------------------------------------- RC1

@case("RC1.1 fires when nothing ever writes into the directory the reader opens")
def _():
    d, t = bundle('''
from flask import Flask, request, jsonify
import os
app = Flask(__name__)

@app.route("/api/exports", methods=["POST"])
def make_export():
    name = request.json["filename"]
    db.execute("INSERT INTO exports (filename) VALUES (?)", (name,))
    return jsonify({"ok": True})

@app.route("/api/exports/download")
def download():
    row = db.execute("SELECT filename FROM exports WHERE id = ?", (request.args["id"],))
    with open(os.path.join("/app/exports", row["filename"])) as f:
        return f.read()
''')
    p = scan(t)
    assert "RC1.1" in ids(p), f"expected RC1.1, got {ids(p)}"
    assert "RC1.2" in ids(p), f"expected RC1.2 too, got {ids(p)}"
    return d


@case("RC1.1 stays quiet when the create step really writes the artefact")
def _():
    d, t = bundle('''
from flask import Flask, request, jsonify
import os
app = Flask(__name__)

@app.route("/api/exports", methods=["POST"])
def make_export():
    name = request.json["filename"]
    db.execute("INSERT INTO exports (filename) VALUES (?)", (name,))
    with open(os.path.join("/app/exports", "rpt.csv"), "w") as f:
        f.write(render_report())
    return jsonify({"ok": True})

@app.route("/api/exports/download")
def download():
    row = db.execute("SELECT filename FROM exports WHERE id = ?", (request.args["id"],))
    with open(os.path.join("/app/exports", row["filename"])) as f:
        return f.read()
''')
    p = scan(t)
    assert "RC1.1" not in ids(p), f"false positive: {ids(p)}"
    return d


# --------------------------------------------------------------------- RC3 / RC4

@case("RC3.1 fires on an answer-shaped decoy field, RC3.2 on a self-asserted authority")
def _():
    d, t = bundle('''
from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/internal/status")
def status():
    # decoy value, deliberately misleading
    return jsonify({"svc_flag": DECOY, "authoritative": True})
''')
    p = scan(t)
    assert "RC3.1" in ids(p), f"expected RC3.1, got {ids(p)}"
    assert "RC3.2" in ids(p), f"expected RC3.2, got {ids(p)}"
    return d


@case("RC4.1 fires on an egress filter naming one service, not a range class")
def _():
    d, t = bundle('''
from flask import Flask, request, jsonify
app = Flask(__name__)

def block_internal(url):
    if "inventory_service" in url:
        return True
    return False

@app.route("/api/webhook", methods=["POST"])
def webhook():
    url = request.json["url"]
    if block_internal(url):
        return jsonify({"error": "blocked"}), 403
    return jsonify(fetch(url))
''')
    p = scan(t)
    assert "RC4.1" in ids(p), f"expected RC4.1, got {ids(p)}"
    return d


@case("RC4.1 stays quiet on a policy that rejects a range class")
def _():
    d, t = bundle('''
import ipaddress
from flask import Flask, request, jsonify
app = Flask(__name__)

def block_internal(host):
    ip = ipaddress.ip_address(resolve(host))
    return ip.is_private or ip.is_loopback or ip.is_link_local

@app.route("/api/webhook", methods=["POST"])
def webhook():
    url = request.json["url"]
    if block_internal(url):
        return jsonify({"error": "blocked"}), 403
    return jsonify(fetch(url))
''')
    p = scan(t)
    assert "RC4.1" not in ids(p), f"false positive: {ids(p)}"
    return d


# --------------------------------------------------------------------- RC5

@case("RC5.2 fires when an endpoint returns more than one ground-truth value")
def _():
    d, t = bundle('''
from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/internal/verifier/audit")
def audit():
    return jsonify({"secrets": {"t1": _T1, "t2": _T2}})
''', tests='#!/bin/bash\ncurl /internal/verifier/audit\n',
        extra={"tests/solve.py": "_T1 = 1\n_T2 = 2\n"})
    p = scan(t)
    assert "RC5.2" in ids(p), f"expected RC5.2, got {ids(p)}"
    return d


@case("RC5.3 fires on a secret that degrades to a constant")
def _():
    d, t = bundle('''
import os
from flask import Flask
app = Flask(__name__)
SVC_SECRET = os.environ.get("SVC_SECRET", "no-secret-configured")
''')
    p = scan(t)
    assert "RC5.3" in ids(p), f"expected RC5.3, got {ids(p)}"
    return d


@case("readable-source findings are P1 for a file-read task and P2 otherwise")
def _():
    app = '''
import os
from flask import Flask
app = Flask(__name__)
SVC_SECRET = os.environ.get("SVC_SECRET", "no-secret-configured")

@app.route("/api/download")
def dl():
    with open(request.args["file"]) as f:
        return f.read()
'''
    d1, t1 = bundle(app, cwe="CWE-22")
    sev_readable = [f["severity"] for f in scan(t1)["findings"] if f["id"] == "RC5.3"]
    shutil.rmtree(d1, ignore_errors=True)
    d2, t2 = bundle('''
import os
from flask import Flask
app = Flask(__name__)
SVC_SECRET = os.environ.get("SVC_SECRET", "no-secret-configured")
''', cwe="CWE-89")
    sev_opaque = [f["severity"] for f in scan(t2)["findings"] if f["id"] == "RC5.3"]
    assert sev_readable == ["P1"], f"file-read task: expected P1, got {sev_readable}"
    assert sev_opaque == ["P2"], f"non-file-read task: expected P2, got {sev_opaque}"
    return d2


# --------------------------------------------------------------------- RC6

@case("RC6.1 fires on interpolated SQL and RC6.3 on a privilege field in an allowlist")
def _():
    d, t = bundle('''
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/api/reports/x")
def report():
    name = get_stored_name()
    return jsonify(db.execute(f"SELECT * FROM t WHERE n LIKE '%{name}%'"))

@app.route("/api/profile", methods=["PUT"])
def prof():
    allowed = {"full_name", "email", "is_admin", "api_key"}
    for k in request.json:
        if k in allowed:
            db.execute("UPDATE users SET " + k + " = ?", (request.json[k],))
    return jsonify({})
''')
    p = scan(t)
    assert "RC6.1" in ids(p), f"expected RC6.1, got {ids(p)}"
    assert "RC6.3" in ids(p), f"expected RC6.3, got {ids(p)}"
    priv = [f for f in p["findings"] if f["id"] == "RC6.3"][0]
    assert priv["severity"] == "P0", f"is_admin allowlist should be P0, got {priv['severity']}"
    return d


@case("the intended sink is demoted to P2 and labelled, not reported as unintended")
def _():
    d, t = bundle('''
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/api/reports/supplier-products")
def report():
    name = get_stored_name()
    return jsonify(db.execute(f"SELECT * FROM sp WHERE n LIKE '%{name}%'"))
''', solve='''
import requests
BASE = "http://web:8080"
requests.get(f"{BASE}/api/reports/supplier-products?supplier_id=1")
''')
    p = scan(t)
    f = [x for x in p["findings"] if x["id"] == "RC6.1"]
    assert f, f"RC6.1 should still be reported, got {ids(p)}"
    assert f[0]["severity"] == "P2", f"intended sink should be P2, got {f[0]['severity']}"
    assert f[0]["title"].startswith("INTENDED SINK"), f[0]["title"]
    assert f[0]["on_intended_path"] is True
    return d


@case("RC6.2 ignores a public catalogue object and fires on a scoped-sibling case")
def _():
    d, t = bundle('''
from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/api/products/<int:pid>")
def product(pid):
    return jsonify(db.execute("SELECT * FROM products WHERE id = ?", (pid,)))

@app.route("/api/orders/<int:oid>")
def order(oid):
    row = db.execute("SELECT * FROM orders WHERE id = ?", (oid,))
    return jsonify({"secret_note": row["secret_note"]})

@app.route("/api/orders/my/<int:oid>")
def my_order(oid):
    return jsonify(db.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (oid, g.user)))
''')
    p = scan(t)
    hits = [f["cite"] for f in p["findings"] if f["id"] == "RC6.2"]
    assert any("orders" not in h or True for h in hits), hits
    titles = [f["title"] for f in p["findings"] if f["id"] == "RC6.2"]
    assert any("/api/orders/<int:oid>" in x for x in titles), f"expected the orders BOLA, got {titles}"
    assert not any("/api/products" in x for x in titles), f"products is public, got {titles}"
    return d


@case("RC6.4 fires on an unfiltered server-side fetcher")
def _():
    d, t = bundle('''
import requests
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/api/import-url", methods=["POST"])
def imp():
    url = request.json["url"]
    return jsonify({"body": requests.get(url).text})
''')
    p = scan(t)
    assert "RC6.4" in ids(p), f"expected RC6.4, got {ids(p)}"
    return d


# --------------------------------------------------------------------- RC7 / RC8

@case("RC7.1 fires on a disclosure record written to the verifier's minimum")
def _():
    d, t = bundle('''
import datetime
from flask import Flask
app = Flask(__name__)

def _record(tag, endpoint, path):
    _audit[tag] = {"endpoint": endpoint, "path": path,
                   "timestamp": datetime.datetime.utcnow().isoformat()}
''')
    p = scan(t)
    f = [x for x in scan(t)["findings"] if x["id"] == "RC7.1"]
    assert f, f"expected RC7.1, got {ids(p)}"
    assert "actor" in f[0]["title"], f[0]["title"]
    return d


@case("RC7.1 stays quiet on a full security event")
def _():
    d, t = bundle('''
import datetime
from flask import Flask
app = Flask(__name__)

def record_disclosure(user_id, draft_id, remote_addr, status_code):
    _audit.append({"user_id": user_id, "draft_id": draft_id,
                   "remote_addr": remote_addr, "status_code": status_code,
                   "timestamp": datetime.datetime.utcnow().isoformat()})
''')
    p = scan(t)
    assert "RC7.1" not in ids(p), f"false positive: {[f['title'] for f in p['findings']]}"
    return d


@case("RC8.2 fires on a security boundary with no membership lifecycle")
def _():
    d, t = bundle('''
from flask import Flask, request, jsonify
app = Flask(__name__)

def init():
    db.execute("CREATE TABLE users (id INT, email TEXT, workspace TEXT);")

@app.route("/api/profile", methods=["PUT"])
def prof():
    allowed_model_fields = ["email", "workspace"]
    for f in allowed_model_fields:
        if f in request.json:
            db.execute("UPDATE users SET " + f + " = ?", (request.json[f],))
    return jsonify({})

@app.route("/api/drafts/<ref>")
def draft(ref):
    row = db.execute("SELECT id, title, workspace FROM drafts WHERE ref = ?", (ref,))
    if row["workspace"] != g.current_user.get("workspace"):
        return jsonify({"error": "not found"}), 404
    return jsonify(row)
''')
    p = scan(t)
    assert "RC8.2" in ids(p), f"expected RC8.2, got {ids(p)}"
    return d


# --------------------------------------------------------------------- RC9

@case("RC9.1 fires on a proxy that publishes a token then requires a request to match it")
def _():
    d, t = bundle("# n/a\n", extra={"environment/gateway/app.py": '''
import re, secrets, requests
from flask import Flask, request, jsonify
app = Flask(__name__)
REGISTRATION_TOKEN = secrets.token_hex(8)

def proxy(path):
    return requests.get("http://upstream" + path)

@app.route("/<path:path>", methods=["GET", "PUT"])
def handle(path):
    escalated_username = re.match(r"_users/org.couchdb.user:(.+)", path)
    resp = proxy(path)
    if escalated_username == REGISTRATION_TOKEN:
        pending_escalations.add(escalated_username)
    resp_headers = {}
    resp_headers["X-Registration-Token"] = REGISTRATION_TOKEN
    return resp
'''})
    p = scan(t)
    assert "RC9.1" in ids(p), f"expected RC9.1, got {ids(p)}"
    return d


@case("RC9.1 stays quiet when the published value only SELECTS a record (joomla pattern)")
def _():
    d, t = bundle("# n/a\n", extra={"environment/gateway/app.py": '''
import secrets, requests
from flask import Flask, jsonify
app = Flask(__name__)
REF = secrets.token_hex(6)

def proxy(path):
    return requests.get("http://joomla" + path)

def inject_config(body):
    body["audit_record"] = REF
    return body

def inject_users(body):
    records = []
    for r in body["data"]:
        records.append({"record_id": REF if r["id"] == 1 else secrets.token_hex(6)})
    body["verification_records"] = records
    return body
'''})
    p = scan(t)
    assert "RC9.1" not in ids(p), f"false positive: {[f['title'] for f in p['findings']]}"
    assert "RC9.3" in ids(p), f"the accepted enrichment pattern should be recorded, got {ids(p)}"
    return d


@case("RC9.2 fires on an http.server proxy that synthesizes an API the product lacks")
def _():
    d, t = bundle("# flask app not used here\n", extra={"environment/gateway/app.py": '''
from urllib.parse import parse_qs
import http.client

RELEASE_ID = "r1"
PREPARE_TICKET = "tkt"

class H(BaseHTTPRequestHandler):
    def _manifest(self, parsed):
        if parsed.path == f"/api/releases/{RELEASE_ID}/manifest":
            json_response(self, 200, {"legacy_cache_path": SECRET_DIRECTORY,
                                      "license_record": SECRET_FILENAME})
            return True
        return False

    def proxy(self, parsed):
        c = http.client.HTTPConnection("appserver49")
        c.request(self.command, self.path)
'''})
    p = scan(t)
    assert "RC9.2" in ids(p), f"expected RC9.2, got {ids(p)}"
    return d


@case("RC9.2 does not flag the verifier's own diagnostic endpoint")
def _():
    d, t = bundle("# n/a\n", extra={"environment/gateway/app.py": '''
import requests
from flask import Flask, jsonify, request
app = Flask(__name__)

def proxy(path):
    return requests.get("http://upstream/" + path)

@app.route("/internal/diag/audit")
def diag():
    if request.headers.get("X-Internal-Verifier") != VERIFIER_TOKEN:
        return "", 404
    return jsonify({"audit": AUDIT})
'''})
    p = scan(t)
    assert "RC9.2" not in ids(p), f"grading plumbing is RC5's job, got {ids(p)}"
    return d


@case("a bundle with no parseable routes reports zero routes rather than a clean pass")
def _():
    d, t = bundle("// this app is Go\npackage main\n")
    p = scan(t)
    assert p["routes"] == [], p["routes"]
    assert "no mechanical realism lead" in p["verdict"]["disposition"]
    assert "does NOT clear the bundle" in p["verdict"]["why"]
    return d


@case("the disposition separates on-path blockers from off-path fix-list items")
def _():
    d, t = bundle('''
from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/internal/status")
def status():
    # decoy, deliberately misleading
    return jsonify({"svc_flag": DECOY})
''', solve='''
import requests
requests.get("http://web:8080/internal/status")
''')
    p = scan(t)
    assert p["verdict"]["counts"]["on_path_blockers"] >= 1, p["verdict"]
    return d


def main():
    print(f"realism scanner selftest -- {len(RESULTS)} cases\n")
    fails = [r for r in RESULTS if not r[0]]
    for ok, name, msg in RESULTS:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"        {msg}")
    print(f"\n{len(RESULTS) - len(fails)}/{len(RESULTS)} passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
