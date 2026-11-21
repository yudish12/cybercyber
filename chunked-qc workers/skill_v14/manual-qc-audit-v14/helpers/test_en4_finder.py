#!/usr/bin/env python3
"""
TDD tests for en4_finder.py — the static FINDER layer of the EN4 eval
(Environment: Operational & Reproducibility).

V19 NOTE: Provenance/Licensing moved to en5_finder.py (see its module docstring
for the EN5-naming-collision warning). en4_finder.py now covers only:
  - image discovery (Dockerfile FROM + compose image:)
  - [Fail - Unbounded or Unpinned] (mutable tag, no @sha256 digest)
  - [Fail - Reproducibility] (static runtime-internet / IP-allowlist signals)
The wheel-license / NOTICE-coverage fixture that used to live here moved to
test_en5_finder.py along with the behavior it tests.

Run:  python3 -I test_en4_finder.py
"""
import os, sys, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import en4_finder  # noqa: E402


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))


def build_fixture(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    _w(os.path.join(t, "task.toml"), '[task]\nname = "acme/en4"\n')
    # pinned image (clean)
    _w(os.path.join(env, "gateway", "Dockerfile"),
       "FROM python:3.12-slim@sha256:aaaa\nCOPY . /app\n")
    # UNPINNED mutable tag
    _w(os.path.join(env, "db", "Dockerfile"),
       "FROM mariadb:11.4\nCOPY . /db\n")
    _w(os.path.join(env, "NOTICE.md"), "irrelevant to en4 now\n")
    _w(os.path.join(env, "docker-compose.yaml"), '''
        services:
          main:
            build: ./gateway
          db:
            build: ./db
    ''')
    # runtime internet signal
    _w(os.path.join(env, "gateway", "entrypoint.sh"),
       "#!/bin/sh\napt-get update && apt-get install -y curl\ncurl https://example.com/setup.sh | sh\n")
    return t


_MAIN_WAIT = ("'i=0; while [ $$i -lt 120 ]; do curl -s -o /dev/null --max-time 3 http://web:8080/ "
              "&& break; sleep 2; i=$$((i+1)); done; exec sleep infinity'")


def build_timeouts(root, caller_timeout, behavior_kind, verifier_total, extra_tests=None):
    """agent waits 120 x (2s + 3s) = 240..600s; behavior.sh is a 120x2s attempt loop calling a
    function that does the curl, or a 600s SECONDS deadline loop, or a single-shot probe."""
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    _w(os.path.join(t, "task.toml"),
       '[task]\nname = "acme/to"\n\n[verifier]\ntimeout_sec = %s\nuser = "root"\n' % verifier_total)
    _w(os.path.join(env, "docker-compose.yaml"),
       "services:\n  main:\n    command:\n      - sh\n      - -c\n      - " + _MAIN_WAIT + "\n  web:\n    build: ./web\n")
    fetch = 'fetch_audit() {\n  curl -s --max-time 3 "http://web:8080/internal/diag/audit"\n}\n'
    if behavior_kind == "attempts":
        body = fetch + ('_i=0\nwhile [ "$_i" -lt 120 ]; do\n  AUDIT="$(fetch_audit)"\n'
                        '  [ -n "$AUDIT" ] && break\n  sleep 2\n  _i=$((_i+1))\ndone\n')
    elif behavior_kind == "deadline":
        body = fetch + ('BUDGET_SECS=600\n_deadline=$((SECONDS + BUDGET_SECS))\nwhile :; do\n'
                        '  AUDIT="$(fetch_audit)"\n  [ -n "$AUDIT" ] && break\n'
                        '  [ "$SECONDS" -ge "$_deadline" ] && break\n  sleep 2\ndone\n')
    else:
        body = fetch + 'AUDIT="$(fetch_audit)"\n'
    _w(os.path.join(t, "tests", "behavior", "behavior.sh"), "#!/bin/bash\n" + body)
    _w(os.path.join(t, "tests", "behavior", "check.py"),
       "import rewardkit as rk\nfrom pathlib import Path\n"
       "rk.command_succeeds(cmd=f\"bash {Path(__file__).parent / 'behavior.sh'}\", timeout=%d)\n" % caller_timeout)
    _w(os.path.join(t, "tests", "test.sh"), 'rewardkit "$HERE/behavior"\nrewardkit "$HERE/report"\n')
    _w(os.path.join(t, "tests", "report", "rubric.toml"), '[judge]\ntimeout = 600\n')
    for rel, txt in (extra_tests or {}).items():
        _w(os.path.join(t, rel), txt)
    return t


PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def main():
    tmp = tempfile.mkdtemp(prefix="en4fix_")
    try:
        t = build_fixture(tmp)
        r = en4_finder.find(t)
        unpin = r["checks"]["unpinned_images"]
        repro = r["checks"]["reproducibility"]

        check("en4 output no longer carries provenance_licensing (moved to en5_finder)",
              "provenance_licensing" not in r["checks"])

        def hit(items, needle, field="component"):
            return any(needle in str(it.get(field, "")) or needle in str(it) for it in items)

        check("both base images discovered",
              any("python:3.12-slim" in str(i) for i in r["images"]) and
              any("mariadb:11.4" in str(i) for i in r["images"]))

        check("mariadb:11.4 (no digest) -> unpinned fail_candidate",
              hit(unpin["fail_candidates"], "mariadb"))
        check("pinned python image -> NOT unpinned",
              not hit(unpin["fail_candidates"], "python:3.12-slim"))

        check("runtime internet (curl/apt) surfaced",
              any("curl" in str(x) or "apt-get" in str(x) or "example.com" in str(x)
                  for x in (repro.get("candidates", []) + repro.get("live_items", []))))

        check("top-level NOTICE.md still detected (informational only now)",
              r["notice"]["present"] and r["notice"]["path"].endswith("environment/NOTICE.md"))

        # ---- timeout budget (v1.6) ----
        def tb(*a, **k):
            d = tempfile.mkdtemp(prefix="en4to_", dir=tmp)
            return en4_finder.find(build_timeouts(d, *a, **k))["checks"]["timeout_budget"]

        def has(res, needle):
            return any(needle in c["issue"] for c in res["candidates"])

        a = tb(60, "attempts", 1300)
        check("agent wait parsed from compose main: floor 240s / worst 600s",
              a["agent_wait"]["floor"] == 240 and a["agent_wait"]["worst"] == 600)
        check("caller timeout=60 < behavior.sh 120x2s loop -> caller-kills-callee candidate",
              has(a, "caller timeout 60s < callee"))
        check("loop calling fetch_audit() picks up the function's --max-time (worst 600, no budget flag)",
              not has(a, "verifier wait budget"))

        b = tb(660, "deadline", 1500)
        check("600s SECONDS deadline + caller 660 + verifier 1500 -> clean", b["candidates"] == [])

        c = tb(660, "deadline", 1200)
        check("behavior 660 + report judge 600 > verifier timeout_sec 1200 -> phase-sum candidate",
              has(c, "verifier phases need"))

        d = tb(60, "single", 1300)
        check("single-shot behavior while the agent waits 600s -> no-verifier-wait candidate",
              has(d, "no verifier-side wait"))

        e = tb(660, "deadline", 1500, extra_tests={
            "tests/isolation_test.sh": "for i in $(seq 1 5); do curl -s --max-time 1 http://web/; sleep 1; done\n"})
        check("standalone tests/isolation_test.sh (not run by test.sh) is not a verifier wait",
              e["candidates"] == [] and "tests/isolation_test.sh" not in e["verifier_waits"])

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
