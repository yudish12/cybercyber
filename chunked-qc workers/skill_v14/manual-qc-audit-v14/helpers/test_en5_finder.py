#!/usr/bin/env python3
"""
TDD tests for en5_finder.py — static FINDER layer of the OFFICIAL V19 EN5 eval
(Provenance / Licensing, split out of EN4).

Pins the design:
  - images/wheels properly licensed in NOTICE.md -> clean (0 fail, 0 non-fail).
  - a component missing from NOTICE but credited ELSEWHERE in the task files
    (the V19 Non-Fail carve-out, score 3) -> non_fail candidate, NOT a fail.
  - a component not attributed ANYWHERE -> fail candidate.
  - OS-package extraction from a multi-line `apt-get install \` Dockerfile block
    (flags/noise filtered, real package names kept).
  - regression: the real 6afb975e9c3753a2c8232a77 pre-fix miss (curl/dnsutils/jq/
    tmux/default-mysql-client installed, attributed nowhere) is caught; the
    post-fix NOTICE (with the OS packages block added) clears it.

Run:  python3 -I test_en5_finder.py
"""
import os, sys, io, zipfile, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import en5_finder  # noqa: E402


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))


def _wheel(path, dist, version, license_str):
    """Write a minimal valid .whl (zip) whose dist-info METADATA names a license."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    meta = f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\nLicense: {license_str}\n"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{dist}-{version}.dist-info/METADATA", meta)


PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


def main():
    dirs = []
    try:
        # ---- clean: image properly licensed in NOTICE ----
        g = tempfile.mkdtemp(); dirs.append(g)
        gt = os.path.join(g, "task")
        _w(os.path.join(gt, "environment", "agent", "Dockerfile"),
           "FROM python:3.12-slim@sha256:aaaa\n")
        _w(os.path.join(gt, "environment", "NOTICE.md"),
           "- agent: python:3.12-slim@sha256:aaaa\nLicenses: Python PSF-2.0.\n")
        gr = en5_finder.find(gt)
        check("GOOD: image licensed in NOTICE -> clean",
              len(gr["checks"]["provenance_licensing"]["fail_candidates"]) == 0
              and len(gr["checks"]["provenance_licensing"]["non_fail_candidates"]) == 0)

        # ---- credited elsewhere (Non-Fail, score 3) ----
        e = tempfile.mkdtemp(); dirs.append(e)
        et = os.path.join(e, "task")
        _w(os.path.join(et, "environment", "agent", "Dockerfile"),
           "FROM python:3.12-slim@sha256:bbbb\n")
        _w(os.path.join(et, "environment", "NOTICE.md"),
           "- agent: python:3.12-slim@sha256:bbbb\n")  # mentioned, no license token
        _w(os.path.join(et, "environment", "agent", "THIRD_PARTY_LICENSES.txt"),
           "python:3.12-slim -- Python-2.0 license, PSF.\n")  # credited elsewhere
        er = en5_finder.find(et)
        epv = er["checks"]["provenance_licensing"]
        check("CREDITED ELSEWHERE: downgraded to Non-Fail, not Fail",
              len(epv["fail_candidates"]) == 0 and len(epv["non_fail_candidates"]) == 1)
        check("CREDITED ELSEWHERE: cites the real file:line",
              "THIRD_PARTY_LICENSES.txt" in epv["non_fail_candidates"][0]["issue"])

        # ---- not attributed anywhere (real Fail) ----
        b = tempfile.mkdtemp(); dirs.append(b)
        bt = os.path.join(b, "task")
        _w(os.path.join(bt, "environment", "agent", "Dockerfile"),
           "FROM python:3.12-slim@sha256:cccc\n")
        _w(os.path.join(bt, "environment", "NOTICE.md"), "Nothing relevant here.\n")
        br = en5_finder.find(bt)
        bpv = br["checks"]["provenance_licensing"]
        check("NOT ATTRIBUTED ANYWHERE: real Fail candidate",
              len(bpv["fail_candidates"]) == 1 and len(bpv["non_fail_candidates"]) == 0)

        # ---- OS-package extraction from a multi-line apt-get install block ----
        o = tempfile.mkdtemp(); dirs.append(o)
        ot = os.path.join(o, "task")
        _w(os.path.join(ot, "environment", "agent", "Dockerfile"), '''
            FROM python:3.12-slim@sha256:dddd
            RUN apt-get update && apt-get install -y --no-install-recommends \\
                curl dnsutils jq tmux && \\
                rm -rf /var/lib/apt/lists/*
        ''')
        pkgs = en5_finder.collect_os_packages(ot)
        names = sorted(p["package"] for p in pkgs)
        check("OS-package extraction: all 4 real packages found",
              names == ["curl", "dnsutils", "jq", "tmux"])
        check("OS-package extraction: flags/noise filtered out",
              not any(n.startswith("-") or n in ("update", "rm") for n in names))

        # ---- regression: real pre-fix 6afb975e miss ----
        pre = tempfile.mkdtemp(); dirs.append(pre)
        pt = os.path.join(pre, "task")
        _w(os.path.join(pt, "environment", "agent", "Dockerfile"), '''
            FROM python:3.12-slim@sha256:eeee
            RUN apt-get update && apt-get install -y --no-install-recommends \\
                curl dnsutils jq tmux && \\
                rm -rf /var/lib/apt/lists/*
        ''')
        _w(os.path.join(pt, "environment", "gateway", "Dockerfile"), '''
            FROM python:3.11-slim@sha256:ffff
            RUN apt-get update && apt-get install -y --no-install-recommends \\
                default-mysql-client && \\
                rm -rf /var/lib/apt/lists/*
        ''')
        _w(os.path.join(pt, "environment", "NOTICE.md"),
           "- agent: python:3.12-slim@sha256:eeee\n"
           "- gateway: python:3.11-slim@sha256:ffff\n"
           "Licenses: Python PSF.\n")  # images covered; OS packages are not
        prer = en5_finder.find(pt)
        prepv = prer["checks"]["provenance_licensing"]
        fail_names = {c["component"] for c in prepv["fail_candidates"]}
        check("REGRESSION (pre-fix 6afb975e): all 5 OS packages flagged",
              {"curl", "dnsutils", "jq", "tmux", "default-mysql-client"} <= fail_names)

        # post-fix: NOTICE now covers the OS packages block
        _w(os.path.join(pt, "environment", "NOTICE.md"),
           "- agent: python:3.12-slim@sha256:eeee\n"
           "- gateway: python:3.11-slim@sha256:ffff\n"
           "Licenses: Python PSF.\n\n"
           "OS packages (apt, Debian repositories):\n"
           "- curl -- curl (MIT/X derivate), dnsutils (ISC/MPL-2.0), jq (MIT), tmux (ISC).\n"
           "- default-mysql-client -- GPL-2.0.\n")
        postr = en5_finder.find(pt)
        postpv = postr["checks"]["provenance_licensing"]
        check("REGRESSION (post-fix): all 5 OS packages now clean (0 fail)",
              len(postpv["fail_candidates"]) == 0)

        # ---- ported from the old en4 fixture: wheel-license mismatch + nested-NOTICE
        # ---- does-not-rescue-coverage (the old EN4 provenance behavior, preserved) ----
        m = tempfile.mkdtemp(); dirs.append(m)
        mt = os.path.join(m, "task")
        _w(os.path.join(mt, "environment", "gateway", "Dockerfile"),
           "FROM python:3.12-slim@sha256:aaaa\n")
        _w(os.path.join(mt, "environment", "db", "Dockerfile"), "FROM mariadb:11.4\n")
        _wheel(os.path.join(mt, "environment", "agent", "vendor-wheels",
                             "certifi-2026.1.0-py3-none-any.whl"),
               "certifi", "2026.1.0", "MPL-2.0")
        _w(os.path.join(mt, "environment", "NOTICE.md"), '''
            | Component | Source | License |
            |---|---|---|
            | Python slim image | python:3.12-slim | Python-2.0 |

            ## Vendored wheels
            | Wheel | Source | License |
            |---|---|---|
            | `certifi-2026.1.0-py3-none-any.whl` | certifi | MIT |
        ''')
        # a decoy NESTED notice that must NOT rescue mariadb's missing coverage
        _w(os.path.join(mt, "environment", "db", "NOTICE.md"), "mariadb GPL-2.0-only sha256:bbbb\n")
        mr = en5_finder.find(mt)
        mpv = mr["checks"]["provenance_licensing"]

        def hit(items, needle, field="component"):
            return any(needle in str(it.get(field, "")) for it in items)

        check("mariadb omitted from top-level NOTICE -> fail (nested NOTICE doesn't rescue)",
              hit(mpv["fail_candidates"], "mariadb"))
        check("certifi MPL-2.0 (METADATA) vs MIT (NOTICE) -> family-mismatch fail, not a gap",
              hit(mpv["fail_candidates"], "certifi")
              and any("MISMATCH" in c["issue"] for c in mpv["fail_candidates"] if "certifi" in c["component"]))
        check("covered+pinned python image is clean",
              not hit(mpv["fail_candidates"], "python:3.12-slim")
              and not hit(mpv["non_fail_candidates"], "python:3.12-slim"))
        check("files_to_read includes NOTICE.md",
              any("NOTICE.md" in f for f in mpv.get("files_to_read", [])))

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
