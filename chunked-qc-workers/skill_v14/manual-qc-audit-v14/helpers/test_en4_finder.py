#!/usr/bin/env python3
"""
TDD tests for en4_finder.py — the static FINDER layer of the EN4 eval
(Environment: Operational & Reproducibility; #1 recurring fail).

Pins the design: enumerate every base image (Dockerfile FROM + compose image:)
and every vendored wheel, cross-reference the TOP-LEVEL environment/NOTICE.md for
a license + digest pin, read each wheel's METADATA license to catch blanket/
mismatch claims, flag mutable (unpinned) tags, and surface reproducibility signals.
Bias to flag: a literal provenance gap is a FAIL-candidate; runtime-only
reproducibility is LIVE; nothing is dropped.

Run:  python3 -I test_en4_finder.py
"""
import os, sys, io, zipfile, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import en4_finder  # noqa: E402


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


def build_fixture(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")

    # task.toml (minimal)
    _w(os.path.join(t, "task.toml"), '[task]\nname = "acme/en4"\n')

    # Dockerfile A: pinned + will be covered in NOTICE  (CLEAN)
    _w(os.path.join(env, "gateway", "Dockerfile"),
       "FROM python:3.12-slim@sha256:aaaa\nCOPY . /app\n")
    # Dockerfile B: UNPINNED mutable tag + NOT in NOTICE  (two fails)
    _w(os.path.join(env, "db", "Dockerfile"),
       "FROM mariadb:11.4\nCOPY . /db\n")

    # a vendored wheel whose METADATA says MPL-2.0 ...
    _wheel(os.path.join(env, "agent", "vendor-wheels", "certifi-2026.1.0-py3-none-any.whl"),
           "certifi", "2026.1.0", "MPL-2.0")
    # ... but NOTICE will blanket it as MIT (mismatch)

    # top-level NOTICE: covers gateway's python image, blankets the wheel as MIT,
    # and OMITS the mariadb image entirely.
    _w(os.path.join(env, "NOTICE.md"), '''
        # NOTICE

        | Component | Source | License | Digest pin |
        |---|---|---|---|
        | Python slim image | python:3.12-slim | Python-2.0 | `sha256:aaaa` |

        ## Vendored wheels
        | Wheel | Source | License |
        |---|---|---|
        | `certifi-2026.1.0-py3-none-any.whl` | certifi | MIT |
    ''')

    # a decoy NESTED notice that must NOT rescue coverage
    _w(os.path.join(env, "db", "NOTICE.md"), "mariadb GPL-2.0-only sha256:bbbb\n")

    # compose with an entrypoint that reaches the internet at runtime (repro signal)
    _w(os.path.join(env, "docker-compose.yaml"), '''
        services:
          main:
            build: ./gateway
          db:
            build: ./db
    ''')
    _w(os.path.join(env, "gateway", "entrypoint.sh"),
       "#!/bin/sh\napt-get update && apt-get install -y curl\ncurl https://example.com/setup.sh | sh\n")
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
        prov = r["checks"]["provenance_licensing"]
        unpin = r["checks"]["unpinned_images"]
        repro = r["checks"]["reproducibility"]

        def hit(items, needle, field="component"):
            return any(needle in str(it.get(field, "")) or needle in str(it) for it in items)

        # images enumerated from Dockerfiles
        check("both base images discovered",
              any("python:3.12-slim" in str(i) for i in r["images"]) and
              any("mariadb:11.4" in str(i) for i in r["images"]))

        # 1. unpinned mutable tag -> fail_candidate
        check("mariadb:11.4 (no digest) -> unpinned fail_candidate",
              hit(unpin["fail_candidates"], "mariadb"))
        check("pinned python image -> NOT unpinned",
              not hit(unpin["fail_candidates"], "python:3.12-slim"))

        # 2. image omitted from NOTICE -> provenance fail_candidate
        check("mariadb omitted from NOTICE -> provenance fail_candidate",
              hit(prov["fail_candidates"], "mariadb"))

        # 3. nested NOTICE must NOT rescue coverage
        check("nested db/NOTICE.md does not rescue mariadb",
              hit(prov["fail_candidates"], "mariadb"))

        # 4. wheel license mismatch (METADATA MPL-2.0 vs NOTICE MIT) -> fail_candidate
        check("certifi MPL-2.0 vs NOTICE MIT -> license mismatch fail_candidate",
              hit(prov["fail_candidates"], "certifi"))

        # 5. covered+pinned image is clean
        check("python image covered+pinned -> not a provenance fail",
              not hit(prov["fail_candidates"], "python:3.12-slim"))

        # 6. reproducibility: runtime internet signal surfaced (candidate or LIVE)
        check("runtime internet (curl/apt) surfaced",
              any("curl" in str(x) or "apt-get" in str(x) or "example.com" in str(x)
                  for x in (repro.get("candidates", []) + repro.get("live_items", []))))

        # 7. NOTICE present is detected (top-level)
        check("top-level NOTICE.md detected",
              r["notice"]["present"] and r["notice"]["path"].endswith("environment/NOTICE.md"))

        # 8. files_to_read populated for the reader
        check("provenance lists files_to_read incl NOTICE",
              any("NOTICE.md" in f for f in prov.get("files_to_read", [])))

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
