#!/usr/bin/env python3
"""
TDD tests for en3_finder.py — static FINDER layer of the EN3 eval
(Environment: Credential & Egress Hygiene).

Design:
  - [Fail - Credential Hygiene]: a non-scored privileged credential that is a reused/
    guessable LITERAL, or hardcoded in served source or compose/.env. A value read from
    a mounted file / env ref ($(...), ${VAR}) is CLEAN. Usernames/logins are identities,
    not secrets.
  - [Fail - Egress Hygiene]: an outbound filter that names a HOSTNAME/service identity
    instead of blocking by IP-address class, so the host is reachable by numeric IP.
Bias to flag; the reader confirms.

Run:  python3 -I test_en3_finder.py
"""
import os, sys, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import en3_finder  # noqa: E402


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))


def build_good(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    _w(os.path.join(env, "docker-compose.yaml"), '''
        services:
          db:
            environment:
              MYSQL_USER: dolibarr
              MYSQL_DATABASE: dolibarr
            networks: [backend]
        networks:
          backend:
            internal: true
    ''')
    _w(os.path.join(env, "dolibarr", "db-entrypoint.sh"),
       '#!/bin/bash\nexport MYSQL_ROOT_PASSWORD="$(cat /doli-creds/.db_root_password)"\n'
       'export MYSQL_PASSWORD="$(cat /doli-creds/.db_password)"\n')
    # egress allowlist by IP class (CLEAN)
    _w(os.path.join(env, "agent", "egress.conf"),
       "allow 10.0.0.0/8\nallow 172.16.0.0/12\ndeny all\n")
    return t


def build_bad_cred(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    # literal guessable password in compose
    _w(os.path.join(env, "docker-compose.yaml"), '''
        services:
          db:
            environment:
              MYSQL_USER: dolibarr
              MYSQL_ROOT_PASSWORD: changeme
    ''')
    # hardcoded password literal in served source
    _w(os.path.join(env, "gateway", "config.py"),
       'ADMIN_PASSWORD = "admin123"\nDB_USER = "svc"\n')
    return t


def build_bad_egress(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    # hostname-based egress filter (reachable by IP)
    _w(os.path.join(env, "agent", "proxy.sh"),
       "#!/bin/sh\nexport NO_PROXY=gateway,db\n"
       "gost -L :8080 --host=gateway.internal\n")
    return t


PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def cand(r, key):
    return r["checks"][key]["candidates"]


def main():
    dirs = []
    try:
        g = tempfile.mkdtemp(); dirs.append(g); gr = en3_finder.find(build_good(g))
        c = tempfile.mkdtemp(); dirs.append(c); cr = en3_finder.find(build_bad_cred(c))
        e = tempfile.mkdtemp(); dirs.append(e); er = en3_finder.find(build_bad_egress(e))

        def anyfile(items, needle):
            return any(needle in str(it.get("file", "")) for it in items)

        # 1. GOOD: file-read password -> NOT a credential candidate
        check("GOOD: $(cat ...) password -> not flagged",
              len(cand(gr, "credential_hygiene")) == 0)

        # 2. BAD: literal guessable password in compose -> candidate
        check("BAD: literal MYSQL_ROOT_PASSWORD -> candidate",
              anyfile(cand(cr, "credential_hygiene"), "docker-compose.yaml"))

        # 3. BAD: hardcoded password in served source -> candidate
        check("BAD: ADMIN_PASSWORD literal in config.py -> candidate",
              anyfile(cand(cr, "credential_hygiene"), "config.py"))

        # 4. usernames/logins are NOT secrets
        check("GOOD: MYSQL_USER/DB_USER not flagged as credentials",
              not any("USER" in str(x.get("key", "")).upper() for x in cand(cr, "credential_hygiene")))

        # 5. BAD egress: hostname filter -> candidate
        check("BAD: hostname egress filter -> candidate",
              anyfile(cand(er, "egress_hygiene"), "proxy.sh"))

        # 6. GOOD egress: CIDR/IP allowlist -> NOT flagged
        check("GOOD: CIDR allowlist -> not flagged",
              len(cand(gr, "egress_hygiene")) == 0)

        # 7. files_to_read populated
        check("credential files_to_read includes compose",
              any("docker-compose" in f for f in cr["checks"]["credential_hygiene"]["files_to_read"]))

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
