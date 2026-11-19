#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
en3_finder.py  --  static FINDER layer of the EN3 eval
(Environment: Credential & Egress Hygiene).

READ-ONLY. It POINTS; the reader decides.

  * [Fail - Credential Hygiene]: a non-scored privileged credential that is a LITERAL
    (hardcoded in compose/.env or served source), reused, or low-entropy/guessable. A
    value read from a mounted file or an env ref ($(...), ${VAR}, $VAR) is CLEAN.
    Usernames/logins are identities, not secrets -- never flagged.
  * [Fail - Egress Hygiene]: an outbound filter that names a HOSTNAME / service identity
    instead of blocking by IP-address class, so the same host is reachable by numeric IP.

Credential scan is scoped to compose/.env + author source (custom/gateway/*-init/
*-service/operator) to avoid vendored-default noise; the reader may look wider. Bias to
flag: a literal credential or a hostname egress entry is a candidate.

Usage:  python3 -I en3_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io

_CRED_KEY_RE = re.compile(r"(pass(?:word|wd)?|secret|api[_-]?key|\btoken\b|root_password|private_key)", re.I)
_GUESSABLE = {"admin", "password", "changeme", "root", "secret", "test", "123456",
              "12345678", "pass", "toor", "letmein", "default", "dolibarr"}
_IP_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_EGRESS_HINT_RE = re.compile(r"NO_PROXY|no_proxy|HTTPS?_PROXY|gost|--host|allow\b|egress|iptables|proxy", re.I)
_SRC_EXT = (".py", ".php", ".sh", ".ts", ".js", ".env", ".conf", ".cfg", ".ini")


def _read(p):
    try:
        with io.open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _is_author(rel):
    segs = rel.replace("\\", "/").split("/")
    for s in segs:
        if s in ("gateway", "custom", "operator", "operator-init", "agent"):
            return True
        if s.endswith("-init") or s.endswith("-service"):
            return True
    return False


def _is_literal(val):
    v = val.strip().strip('"\'').strip()
    if not v:
        return False
    if v.startswith("$") or "$(" in v or "${" in v:
        return False
    if v.lower().startswith(("cat ", "/", "./", "file:", "read ")):
        return False
    if "cat " in v or "/run/secrets" in v or v.lower() in ("none", "true", "false"):
        return False
    return True


# --------------------------------------------------------------------------- #
def _credential(task_dir):
    cands, files = [], set()
    env = os.path.join(task_dir, "environment")
    targets = []
    for name in ("environment/docker-compose.yaml", "environment/docker-compose.yml"):
        if os.path.exists(os.path.join(task_dir, name)):
            targets.append(name)
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if fn.endswith(_SRC_EXT) or fn == ".env" or fn.startswith(".env"):
                rel = os.path.relpath(os.path.join(dp, fn), task_dir)
                if rel in targets:
                    continue
                if _is_author(rel) or fn.startswith(".env") or fn.endswith((".env", ".conf", ".cfg", ".ini")):
                    targets.append(rel)

    _KEY = r"[A-Za-z0-9_]*(?:password|passwd|secret|api[_-]?key|private_key|\btoken)[A-Za-z0-9_]*"
    _COMPOSE = (".yaml", ".yml", ".env", ".conf", ".cfg", ".ini")
    # a line in source that is NOT a hardcoded literal: generation, env/file reads, SQL, comparisons
    _SKIP_SRC = re.compile(r"secrets\.|token_hex|token_urlsafe|urandom|uuid|randbytes|getenv|"
                           r"environ|request\.|\$\(|\$\{|\bcat\b|/run/secrets|==|!=|\?", re.I)
    for rel in targets:
        files.add(rel)
        is_compose = rel.endswith(_COMPOSE) or os.path.basename(rel).startswith(".env")
        for i, line in enumerate(_read(os.path.join(task_dir, rel)).splitlines(), 1):
            if is_compose:
                m = re.search(r"^\s*(" + _KEY + r")\s*[:=]\s*(\S+)", line, re.I)
                if not m:
                    continue
                key, rawval = m.group(1), m.group(2)
                if re.search(r"(user|login|username|host|db_name|database)", key, re.I):
                    continue
                if not _is_literal(rawval):
                    continue
                v = rawval.strip().strip('"\'')
            else:
                # SOURCE: require a genuine quoted-string literal value, and no gen/read/SQL
                if _SKIP_SRC.search(line):
                    continue
                m = re.search(r"\b(" + _KEY + r")\s*[:=]\s*[\"']([^\"']{3,})[\"']", line, re.I)
                if not m:
                    continue
                key, v = m.group(1), m.group(2)
                if re.search(r"(user|login|username)", key, re.I):
                    continue
            why = "hardcoded literal credential"
            if v.lower() in _GUESSABLE or len(v) < 8:
                why = "hardcoded, low-entropy/guessable credential"
            cands.append({"file": rel, "line": i, "key": key, "value": v[:40],
                          "why": why, "text": line.strip()[:160]})
    return {"label": "[Fail - Credential Hygiene]", "candidates": cands,
            "files_to_read": sorted(files),
            "note": "reader confirms each is a NON-SCORED privileged credential (not the generated "
                    "scored marker, not a username) and genuinely hardcoded/guessable."}


def _egress(task_dir):
    cands, files = [], set()
    env = os.path.join(task_dir, "environment")
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if not (fn.endswith((".sh", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".env")) or fn.startswith(".env")):
                continue
            rel = os.path.relpath(os.path.join(dp, fn), task_dir)
            text = _read(os.path.join(task_dir, rel))
            if not _EGRESS_HINT_RE.search(text):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if not _EGRESS_HINT_RE.search(line):
                    continue
                # collect candidate host/allow entries on the line
                entries = []
                mp = re.search(r"(?:NO_PROXY|no_proxy|HTTPS?_PROXY)\s*=\s*([^\s#]+)", line, re.I)
                if mp:
                    entries += [e for e in re.split(r"[,:]", mp.group(1)) if e]
                for mh in re.finditer(r"--host[=\s]+([^\s#]+)", line, re.I):
                    entries.append(mh.group(1))
                ma = re.match(r"\s*(?:allow|host|permit)\s+([^\s#]+)", line, re.I)
                if ma:
                    entries.append(ma.group(1))
                for e in entries:
                    e = e.strip().strip('"\'')
                    if not e or e.lower() in ("all", "any", "none", "deny"):
                        continue
                    if _IP_CIDR_RE.match(e):
                        continue  # IP-class filter -> clean
                    if re.search(r"[a-zA-Z]", e):  # a hostname / service identity
                        cands.append({"file": rel, "line": i, "entry": e,
                                      "why": "egress filter names a hostname/service identity, not an IP class — "
                                             "reachable by numeric IP",
                                      "text": line.strip()[:160]})
                        files.add(rel)
    return {"label": "[Fail - Egress Hygiene]", "candidates": cands,
            "files_to_read": sorted(files),
            "note": "reader confirms the outbound filter blocks by IP-address class, not by hostname "
                    "(a hostname allowlist is bypassable via the numeric IP)."}


def find(task_dir):
    return {
        "task_dir": os.path.abspath(task_dir),
        "checks": {
            "credential_hygiene": _credential(task_dir),
            "egress_hygiene": _egress(task_dir),
        },
    }


def _summary(r):
    o = [f"EN3 FINDER — {r['task_dir']}"]
    ch = r["checks"]["credential_hygiene"]
    o.append(f"  [Credential Hygiene] candidates={len(ch['candidates'])}")
    for c in ch["candidates"][:15]:
        o.append(f"     FAIL?  {c['file']}:{c['line']}  {c['key']}={c['value']!r}  — {c['why']}")
    eg = r["checks"]["egress_hygiene"]
    o.append(f"  [Egress Hygiene] candidates={len(eg['candidates'])}")
    for c in eg["candidates"][:10]:
        o.append(f"     FAIL?  {c['file']}:{c['line']}  entry={c['entry']!r}  — {c['why']}")
    o.append("  NOTE: finder points. The reader opens compose/.env + the egress config and decides.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: en3_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
