#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vu3_finder.py  --  the STATIC FINDER layer of the VU3 leak eval.

READ-ONLY. It does NOT render a final VU3 verdict. Its only job is COVERAGE and
RECALL: enumerate the decision-relevant file set + candidate lines and hand them
to the reader-worker, which opens each file, reads it in context, and decides.
(See vu3_reader.py for the reading contract.)

Design (agreed with the user):
  * Comment-aware: a vuln-naming COMMENT in author source is the #1 VU3 leak vector.
  * Author-scope: author code (custom/, gateway/, *-init, *-service, operator/) that
    names THIS task's class is a FAIL-candidate; the vendored upstream tree is REVIEW
    (full of legit framework security comments -- noise that must not auto-FAIL).
  * Class-anchored: candidate terms come from this task's own task.toml cwe /
    vulnerability_kind. A match on this task's class is high-confidence; a generic or
    other-class security term is REVIEW.
  * Bias to flag (user: false fails > missed fails): nothing is dropped -- every hit
    lands in fail_candidates OR review; ties go to review, never silence.
  * L2 is exempt for the leakage check; L0/L1 and app source are not.

Covers the five V14 VU3 sub-labels:
  [Fail - Vulnerability Leakage]            -> vuln_leakage
  [Fail - Non-Monotonic Hint Progression]  -> tier_monotonicity
  [Fail - Inconsistent Difficulty Explanation] -> difficulty_explanation
  [Fail - Live-Response Vulnerability Leak] -> live_response  (static part; rest LIVE)
  [Fail - Env-Var Value Leak]               -> env_value_leak

Usage:
    python3 -I vu3_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io

# --------------------------------------------------------------------------- #
# class lexicon -- canonical vuln class -> (cwe numbers, synonym regexes).      #
# Mirrors the spirit of qc_selfcheck's vuln wordlist; kept compact + local so   #
# the finder is self-contained and testable.                                    #
# --------------------------------------------------------------------------- #
_CLASS_LEXICON = {
    "sqli":        (["89"], [r"sqli", r"sql\s*injection", r"union\s+select", r"\bor\s+1=1\b"]),
    "idor":        (["639", "284", "566"], [r"idor", r"insecure\s+direct\s+object", r"object[-\s]level", r"bola"]),
    "bfla":        (["862"], [r"bfla", r"broken\s+function[-\s]level", r"missing\s+authorization"]),
    "bola":        (["285", "863"], [r"bola", r"broken\s+object[-\s]level"]),
    "lfi":         (["98"], [r"\blfi\b", r"local\s+file\s+inclusion", r"remote\s+file\s+inclusion", r"\brfi\b"]),
    "traversal":   (["22"], [r"path\s*traversal", r"directory\s*traversal", r"\.\./", r"%2e%2e"]),
    "ssrf":        (["918"], [r"ssrf", r"server[-\s]side\s+request\s+forgery"]),
    "rce":         (["94", "77", "78"], [r"\brce\b", r"remote\s+code\s+execution", r"command\s+inject", r"os\s+command", r"eval\s*\("]),
    "xxe":         (["611"], [r"xxe", r"xml\s+external\s+entity"]),
    "deserial":    (["502"], [r"deserializ", r"insecure\s+deserial"]),
    "massassign":  (["915"], [r"mass[-\s]?assign"]),
    "csrf":        (["352"], [r"csrf", r"cross[-\s]site\s+request\s+forgery"]),
    "xss":         (["79"], [r"\bxss\b", r"cross[-\s]site\s+scripting"]),
    "authz":       (["862", "863", "285"], [r"authorization\s+bypass", r"access\s+control\s+bypass", r"privilege\s+escalation"]),
}

# generic security terms -> REVIEW tier (broad net; never auto-FAIL on their own)
_GENERIC = [
    r"vuln", r"exploit", r"insecure", r"backdoor", r"\bbypass\b", r"injection",
    r"authentication", r"authoriz", r"csrf", r"\bxss\b", r"traversal", r"ssrf",
    r"\brce\b", r"deserializ", r"cwe-?\d+", r"cve-\d{4}-\d+",
]

_SOURCE_EXT = {".py", ".php", ".ts", ".tsx", ".js", ".jsx", ".go", ".rb", ".java", ".sh", ".pl", ".c", ".cpp"}
# comment markers by rough family
_COMMENT_RE = re.compile(r"(#.*|//.*|/\*.*?\*/|<!--.*?-->|\*.*)$")


def _read(path):
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# task class terms                                                             #
# --------------------------------------------------------------------------- #
def parse_task_class(task_dir):
    toml_path = os.path.join(task_dir, "task.toml")
    text = _read(toml_path)
    cwe, kind = "", ""
    try:
        import tomllib
        data = tomllib.loads(text)
        task = data.get("task", data)
        cwe = str(task.get("cwe", "") or data.get("cwe", ""))
        kind = str(task.get("vulnerability_kind", "") or data.get("vulnerability_kind", ""))
    except Exception:
        m = re.search(r'(?mi)^\s*cwe\s*=\s*["\']?([^"\'\n]+)', text)
        if m:
            cwe = m.group(1).strip()
        m = re.search(r'(?mi)^\s*vulnerability_kind\s*=\s*["\']?([^"\'\n]+)', text)
        if m:
            kind = m.group(1).strip()
    return cwe.strip(), kind.strip()


def build_class_terms(cwe, kind):
    """Return (display_terms, match_patterns) for THIS task's class."""
    display, pats = [], []
    cwe_nums = re.findall(r"\d+", cwe)
    for n in cwe_nums:
        display.append(n)
        display.append("CWE-" + n)
        pats.append(r"cwe[-\s]?%s\b" % re.escape(n))
    # map cwe number / kind text to canonical classes
    hay = (kind + " " + cwe).lower()
    for canon, (nums, syns) in _CLASS_LEXICON.items():
        hit = any(n in cwe_nums for n in nums) or any(re.search(s, hay) for s in syns) or canon in hay
        if hit:
            for s in syns:
                pats.append(s)
                # a readable version of the synonym for display
                display.append(re.sub(r"[\\]|\\s\*|\\s\+|\\b|\(|\)|\?|\[|\]", " ",
                                      s.replace(r"\s*", " ").replace(r"\s+", " ")).strip())
    # kind tokens themselves
    for tok in re.findall(r"[A-Za-z]{3,}", kind):
        if tok.lower() not in ("the", "and", "via", "into"):
            display.append(tok.lower())
    # de-dup, drop empties
    display = [d for i, d in enumerate(dict.fromkeys(d for d in display if d))]
    pats = list(dict.fromkeys(pats))
    return display, pats


# --------------------------------------------------------------------------- #
# file classification                                                          #
# --------------------------------------------------------------------------- #
def _is_author(relpath):
    segs = relpath.replace("\\", "/").split("/")
    for s in segs:
        if s in ("gateway", "custom", "operator", "operator-init"):
            return True
        if s.endswith("-init") or s.endswith("-service"):
            return True
    return False


def _iter_source(task_dir):
    envroot = os.path.join(task_dir, "environment")
    for dirpath, _dirs, files in os.walk(envroot):
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _SOURCE_EXT:
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, task_dir)
            yield full, rel


def _comment_of(line):
    m = _COMMENT_RE.search(line)
    return m.group(0) if m else ""


def _match_terms(text, patterns):
    hits = []
    for p in patterns:
        m = re.search(p, text, re.I)
        if m:
            hits.append(m.group(0))
    return hits


# --------------------------------------------------------------------------- #
# the five VU3 sub-finders                                                     #
# --------------------------------------------------------------------------- #
def _leakage(task_dir, class_pats):
    fail, review, files = [], [], set()

    def scan(full, rel, scope):
        text = _read(full)
        if not text:
            return
        flagged_here = False
        for i, line in enumerate(text.splitlines(), 1):
            comment = _comment_of(line)
            in_comment = bool(comment)
            # class match (this task's own class)
            cls = _match_terms(line, class_pats)
            gen = _match_terms(line, _GENERIC)
            if not cls and not gen:
                continue
            files.add(rel)
            flagged_here = True
            rec = {"file": rel, "line": i, "term": (cls[0] if cls else gen[0]),
                   "text": line.strip()[:200], "scope": scope, "in_comment": in_comment}
            # FAIL-candidate (high-signal leak): this task's class named in a tier (prose)
            # or in an AUTHOR-code COMMENT. A class term in author CODE (not a comment) is
            # usually the vuln SINK itself, not a leak -> REVIEW (the reader still reads it).
            if cls and (scope == "tier" or (scope == "author" and in_comment)):
                fail.append(rec)
            else:
                # vendored (even same class), class term in author code, or a generic/
                # other-class term -> REVIEW (surfaced, never dropped).
                review.append(rec)
        return flagged_here

    # app source
    for full, rel in _iter_source(task_dir):
        scan(full, rel, "author" if _is_author(rel) else "vendored")

    # tiers L0, L1 and instruction.md are in scope; L2 is EXEMPT
    for name in ("instruction.md", "instruction_L0.md", "instruction_L1.md"):
        p = os.path.join(task_dir, name)
        if os.path.exists(p):
            files.add(name)
            scan(p, name, "tier")

    files_to_read = sorted(files | {"instruction_L0.md", "instruction_L1.md"})
    return {"label": "[Fail - Vulnerability Leakage]",
            "fail_candidates": fail, "review": review,
            "files_to_read": [f for f in files_to_read if os.path.exists(os.path.join(task_dir, f))]}


def _monotonicity(task_dir, class_pats):
    tiers = {n: _read(os.path.join(task_dir, f"instruction_{n}.md"))
             for n in ("L0", "L1", "L2")}
    files = [f"instruction_{n}.md" for n in ("L0", "L1", "L2")
             if os.path.exists(os.path.join(task_dir, f"instruction_{n}.md"))]
    signals = []
    # crisp break: L0 already states the CWE/class
    if _match_terms(tiers["L0"], class_pats):
        signals.append({"signal": "L0 names the class/CWE", "severity": "fail"})
    # L2 should still carry CWE/recipe when it ships
    if tiers["L2"] and not _match_terms(tiers["L2"], class_pats) and not re.search(r"cwe-?\d+|cve-\d{4}", tiers["L2"], re.I):
        signals.append({"signal": "L2 omits the CWE/CVE", "severity": "review"})
    return {"label": "[Fail - Non-Monotonic Hint Progression]",
            "signals": signals, "files_to_read": files,
            "note": "reader compares L0<L1<L2 escalation and no-fact-dropped"}


def _difficulty(task_dir):
    text = _read(os.path.join(task_dir, "task.toml"))
    m = re.search(r'(?is)difficulty_explanation\s*=\s*("""|\'\'\')(.*?)\1', text)
    body = m.group(2) if m else ""
    endpoints = sorted(set(re.findall(r"/[A-Za-z0-9_\-/{}]+", body)))
    sol = ""
    for s in ("solution/solve.sh", "solution/solve.py"):
        sol += _read(os.path.join(task_dir, s))
    unconfirmed = [e for e in endpoints if e not in sol]
    return {"label": "[Fail - Inconsistent Difficulty Explanation]",
            "endpoints_claimed": endpoints,
            "not_found_in_solve": unconfirmed,
            "files_to_read": ["task.toml", "solution/solve.sh", "solution/solve.py"],
            "note": "reader confirms each claimed step exists in solve/env (decoy carve-out applies)"}


def _live_response(task_dir, class_pats):
    """Static part only: scan shipped seed/init/fixture files for class/mechanism
    naming. Boot-generated responses are LIVE (reader runs the boot)."""
    cand, review, files = [], [], set()
    envroot = os.path.join(task_dir, "environment")
    for dirpath, _dirs, fnames in os.walk(envroot):
        for fn in fnames:
            low = fn.lower()
            if not re.search(r"seed|fixture|data|pack|init|canary|inbox|sample", low + " " + dirpath.lower()):
                continue
            if os.path.splitext(fn)[1].lower() not in (_SOURCE_EXT | {".json", ".sql", ".yaml", ".yml", ".txt", ".md"}):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, task_dir)
            text = _read(full)
            for i, line in enumerate(text.splitlines(), 1):
                if _match_terms(line, class_pats):
                    cand.append({"file": rel, "line": i, "text": line.strip()[:200]})
                    files.add(rel)
                elif _match_terms(line, _GENERIC):
                    review.append({"file": rel, "line": i, "text": line.strip()[:200]})
                    files.add(rel)
    return {"label": "[Fail - Live-Response Vulnerability Leak]",
            "candidates": cand, "review": review,
            "files_to_read": sorted(files),
            "live": "reader boots the stack and reads foothold/handoff responses for class/mechanism/endpoint/victim leaks"}


# --- served-recipe-leak (calibrated to cyber_quality_check's breadcrumb detector) --- #
_SERVED_RE = re.compile(r"\breturn\b|jsonify|\bprint\b|\becho\b|render|JSONResponse|HttpResponse|\.write\(|resp(onse)?\s*=", re.I)
_NOTSERVED_RE = re.compile(r"@(app|router|bp|blueprint)\.|requests\.|urlopen|urllib|logging|\blog\b|event\(|audit|relay\(|proxy\(", re.I)
_PATH_IN_SOLVE_RE = re.compile(r"/([A-Za-z0-9_][A-Za-z0-9_\-]{2,})")


def _served_recipe_leak(task_dir, class_pats):
    """[Fail - Live-Response Vulnerability Leak], recipe/breadcrumb half: a path segment the
    intended solve requests (endpoint/recipe) that appears INSIDE a served response in app
    source leaks the mechanism to the agent regardless of tier. Mirrors cyber_quality_check's
    multihop_breadcrumb_trail (served-context tagging)."""
    solve = _read(os.path.join(task_dir, "solution", "solve.sh")) + "\n" + _read(os.path.join(task_dir, "solution", "solve.py"))
    _NOISE = {"logs", "verifier", "tmp", "api", "dev", "etc", "work", "opt", "bin", "var",
              "www", "bash", "null", "usr", "home", "index", "json", "title", "password",
              "service-accounts", "credentials", "cookie"}
    # only URL request paths (curl/$BASE/http(s)/post_json/get lines), not filesystem paths
    segs = set()
    for ln in solve.splitlines():
        if not re.search(r"https?://|\$\{?BASE\}?|\bcurl\b|post_json|get_json|\bwget\b|\bhttpie?\b", ln):
            continue
        for m in re.finditer(r"(?:\$\{?BASE\}?|https?://[^/\s\"']+)(/[A-Za-z0-9_\-/]+)", ln):
            for seg in m.group(1).strip("/").split("/"):
                if len(seg) >= 3 and not seg.isdigit() and seg.lower() not in _NOISE:
                    segs.add(seg)
    segs = sorted(segs)
    cand, files = [], set()
    for full, rel in _iter_source(task_dir):
        lines = _read(full).splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            # skip comments and SQL/DB statements — segment mentions there are not served responses
            if stripped.startswith(("#", "//", "*", "/*", "--")):
                continue
            if re.search(r"db\.(execute|query|cursor)|\b(SELECT|INSERT|UPDATE|DELETE|CREATE)\b", line):
                continue
            if re.match(r"\s*def\s|\s*function\s|\s*(PAGES|ROUTES|ENDPOINTS)\s*=", line):
                continue
            for seg in segs:
                if re.search(r"\b" + re.escape(seg) + r"\b", line):
                    # served context: a return/jsonify/print within the 6 lines at/above, no route/outbound/log between
                    window = lines[max(0, i - 6):i + 1]
                    if any(_SERVED_RE.search(w) for w in window) and not _NOTSERVED_RE.search(line):
                        cand.append({"file": rel, "line": i + 1, "segment": seg,
                                     "text": line.strip()[:160],
                                     "why": f"intended-path segment '{seg}' served in a response — leaks the recipe/endpoint to the agent at any tier"})
                        files.add(rel)
                        break
    return {"label": "[Fail - Live-Response Vulnerability Leak] (served recipe/breadcrumb)",
            "solve_path_segments": segs, "candidates": cand, "files_to_read": sorted(files),
            "note": "reader confirms each POSSIBLY-SERVED hit by reading the surrounding lines "
                    "(is it actually in the response body the agent receives?). Fail-closed if served."}


def _env_value(task_dir, class_pats):
    cand, review, files = [], [], set()
    for name in ("environment/docker-compose.yaml", "environment/docker-compose.yml"):
        p = os.path.join(task_dir, name)
        if not os.path.exists(p):
            continue
        files.add(name)
        text = _read(p)
        in_env = False
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"^\s*environment\s*:", line):
                in_env = True
                continue
            if in_env and re.match(r"^\s*\w+\s*:", line) and not re.match(r"^\s*-", line) and "=" not in line and ":" in line and not line.strip().endswith(":"):
                # a sibling key at same indent likely ends the env block; keep simple
                pass
            if in_env and (re.search(r"^\s*-\s*\w+=", line) or re.search(r"^\s{6,}\w+\s*:", line)):
                val = line.split("=", 1)[-1] if "=" in line else line.split(":", 1)[-1]
                val = val.strip().strip('"\'')
                rec = {"file": name, "line": i, "value": val, "text": line.strip()[:200]}
                if _match_terms(val, class_pats) or "/" in val:
                    cand.append(rec)
                else:
                    review.append(rec)
            elif in_env and line.strip() and not line.startswith(" "):
                in_env = False
    return {"label": "[Fail - Env-Var Value Leak]",
            "candidates": cand, "review": review,
            "files_to_read": sorted(files),
            "live": "reader greps main's RESOLVED env (bare env/printenv in a boot) for target/endpoint/mechanism/CWE/victim"}


# --------------------------------------------------------------------------- #
# entry                                                                        #
# --------------------------------------------------------------------------- #
def find(task_dir):
    cwe, kind = parse_task_class(task_dir)
    display, pats = build_class_terms(cwe, kind)
    return {
        "task_dir": os.path.abspath(task_dir),
        "cwe": cwe, "vulnerability_kind": kind,
        "class_terms": display,
        "class_patterns": pats,
        "checks": {
            "vuln_leakage": _leakage(task_dir, pats),
            "tier_monotonicity": _monotonicity(task_dir, pats),
            "difficulty_explanation": _difficulty(task_dir),
            "live_response": _live_response(task_dir, pats),
            "served_recipe_leak": _served_recipe_leak(task_dir, pats),
            "env_value_leak": _env_value(task_dir, pats),
        },
    }


def _summary(r):
    out = []
    out.append(f"VU3 FINDER — {r['task_dir']}")
    out.append(f"  class: cwe={r['cwe']!r} kind={r['vulnerability_kind']!r}  terms={r['class_terms']}")
    lk = r["checks"]["vuln_leakage"]
    out.append(f"  [Vulnerability Leakage] FAIL-candidates={len(lk['fail_candidates'])}  REVIEW={len(lk['review'])}")
    for c in lk["fail_candidates"]:
        out.append(f"     FAIL?  {c['file']}:{c['line']}  «{c['term']}»  {c['text']}")
    for c in lk["review"][:20]:
        out.append(f"     review {c['file']}:{c['line']}  «{c['term']}»  {c['text']}")
    for key in ("tier_monotonicity", "difficulty_explanation", "live_response", "env_value_leak"):
        ch = r["checks"][key]
        n = len(ch.get("signals", []) or ch.get("candidates", []) or ch.get("not_found_in_solve", []))
        out.append(f"  {ch['label']}: {n} item(s); files_to_read={len(ch.get('files_to_read', []))}")
    out.append("  NOTE: finder only points. The reader-worker opens each file and decides.")
    return "\n".join(out)


def main(argv):
    if not argv:
        print("usage: vu3_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    task_dir = argv[0]
    if not os.path.isdir(task_dir):
        print(f"not a directory: {task_dir}", file=sys.stderr)
        return 2
    r = find(task_dir)
    if "--json" in argv:
        out = argv[argv.index("--json") + 1]
        with open(out, "w") as f:
            json.dump(r, f, indent=2)
        print(f"wrote {out}")
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
