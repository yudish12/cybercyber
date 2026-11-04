#!/usr/bin/env python3
"""Spec-specific rubric checks (24 dimensions).

Covers what the current rubric added or changed over the older 16-dimension one.
Some logic is adapted from the lead's `blackbox-pentest-qa` reviewer, whose Q4/Q5/Q7/
Q15 map onto the changed and new dimensions. Two of its checks are deliberately NOT
ported:
  * Q4 fails any role-named prefix (ADMIN_FLAG=). Dimension 4 only fails a prefix that
    names the vulnerability CLASS, so a role name is not a fail there.
  * Q15 scans environment/ source for leftover prefixes. Dimension 7 grades what the
    agent can retrieve OVER HTTP, which is narrower.

NAMING: the module, and the `v4_*` evidence keys it populates, keep the "v4" label from
an interim sheet. The customer's FINAL sheet is the V3 one with the pass@k fail
definition folded in; `rubric.json` is verbatim from THAT file and governs. The names are
load-bearing across prompts and packs, so they were left alone; treat "v4" here as
meaning "the current rubric". See references/rubric_changes.md.
"""
import json, os, re

EXACT_PATH = re.compile(r"/api/[A-Za-z0-9_./{}<>:-]+")

# Prefixes that name a vulnerability CLASS (V4 D4). Role names are not included.
CLASS_PREFIX = re.compile(
    r"\b(SQLI|SQL|IDOR|BOLA|SSRF|XSS|CSRF|RCE|XXE|LFI|RFI|SSTI|TRAVERSAL|PATH|"
    r"MASSASSIGN|MASS_ASSIGN|INJECTION|INJECT|DESERIAL|PRIVESC)[_-]?FLAG\s*=", re.I)

# Any prefixed canary shape, used for the D7 leftover sweep.
ANY_PREFIX = re.compile(r"\b([A-Z][A-Z0-9_]{2,30})\s*=\s*(?:<?hex>?|[\"']?[0-9a-f]{16,}|\{)", re.I)
KNOWN_CANARY = re.compile(
    r"\b(ADMIN_FLAG|ORDER_FLAG|LICENSE_MARKER|IDOR_FLAG|SQLI_FLAG|SVC_FLAG|BOLA_FLAG|"
    r"SYSTEM_SECRET|SERVICE_TOKEN|LEGACY_MARKER)\s*=", re.I)

SKILL_FAMILIES = {
    "idor": ("idor", "bola", "cwe-639", "cwe 639", "cwe-284", "insecure direct"),
    "sqli": ("sqli", "sql-injection", "sql injection", "cwe-89", "cwe 89"),
    "ssrf": ("ssrf", "cwe-918", "cwe 918"),
    "traversal": ("traversal", "path-traversal", "path_traversal", "cwe-22", "cwe 22", "arbitrary file"),
    "mass-assignment": ("mass-assignment", "mass_assignment", "massassignment",
                        "mass assignment", "cwe-915", "cwe 915", "object-property"),
}


def _read(p, limit=1_000_000):
    try:
        with open(p, "r", errors="replace") as f:
            return f.read(limit)
    except Exception:
        return ""


def _instr(task_root):
    out = {}
    for n in ("instruction.md", "instruction_L0.md", "instruction_L1.md", "instruction_L2.md"):
        p = os.path.join(task_root, n)
        if os.path.isfile(p):
            out[n] = _read(p)
    return out


def families(text):
    t = (text or "").lower().replace("_", "-")
    return {f for f, keys in SKILL_FAMILIES.items() if any(k in t for k in keys)}


def verdict(dim_id, title, score, option, evidence, note=""):
    return {"dimension_id": dim_id, "title": title, "score": score,
            "option": option, "evidence": evidence, "note": note}


# ───────────────────────── D16 (changed): reward written on EVERY branch ─────────────────────────

def check_reward_written_every_branch(task_root):
    """V4 D16 adds: 'Any branch of test.sh can exit (including a set -e abort or a
    failed $(...)) without writing both reward.json and reward.txt.'"""
    t = os.path.join(task_root, "tests", "test.sh")
    text = _read(t)
    if not text:
        return {"status": "FAIL", "detail": "tests/test.sh missing"}
    # `set -e` appears as -e, -eu, -euo pipefail, -o errexit ... the old \b after
    # -e matched only the bare form and silently passed `set -euo pipefail`.
    has_set_e = bool(re.search(r"^\s*set\s+-[a-z]*e[a-z]*\b|^\s*set\s+-o\s+errexit\b",
                               text, re.M))
    # `first_reward` must be the first place a reward is ACTUALLY WRITTEN on the main
    # path. Using the first textual mention let a commented-out line, or a helper
    # function DEFINED early and called late, mask every unguarded substitution after
    # it. Blank out comments and function bodies before locating it, preserving offsets.
    # Blank to spaces but KEEP newlines, so byte offsets AND line numbers both stay
    # aligned with the original text.
    _blank = lambda m: "".join("\n" if c == "\n" else " " for c in m.group(0))
    scan = re.sub(r"(?m)#.*$", _blank, text)
    scan = re.sub(r"(?ms)^[ \t]*(?:function\s+)?[A-Za-z_]\w*\s*\(\)\s*\{.*?^[ \t]*\}",
                  _blank, scan)
    # Resolve path variables first: real graders write through `$REWARD_TXT`, and a
    # bare search for the literal "reward.txt" matched the PATH ASSIGNMENT on line 7
    # rather than any write — so every later substitution was treated as safe.
    reward_vars = set()
    for m in re.finditer(r"(?m)^[ \t]*(?:export\s+|local\s+)?([A-Za-z_]\w*)\s*=\s*"
                         r"[\"']?[^\n\"']*reward\.(?:json|txt)", text):
        reward_vars.add(m.group(1))
    _vars = ("|".join(re.escape(v) for v in reward_vars)) if reward_vars else r"(?!x)x"
    # An actual WRITE: a redirect into a reward path, literal or through one of those
    # variables. A mention is not a write.
    WRITE_RE = re.compile(
        rf">\s*[\"']?(?:\$\{{?(?:{_vars})\}}?|[^\s\"'|;&]*reward\.(?:json|txt))", re.I)
    # A trap that writes a reward on EXIT covers the abort paths, so an early
    # substitution is no longer fatal.
    has_reward_trap = bool(re.search(r"^\s*trap\s+[\"'][^\"']*reward\.(?:json|txt)", text, re.M))
    # Only a substitution that can REALISTICALLY fail aborts the script. Flagging
    # every `VAR=$(...)` false-failed harmless text pipelines (`$(cat f | tr -d ...)`,
    # `$(echo "$X" | sed ...)`), which cannot abort a run in practice. The shapes the
    # rubric actually cares about are network and subprocess calls.
    CAN_FAIL = re.compile(
        r"\b(?:curl|wget|nc|ncat|netcat|ssh|scp|docker|kubectl|psql|mysql|redis-cli|"
        r"python[23]?|node|ruby|perl|php|java|jq|grep|test|diff|cmp|"
        r"solve\.(?:py|sh))\b")
    # A helper that writes BOTH reward files. Detect it through the resolved variables
    # too: `echo "$1" > "$REWARD_TXT"` never contains the literal "reward.txt".
    def _writes_both(body):
        if "reward.json" in body and "reward.txt" in body:
            return True
        hits = {m.group(0) for m in WRITE_RE.finditer(body)}
        joined = " ".join(hits).lower()
        return (("json" in joined or any("JSON" in v.upper() for v in reward_vars if v in joined.upper()))
                and len(hits) >= 2)
    writer_fns = set()
    for fm in re.finditer(r"(?ms)^[ \t]*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{(.*?)^[ \t]*\}", text):
        if _writes_both(fm.group(2)):
            writer_fns.add(fm.group(1))
    _wcall = ("|".join(re.escape(f) for f in writer_fns)) if writer_fns else r"(?!x)x"

    # The cutoff is the first reward write that is GUARANTEED on the main path: a
    # top-level (unindented, outside any function) write or writer call. A write inside
    # `if ... ; exit 0` does not protect a later abort, because reaching that later line
    # means the branch was not taken.
    first_reward = -1
    for m in re.finditer(rf"(?m)^(?:{_wcall})\b|^[^\s#].*{WRITE_RE.pattern}", scan):
        first_reward = m.start()
        break

    risky, benign = [], []
    # `[ \t]*` not `\s*`: with re.M, `\s*` would run across the blanked lines and
    # anchor the match to the wrong line number.
    for m in re.finditer(r"^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*\$\(", scan, re.M):
        if first_reward == -1 or m.start() < first_reward:
            line = text[:m.start()].count("\n") + 1
            # Read the WHOLE substitution, not just its first line: a multi-line
            # `VAR=$(... \n ... || true)` carries its guard on a continuation line, and
            # a first-line-only test reported it as unguarded.
            depth, j = 0, m.end() - 1
            while j < len(text):
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            end = text.find("\n", j) if j < len(text) else text.find("\n", m.start())
            stmt = text[m.start():end if end > 0 else len(text)]
            if re.match(r"\s*(if|elif|while|until)\b", stmt) or "||" in stmt:
                continue
            stmt = " ".join(stmt.split())
            if not CAN_FAIL.search(stmt):
                benign.append(f"line {line}: {stmt[:60]}")
                continue
            risky.append(f"line {line}: {stmt[:90]}")
    writes_json = len(re.findall(r"reward\.json", text))
    writes_txt = len(re.findall(r"reward\.txt", text))
    problems = []
    # A writer helper does NOT excuse a risky substitution: `set -e` aborts before the
    # helper is ever called, so the branch still exits with neither file written. The
    # `|| true` / `|| deny` guard is what actually covers it, and those lines are skipped
    # above. Record the helpers as mitigating evidence, not as an escape hatch.
    if has_set_e and risky and not has_reward_trap:
        problems.append("set -e with unguarded command substitution(s) before any reward write: "
                        + "; ".join(risky[:3]))
    if writes_json == 0:
        problems.append("no reward.json write found")
    if writes_txt == 0:
        problems.append("no reward.txt write found")
    # The clause is "ANY BRANCH of test.sh can exit without writing BOTH files", but the
    # test above is a whole-file count: a script that writes both on the happy path and
    # bails out of an early `if` writing neither still scored 5. Walk the indented exits.
    if not has_reward_trap:
        _lines = text.split("\n")
        _bad_exit = []
        for _i, _l in enumerate(_lines):
            _m = re.match(r"^([ \t]+)exit\b", _l)
            if not _m:
                continue                      # a top-level trailing exit falls through
            _indent = len(_m.group(1).expandtabs(4))
            # walk back to the line that opened this block
            _start = 0
            for _j in range(_i - 1, -1, -1):
                _pl = _lines[_j]
                if not _pl.strip():
                    continue
                _pi = len(_pl) - len(_pl.lstrip().rjust(len(_pl.lstrip())))
                _pi = len(_pl[:len(_pl) - len(_pl.lstrip())].expandtabs(4))
                if _pi < _indent and re.search(r"(?:\bthen\b|\belse\b|\bdo\b|\{)\s*$", _pl):
                    _start = _j
                    break
                if _pi < _indent:
                    _start = _j
                    break
            _block = "\n".join(_lines[_start:_i + 1])
            if "reward.json" not in _block or "reward.txt" not in _block:
                # a write ABOVE the block on the main path still covers it
                _before = "\n".join(_lines[:_start + 1])
                if not (re.search(r"reward\.json", _before) and re.search(r"reward\.txt", _before)):
                    _bad_exit.append(_i + 1)
        if _bad_exit:
            problems.append("branch exit(s) at line(s) "
                            + ", ".join(map(str, _bad_exit[:4]))
                            + " can leave without writing both reward.json and reward.txt")
    return {"status": "FAIL" if problems else "PASS",
            "detail": "; ".join(problems) if problems else
                      f"reward.json x{writes_json}, reward.txt x{writes_txt}; no unguarded abort before a write"
                      + (" (EXIT trap writes a reward)" if has_reward_trap else ""),
            "problems": problems,
            "has_exit_trap": has_reward_trap,
            "reward_writing_helpers": sorted(writer_fns),
            "benign_substitutions_ignored": benign[:5],
            "risky_substitutions": risky[:5],
            "first_reward_write_offset": first_reward,
            # A writer helper covers the paths it is CALLED on, not an abort that never
            # reaches a call. Say so rather than silently passing.
            "needs_judgment": False,
            "_mitigation_note": (
                f"{sorted(writer_fns)} write(s) both reward files, but only on the paths where "
                "they are CALLED — a `set -e` abort at the flagged line never reaches them. "
                "Guard the call with `|| true` / `|| <helper>`, or add a `trap ... EXIT`."
                if (has_set_e and risky and writer_fns) else "")}


# ───────────────────────── D17 (new): anti-cheat ordering ─────────────────────────

# Phrases that identify a recorded disclosure step in an audit log. The rubric allows
# "an endpoint-match (OR EQUIVALENT DISCLOSURE CHECK)", so gating on these is a match.
DISCLOSURE_PHRASE_RE = re.compile(
    r"disclos|unauthenticated|leak|config\s*read|directory\s*listing|user[- ]director"
    r"|anonymous\s*(?:read|access)|traversal|bypass|public\s*read|exposed", re.I)

def _no_echo_text(line):
    """Drop progress-message text before looking for a ground-truth re-derivation.

    `echo "re-deriving ground truth..."` is a log line, not a call. Matching inside it
    marked the re-derivation as happening EARLIER than it does and false-failed verifiers
    whose anti-cheat check genuinely runs first. Only echo/printf argument text is
    removed -- quoted text elsewhere can legitimately hold a command.
    """
    line = re.sub(r"\b(?:echo|printf)\b[^\n;|&]*", " ", line)
    return line


def check_anticheat_order(task_root):
    """V4 D17: an endpoint-match (or equivalent disclosure check) must EXIST and
    run BEFORE ground-truth re-derivation / the golden exploit.

    A substring search was not enough: a plain `ENDPOINT="http://..."` variable
    with no comparison anywhere scored 5/5. Now we require an actual COMPARISON
    whose operand is the disclosure value, and we detect the ground-truth step
    generically (any interpreter invoking a solve script, or a GROUND_TRUTH-ish
    assignment from a command substitution).
    """
    text = _read(os.path.join(task_root, "tests", "test.sh"))
    if not text:
        return {"status": "FAIL", "detail": "tests/test.sh missing"}
    lines = [l for l in text.splitlines()]
    # Strip whole-line AND trailing inline comments: a commented-out
    # `# python3 solve.py` on an earlier line used to fake a ground-truth step
    # and make a genuinely late comparison look early.
    def _decomment(l):
        out, q = [], None
        for ch in l:
            if q:
                out.append(ch)
                if ch == q:
                    q = None
            elif ch in "\"'":
                q = ch; out.append(ch)
            elif ch == "#":
                break
            else:
                out.append(ch)
        return "".join(out)
    code = [(i, _decomment(l)) for i, l in enumerate(lines, 1)
            if not l.strip().startswith("#")]

    # Where the disclosure/audit surface is FETCHED.
    fetch_re = re.compile(r"(audit|disclos|endpoint|intended|/internal/|route|path)", re.I)
    # A real comparison: if/case/test/[ ]/[[ ]]/grep -q/python assert-style.
    cmp_re = re.compile(
        r"^\s*(?:if|elif|case|while)\b|\[\[?\s|\btest\s+|grep\s+-\w*q|"
        r"!=|==|\bjq\s+-e\b", re.I)
    # The comparison must be ABOUT a route/endpoint, not merely a line that happens
    # to contain the word "endpoint". Either operand must be a route-shaped literal
    # or a route-named variable. Without this, any incidental guard placed before the
    # solve invocation satisfied the ordering and the check was vacuous.
    endpoint_operand_re = re.compile(
        r"[\"\'](?:GET|POST|PUT|PATCH|DELETE)\s+/[^\"\']*[\"\']"      # "GET /api/x"
        r"|[\"\']/[A-Za-z0-9_./{}-]{2,}[\"\']"                          # "/api/orders/{id}"
        r"|\$\{?[A-Za-z_]*(?:ENDPOINT|ROUTE|PATH|URL|SINK)[A-Za-z0-9_]*\b"  # $ENDPOINT
        r"|\b[A-Za-z_]*(?:ENDPOINT|ROUTE|PATH|URL|SINK)[A-Za-z0-9_]*\s*(?:==|!=|=~|\s=\s)",
        re.I)
    # An "equivalent disclosure check" per the rubric: gating on an audit log that
    # records the intended unauthenticated disclosures is a valid endpoint match even
    # though no /api path literal appears.
    # Ground-truth re-derivation / golden exploit invocation. The FINAL text names
    # tests/solve.py explicitly, so a bare `./solve.py` or `$SOLVE` with no
    # interpreter word in front of it must also count.
    gt_re = re.compile(
        r"\b(?:python3?|bash|sh|perl|ruby|node)\b[^\n]*\bsolve\b"     # python3 solve.py
        r"|(?:^|[\s;&|(])\.?/?(?:tests/)?solve(?:\.py|\.sh)?\b"        # ./solve.py, tests/solve.py
        r"|\$\{?SOLVE[A-Z_]*\b"                                        # $SOLVE_CMD
        r"|\b(?:GROUND_TRUTH|EXPECTED|TRUTH)[A-Z_]*\s*=\s*\$\(|re-?deriv", re.I)

    fetch_line = cmp_line = gt_line = None
    weak_cmp_line = None
    # Variables that carry disclosure data. A verifier commonly fetches an audit
    # blob and then parses it into DERIVED variables (CONFIG_EP=$(echo "$AUDIT" |
    # ...)), gating on those. Following only the original fetch variable reported a
    # live anti-cheat as vacuous, so propagate taint transitively.
    tainted = set()
    for i, l in code:
        m = re.match(r"\s*(?:export\s+|local\s+)?([A-Za-z_]\w*)\s*=", l)
        if not m:
            continue
        name, rhs = m.group(1), l[m.end():]
        if fetch_re.search(l) and ("$(" in l or "curl" in l.lower() or "wget" in l.lower()):
            tainted.add(name)
        elif any(re.search(rf"\$\{{?{re.escape(t)}\b", rhs) for t in tainted):
            tainted.add(name)
    taint_re = (re.compile(r"\$\{?(?:" + "|".join(re.escape(t) for t in tainted) + r")\b")
                if tainted else None)

    for i, l in code:
        if fetch_line is None and fetch_re.search(l) and ("$(" in l or "curl" in l.lower()
                                                          or "wget" in l.lower()):
            fetch_line = i
        if gt_line is None and gt_re.search(_no_echo_text(l)):
            gt_line = i
        on_disclosure = fetch_re.search(l) or (taint_re and taint_re.search(l))
        if cmp_re.search(l) and on_disclosure:
            if cmp_line is None and endpoint_operand_re.search(l):
                cmp_line = i
            elif weak_cmp_line is None:
                weak_cmp_line = i

    # `case "$VAR" in <pattern>) ... ;; *) fail` is an endpoint match whose operand
    # lives on the PATTERN lines, not the `case` line. Scan the case body for a
    # pattern that names a route or a disclosure phrase.
    if cmp_line is None and taint_re:
        case_open = None
        for i, l in code:
            cm = re.match(r"\s*case\s+\"?\$\{?([A-Za-z_]\w*)", l)
            if cm and cm.group(1) in tainted:
                case_open = i
                continue
            if case_open is not None:
                if re.match(r"\s*esac\b", l):
                    case_open = None
                    continue
                # a case arm: `*"user-directory disclosure"*)` or `/api/x)`
                arm = re.match(r"\s*\(?\s*([^)]+?)\s*\)", l)
                if arm and arm.group(1).strip() not in ("*", '"*"'):
                    pat = arm.group(1)
                    if (endpoint_operand_re.search(pat)
                            or DISCLOSURE_PHRASE_RE.search(pat)):
                        cmp_line = case_open
                        break
    # A comparison may reference the variable the fetch bound, on a later line.
    # It must be a real EQUALITY test against something, not a presence test:
    # `if [ -n "$AUDIT" ]` proves the endpoint answered, not that the submission
    # came from the intended one, and the rubric calls that vacuous.
    real_cmp_re = re.compile(r"==|!=|=~|\s=\s|grep\s+-\w*q|^\s*case\b", re.I)
    presence_only_re = re.compile(r"\[\[?\s*-[nz]\s|\btest\s+-[nz]\s", re.I)
    if cmp_line is None and fetch_line is not None:
        m = re.match(r"\s*([A-Za-z_]\w*)\s*=", lines[fetch_line - 1])
        if m:
            var = m.group(1)
            for i, l in code:
                if (i > fetch_line and cmp_re.search(l) and re.search(rf"\${{?{var}\b", l)
                        and real_cmp_re.search(l) and not presence_only_re.search(l)):
                    cmp_line = i
                    break
                if (i > fetch_line and cmp_re.search(l) and re.search(rf"\${{?{var}\b", l)
                        and weak_cmp_line is None):
                    weak_cmp_line = i

    if fetch_line is None and cmp_line is None and weak_cmp_line is None:
        return {"status": "FAIL",
                "detail": "no endpoint-match / disclosure check found in tests/test.sh — "
                          "any path to a valid secret scores 1",
                "lines": {}}
    if cmp_line is None:
        where = f" (nearest conditional on line {weak_cmp_line} compares no route-shaped value)" \
                if weak_cmp_line else ""
        return {"status": "FAIL",
                "detail": (f"a disclosure value is fetched (line {fetch_line}) but never COMPARED "
                           f"against an endpoint/route{where} — the anti-cheat is vacuous; naming "
                           "an endpoint in a variable is not a check"),
                "lines": {"fetch": fetch_line, "weak_compare": weak_cmp_line}}
    if gt_line is not None and cmp_line > gt_line:
        return {"status": "FAIL",
                "detail": (f"anti-cheat comparison at line {cmp_line} runs AFTER ground-truth "
                           f"re-derivation at line {gt_line} — any valid secret scores 1"),
                "lines": {"fetch": fetch_line, "compare": cmp_line, "ground_truth": gt_line}}
    return {"status": "PASS",
            "detail": (f"disclosure fetched at line {fetch_line}, compared at line {cmp_line}"
                       + (f", before ground-truth at line {gt_line}" if gt_line else "")),
            "lines": {"fetch": fetch_line, "compare": cmp_line, "ground_truth": gt_line}}


# ───────────────────────── D18 (new): fresh canary + live re-derive ─────────────────────────

def check_fresh_canary(task_root):
    """V4 D18: the secret must be generated PER BOOT and the verifier must
    re-derive ground truth from the running app.

    The old version passed a canonical baked-secret task: it accepted ANY CSPRNG
    call anywhere in the environment (session salts count), and only looked for
    a literal `flag{...}`. Now: identify canary-shaped names, require the CSPRNG
    to bind one of THEM, and flag any long hex/base64 literal assigned to a
    canary-shaped name anywhere the app or verifier can read.
    """
    # Case-insensitive and hyphen-tolerant: lowercase `order_flag`, `admin-secret`
    # and mixed-case names are the same thing to the rubric.
    CANARY = r"[A-Za-z0-9_-]*(?:FLAG|SECRET|CANARY|MARKER|TOKEN|KEY)[A-Za-z0-9_-]*"
    files, env_blob = [], ""
    for dp, dn, fn in os.walk(os.path.join(task_root, "environment")):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", "__pycache__")]
        for f in fn:
            # An extension whitelist hid baked secrets in Dockerfiles, .txt seeds and
            # extensionless scripts. Invert it: read everything that is not obviously
            # binary, and let the size cap below bound the cost.
            if not f.lower().endswith((
                    ".pyc", ".pyo", ".so", ".dll", ".dylib", ".png", ".jpg", ".jpeg",
                    ".gif", ".ico", ".svg", ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz",
                    ".db", ".sqlite", ".sqlite3", ".woff", ".woff2", ".ttf", ".eot",
                    ".mp4", ".mp3", ".bin", ".class", ".jar")) \
                    and not f.startswith("._"):
                files.append(os.path.join(dp, f))
                env_blob += _read(os.path.join(dp, f), 300_000) + "\n"
    gen = _read(os.path.join(task_root, "environment", "generate_secrets.sh"))
    blob = env_blob + "\n" + gen

    # (1) a CSPRNG call must BIND a canary-shaped name
    # The rubric says "token_hex / urandom OR EQUIVALENT". Restricting the vocabulary to
    # Python's spelling hard-failed perfectly good Go/Node/Java/SQL bundles.
    CSPRNG = r"(?:secrets\.token_(?:hex|urlsafe|bytes)|secrets\.(?:randbelow|choice)|" \
             r"os\.urandom|/dev/urandom|SystemRandom|openssl\s+rand|uuidgen|\$RANDOM|" \
             r"uuid\.uuid4|uuid4\s*\(|randomUUID|gen_random_uuid|" \
             r"crypto\.randomBytes|crypto\.getRandomValues|window\.crypto|" \
             r"SecureRandom|java\.security\.SecureRandom|" \
             r"crypto/rand|rand\.Read|rand\.Reader|" \
             r"RAND_bytes|random_bytes|bin2hex\s*\(\s*random_bytes|" \
             r"head\s+-c\s+\d+\s+/dev/(?:u?random))"
    fresh_bindings = sorted(set(re.findall(
        rf"\b({CANARY})\s*[:=]\s*[^\n]*{CSPRNG}", blob, re.I)))
    any_csprng = bool(re.search(CSPRNG, blob, re.I))

    # A CSPRNG is routinely wrapped in a helper (`gen_hex() { openssl rand -hex 24; }`)
    # and the secret bound to a name with no canary word (`V_PRIMARY=$(gen_hex)`).
    # Resolve one level of indirection so those count as per-boot generation.
    csprng_fns = set()
    # multi-line shell function:  name() {\n ... \n}
    for fm in re.finditer(
            r"(?ms)^[ \t]*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{(.*?)^[ \t]*\}", blob):
        if re.search(CSPRNG, fm.group(2), re.I):
            csprng_fns.add(fm.group(1))
    # single-line shell function:  name() { ...; }
    for fm in re.finditer(r"(?m)^[ \t]*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{(.*?)\}[ \t]*$", blob):
        if re.search(CSPRNG, fm.group(2), re.I):
            csprng_fns.add(fm.group(1))
    for fm in re.finditer(r"(?ms)^[ \t]*def\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*:(.*?)(?=^\S|\Z)", blob):
        if re.search(CSPRNG, fm.group(2), re.I):
            csprng_fns.add(fm.group(1))
    indirect_bindings = []
    if csprng_fns:
        callre = "|".join(re.escape(f) for f in csprng_fns)
        indirect_bindings = sorted(set(re.findall(
            rf"\b([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*[^\n]*\b(?:{callre})\s*\(", blob)))
        indirect_bindings += sorted(set(re.findall(
            rf"\b([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*\$\(\s*(?:{callre})\b", blob)))
        indirect_bindings = sorted(set(indirect_bindings))
    per_boot = bool(fresh_bindings or indirect_bindings)

    # (2) baked literals assigned to a canary-shaped name
    BAKED_LITERAL_RE = re.compile(
        rf"\b({CANARY})\s*[:=]\s*[\"']([0-9a-fA-F]{{16,}}|[A-Za-z0-9+/=]{{24,}})[\"']", re.I)
    FLAG_LITERAL_RE = re.compile(r"flag\{[^}\n]{4,}\}", re.I)
    baked = sorted(set(
        f"{m.group(1)}={m.group(2)[:12]}..." for m in BAKED_LITERAL_RE.finditer(blob)))
    baked += [f"literal {m}" for m in sorted(set(FLAG_LITERAL_RE.findall(blob)))]

    # (3) the verifier must re-derive live, not compare to a constant.
    # FINAL: "the secret should not be hardcoded into ANY OF THE VERIFIERS" -- so scan
    # every script under tests/, not just test.sh and solve.py.
    verifier_files, test_blob = [], ""
    tdir = os.path.join(task_root, "tests")
    for dp, dn, fn in os.walk(tdir):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", "__pycache__")]
        for f in sorted(fn):
            if f.endswith((".sh", ".py", ".js", ".ts", ".rb", ".go", ".pl")):
                fp = os.path.join(dp, f)
                verifier_files.append(os.path.relpath(fp, task_root))
                test_blob += f"\n### {os.path.relpath(fp, task_root)}\n" + _read(fp, 300_000)
    hardcoded_cmp = sorted(set(
        m.group(0)[:60] for m in re.finditer(
            # named constant assignment ...
            r"(?i)\b[A-Za-z_]*(?:GROUND_TRUTH|EXPECTED|TRUTH|FLAG|SECRET|CANARY|MARKER)"
            r"[A-Za-z0-9_]*\s*=\s*[\"'](?:[0-9a-fA-F]{16,}|flag\{[^}\n]{4,}\})[\"']"
            # ... or a direct comparison against a constant, in python OR posix shell
            r"|(?:==|!=|=~)\s*[\"'](?:[0-9a-fA-F]{16,}|flag\{[^}\n]{4,}\})[\"']"
            r"|\s=\s+[\"'](?:[0-9a-fA-F]{16,}|flag\{[^}\n]{4,}\})[\"']", test_blob)))
    # A secret baked into a verifier is just as much a fail as one baked into the app.
    baked += [f"{m.group(1)}={m.group(2)[:12]}... (in a verifier)"
              for m in BAKED_LITERAL_RE.finditer(test_blob)]
    baked += [f"literal {m} (in a verifier)" for m in sorted(set(FLAG_LITERAL_RE.findall(test_blob)))]
    baked = sorted(set(baked))
    rederive = bool(re.search(r"solve\.py|curl|wget|requests\.|http://|https://", test_blob))

    # Clause (1) can be satisfied by an unrelated infrastructure secret
    # (SECRET_KEY, SHARED_SVC_TOKEN, a session salt) rather than by the task's own
    # canary -- and real bundles name the canary things like `_T1`, so tightening
    # this on the NAME would false-fail conforming tasks. Instead: say so, with the
    # evidence, and let the judging tier settle it.
    INFRA_ONLY = re.compile(r"(?:TOKEN|KEY|SECRET)", re.I)
    CANARY_WORD = re.compile(r"(?:FLAG|CANARY|MARKER)", re.I)
    canary_named = [b for b in (fresh_bindings + indirect_bindings) if CANARY_WORD.search(b)]
    csprng_sites = []
    for m in re.finditer(rf"^.*{CSPRNG}.*$", blob, re.M | re.I):
        csprng_sites.append(m.group(0).strip()[:110])

    problems = []
    if baked:
        problems.append(f"baked secret literal(s): {baked[:3]}")
    if hardcoded_cmp:
        problems.append(f"verifier compares against a constant: {hardcoded_cmp[:2]}")
    # The rubric's FAIL option names exactly two things: a static `flag{...}` in source,
    # and a verifier that compares to a hardcoded string. "No CSPRNG binds a
    # canary-shaped name" is our INFERENCE about per-boot generation, not a listed fail
    # condition, and it false-failed tasks whose secret is simply named something else.
    # Absence of a CSPRNG anywhere is still a fail; a naming mismatch is a question.
    if not per_boot and not any_csprng:
        problems.append("no CSPRNG (token_hex / urandom / openssl rand / uuidgen) appears "
                        "anywhere in the environment — the secret cannot be per-boot")
    if not rederive:
        problems.append("verifier does not appear to re-derive ground truth from the live app")
    return {"status": "FAIL" if problems else "PASS",
            "detail": "; ".join(problems) if problems else
                      f"canary bound to a CSPRNG ({fresh_bindings[:3]}) and the verifier "
                      f"re-derives from the running app",
            "problems": problems,
            "fresh_bindings": fresh_bindings,
            "csprng_helper_functions": sorted(csprng_fns),
            "indirect_csprng_bindings": indirect_bindings,
            "per_boot_generation_evidenced": per_boot,
            "baked_literals": baked,
            "hardcoded_comparisons": hardcoded_cmp,
            "verifier_files_scanned": verifier_files,
            "csprng_call_sites": csprng_sites[:12],
            "canary_named_bindings": canary_named,
            "needs_judgment": (not problems and not canary_named),
            "_per_boot_note": (
                "" if per_boot else
                "A CSPRNG exists but no binding (direct or through a helper) could be tied to "
                "the task secret. The rubric does not list that as a fail condition, so this is "
                "scored on the two conditions it DOES list (static flag{...}, hardcoded compare). "
                "Confirm per-boot generation by reading csprng_call_sites."),
            "_why_judgment": (
                "" if (problems or canary_named) else
                "The per-boot clause is satisfied only by infrastructure-shaped names "
                f"({fresh_bindings[:4]}) -- none of them contains FLAG/CANARY/MARKER. That is "
                "common and legitimate (real bundles name the canary `_T1`, `_ADMIN_SECRET_1`), "
                "but it means the CSPRNG binding found here was NOT proven to be the task's own "
                "canary. Read csprng_call_sites and confirm the value the verifier re-derives is "
                "one of them.")}


# ───────────────────────── D5 (changed): tier contract ─────────────────────────

def tier_contract_evidence(task_root):
    """V4 D5 adds an explicit contract: L0 = target+creds only; L1 = + mechanism in
    plain terms, NO exact endpoint; L2 = + exact URL and full recipe.
    (Adapted from the lead's Q5, which is correct under V4.)"""
    f = _instr(task_root)
    l0, l1, l2 = f.get("instruction_L0.md", ""), f.get("instruction_L1.md", ""), f.get("instruction_L2.md", "")
    p0, p1, p2 = EXACT_PATH.findall(l0), EXACT_PATH.findall(l1), EXACT_PATH.findall(l2)
    breaches = []
    if p0:
        breaches.append(f"L0 names exact path(s) {sorted(set(p0))[:4]} — that is an L2 fact")
    if p1:
        breaches.append(f"L1 hands over exact endpoint(s) {sorted(set(p1))[:4]} — V4: the URL is an "
                        f"L2 fact; omitting /api/... from L1 is CORRECT, naming it is a fail")
    # The FINAL contract makes L2 owe TWO things: the exact URL AND the full recipe
    # (CVE or technique name). An /api path proves only the first, so check the
    # recipe separately instead of inferring both from one signal.
    RECIPE = re.compile(
        r"\bCVE-\d{4}-\d{4,7}\b|\bpayload\b|\bUNION\s+SELECT\b|\b--\s|\bOR\s+1\s*=\s*1\b"
        r"|\.\./|\bcurl\b|\bPUT\b|\bPOST\b|\bstep\s*\d|\b1\.\s|\binjection\b|\btraversal\b"
        r"|\bmass[- ]assign|\bSSRF\b|\bIDOR\b|\bheader\b|\bbody\b|\bparameter\b", re.I)
    l2_has_recipe = bool(l2 and RECIPE.search(l2))
    if l2 and not p2:
        breaches.append("L2 omits an exact URL (no /api/... path appears in instruction_L2.md)")
    if l2 and not l2_has_recipe:
        breaches.append("L2 omits the full recipe (no CVE, technique name, payload or step list "
                        "appears in instruction_L2.md)")
    # An L1 that adds no mechanism is still L0 -- the FINAL tier-contract option names
    # this explicitly and nothing was checking it.
    MECHANISM = re.compile(
        r"\bunvalidated\b|\bunsanit|\bnot\s+(?:checked|validated|escaped)\b|\binterpolat"
        r"|\bownership\b|\bwithout\s+(?:a\s+)?(?:check|validation)\b|\bconcatenat"
        r"|\breus(?:e|ed)\b|\bstored\b|\bbinds?\b|\bfetch(?:es)?\s+a\s+user[- ]supplied"
        r"|\bescape[sd]?\b|\btrusted\b|\bsanitiz", re.I)
    if l1 and l0 and not MECHANISM.search(l1):
        breaches.append("L1 may add no mechanism over L0 (no mechanism-describing language "
                        "found in instruction_L1.md) — confirm by reading both tiers")
    return {"l0_paths": sorted(set(p0)), "l1_paths": sorted(set(p1)), "l2_paths": sorted(set(p2)),
            "l2_has_recipe": l2_has_recipe,
            "l1_mechanism_language": bool(l1 and MECHANISM.search(l1)),
            "contract_breaches": breaches,
            "_how_to_judge": (
                "V4 tier contract: L0 = target + credentials ONLY (no mechanism, no class, no "
                "endpoint). L1 = L0 + the mechanism in plain terms, but NO exact endpoint. "
                "L2 = L1 + the exact URL and full recipe. Do NOT fail L1 for omitting an "
                "/api/... path — that is correct. DO fail an L1 that hands one over. Also still "
                "require monotonicity: each tier keeps every fact of the tier below.")}


# ───────────────────────── D7 (new): agent-reachable leftover prefixes ─────────────────────────

_ROUTE_DECL_V4 = re.compile(
    r"@\w+\.route\s*\(\s*[\"']([^\"']+)"                                  # Flask/Bottle @app.route("/x")
    r"|@(?:route|get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)"           # Bottle bare @route("/x")
    r"|@\w+\.(?:get|post|put|patch|delete|head|options)\s*\(\s*[\"']([^\"']+)"  # FastAPI @app.get("/x")
    r"|\b\w+\.(?:get|post|put|patch|delete|all|use)\s*\(\s*[\"'`]([^\"'`]+)"   # Express any router var
    r"|\b\w+\.(?:GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\s*\(\s*\"([^\"]+)"  # gin/echo/chi
    r"|\b\w+\.Handle(?:Func)?\s*\(\s*\"(?:[A-Z]+\s+)?([^\"]+)"            # Go net/http + ServeMux 1.22
    r"|(?<![A-Za-z_])path\s*\(\s*[\"']([^\"']*)"                            # Django path("x/", ...)
    r"|(?<![A-Za-z_])re_path\s*\(\s*r?[\"']([^\"']*)")                      # Django re_path



def _norm_route_v4(r):
    """Same normalisation the extractor uses: a route is a URL path, and a filesystem
    path from `pathlib.Path(...)` is not a route."""
    if not r:
        return None
    r = r.strip().lstrip("^").rstrip("$")
    if not r.startswith("/"):
        r = "/" + r
    if " " in r:
        return None
    tail = r.rsplit("/", 1)[-1]
    if re.search(r"\.(?:csv|json|db|sqlite3?|txt|log|ya?ml|png|jpg|pdf|zip|gz|env|ini|cfg|pem|key)$",
                 tail, re.I):
        return None
    return r or None


def leftover_prefix_evidence(task_root):
    """V4 D7 grades what the agent can retrieve OVER HTTP. The task's own taught
    success format is allowed; any sibling/decoy prefixed secret is a fail.

    Two passes, because scoping the sweep to route-decorator windows missed the
    commonest real shape: a canary seeded at MODULE scope (a fixture list, a DB seed
    row, a helper constant) and then returned verbatim by a handler -- which is
    exactly the "order response" case the rubric names. Pass 1 sweeps whole
    HTTP-surface files for canary literals; pass 2 builds the route index. We still
    do not fail on mere presence: the judging tier confirms HTTP reachability.
    """
    taught = set()
    for name, text in _instr(task_root).items():
        taught.update(m.group(1).upper() for m in re.finditer(r"\b([A-Z][A-Z0-9_]{2,30})\s*=", text))

    NOISE = {"GET", "POST", "PUT", "PATCH", "DELETE", "TRUE", "FALSE", "NONE", "SELECT",
             "FROM", "WHERE", "INSERT", "INTO", "VALUES", "UPDATE", "AND", "OR", "NOT",
             "NULL", "DEFAULT", "PRIMARY", "TEXT", "INTEGER", "REAL", "BLOB"}
    # Any canary-SHAPED name, not only the hardcoded 10-name vocabulary: the FINAL
    # text covers "any other task's prefixed canary", so a bundle inventing
    # `PARTNER_MARKER=` must not slip through.
    # The rubric's examples are all FLAG/MARKER/CANARY-shaped (`ADMIN_FLAG=`,
    # `ORDER_FLAG=`, `LICENSE_MARKER=`). TOKEN/KEY names are overwhelmingly
    # infrastructure (VERIFIER_TOKEN, API_KEY, SECRET_KEY) and including them buried
    # the real signal, so they are tracked separately rather than as candidates.
    CANARY_SHAPED = re.compile(
        r"\b([A-Z][A-Z0-9_]*(?:FLAG|CANARY|MARKER)[A-Z0-9_]*)\s*=", re.I)
    INFRA_SHAPED = re.compile(
        r"\b([A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET)[A-Z0-9_]*)\s*=", re.I)
    INFRA_NAMES = {"VERIFIER_TOKEN", "API_KEY", "SECRET_KEY", "SHARED_SVC_TOKEN",
                   "TOKEN_SIGNING_SECRET", "SESSION_SECRET", "CSRF_TOKEN", "JWT_SECRET",
                   "SHARE_TOKEN", "ACCESS_TOKEN", "REFRESH_TOKEN"}

    SURFACE_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".go", ".rb", ".php",
                   ".html", ".jinja", ".jinja2", ".j2", ".tpl", ".json", ".sql")
    # ── pass 1: whole-file canary literals on any HTTP-surface file ──
    canary_literals = {}
    for dp, dn, fn in os.walk(os.path.join(task_root, "environment")):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", "__pycache__")]
        for f in fn:
            if not f.endswith(SURFACE_EXT):
                continue
            fp = os.path.join(dp, f)
            src = _read(fp, 8_000_000)
            lines = src.splitlines()
            for i, line in enumerate(lines, 1):
                for m in CANARY_SHAPED.finditer(line):
                    nm = m.group(1).upper()
                    if nm in NOISE or nm in taught or nm in INFRA_NAMES:
                        continue
                    canary_literals.setdefault(nm, []).append({
                        "file": os.path.relpath(fp, task_root), "line": i,
                        "context": line.strip()[:160]})

    # ── pass 2: route index, so each literal can be tied to a reachable handler ──
    routes = {}
    for dp, dn, fn in os.walk(os.path.join(task_root, "environment")):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", "__pycache__")]
        for f in fn:
            if not f.endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".go", ".rb")):
                continue
            src = _read(os.path.join(dp, f), 400_000)
            lines = src.splitlines()
            idx = [i for i, l in enumerate(lines) if _ROUTE_DECL_V4.search(l)]
            for n, i in enumerate(idx):
                mm = _ROUTE_DECL_V4.search(lines[i])
                route = _norm_route_v4(next((g for g in mm.groups() if g), None)) if mm else None
                if not route:
                    continue
                end = idx[n + 1] if n + 1 < len(idx) else min(i + 90, len(lines))
                body = "\n".join(lines[i:end])
                found = sorted({x.group(1).upper() for x in re.finditer(
                    r"\b([A-Z][A-Z0-9_]{2,30})\s*=", body)} - NOISE)
                canary = sorted({x.group(1).upper() for x in CANARY_SHAPED.finditer(body)}
                                - NOISE - INFRA_NAMES)
                # The rubric's example list is "ADMIN_FLAG=, ORDER_FLAG=, LICENSE_MARKER=,
                # or ANY OTHER task's prefixed canary". A sibling canary named *_SECRET /
                # *_TOKEN / *_KEY is just as much a leftover prefix, but only FLAG/CANARY/
                # MARKER shapes were swept. INFRA_SHAPED existed for this and was never
                # used. Kept ADVISORY (a separate key, not candidate_leftovers) because
                # infrastructure legitimately carries these names.
                infra = sorted({x.group(1).upper() for x in INFRA_SHAPED.finditer(body)}
                               - NOISE - INFRA_NAMES)
                # A handler that merely REFERENCES a module-scope canary name also
                # exposes it, so look for bare references too, not just assignments.
                refs = sorted({nm for nm in canary_literals
                               if re.search(rf"\b{re.escape(nm)}\b", body, re.I)})
                if canary or refs or infra:
                    routes[route] = {"file": os.path.relpath(os.path.join(dp, f), task_root),
                                     "line": i + 1, "prefixes_emitted": found,
                                     "known_canaries": sorted(set(canary) | set(refs)),
                                     "infra_shaped_seen": infra}
    # An /internal/... route is not agent-reachable by construction, so it cannot be
    # a D7 fail on its own -- that is dimension 11's territory.
    INTERNAL = re.compile(r"^/internal/|^/_|/verifier/", re.I)
    leftovers = {r: v for r, v in routes.items()
                 if [c for c in v["known_canaries"] if c not in taught]
                 and not INTERNAL.search(r)}
    internal_only = {r: v for r, v in routes.items() if INTERNAL.search(r)}
    # Module-scope canaries no handler visibly references are still worth showing:
    # a template render or an ORM row dump can return them without naming them.
    unreferenced = {k: v[:3] for k, v in canary_literals.items()
                    if not any(k in r["known_canaries"] for r in routes.values())}
    return {"taught_prefixes": sorted(taught),
            "routes_emitting_canaries": routes,
            "candidate_leftovers": leftovers,
            "canary_literals": {k: v[:3] for k, v in canary_literals.items()},
            "internal_only_routes_excluded": sorted(internal_only),
            "canary_literals_not_tied_to_a_route": unreferenced,
            "_how_to_judge": (
                "FAIL only if an agent-reachable HTTP response body can contain a prefixed secret "
                "that is NOT this task's taught success format. Open each candidate route: confirm "
                "the agent can actually reach it (not internal-only, not verifier-only) and that "
                "the prefix differs from the taught one. A prefix present in source but never "
                "returned over HTTP is NOT a fail -- but check canary_literals_not_tied_to_a_route "
                "too: a seed row or fixture returned by a generic list/detail handler is reachable "
                "even though no handler names it. Note the rubric: 'Vulnerability Leak via "
                "Flag/Secret Format' can be a 5 and this can still fail.")}


# ───────────────────────── D8 (changed): identity check ─────────────────────────

def identity_evidence(task_root, bundle_name, meta):
    """V4 D8 adds: the zip filename, [task] name, cwe, vulnerability_kind and
    solve.py must all name the same skill. (Adapted from the lead's Q7.)"""
    name = str((meta or {}).get("_task_name") or "")
    cwe = str((meta or {}).get("cwe") or "")
    kind = str((meta or {}).get("vulnerability_kind") or "")
    solve = _read(os.path.join(task_root, "solution", "solve.py"))
    fam = {"bundle": families(bundle_name), "task_name": families(name),
           "cwe": families(cwe), "vulnerability_kind": families(kind),
           "solve_py": families(solve[:4000])}
    # Only the DECLARED sources vote mechanically. solve.py is kept as evidence but
    # excluded from the vote: a legitimate task often mentions more than one class
    # (a second-order traversal names both), which produced false conflicts.
    declared = {k: v for k, v in fam.items()
                if k in ("bundle", "task_name", "cwe", "vulnerability_kind") and len(v) == 1}
    conflict = ""
    if len(declared) >= 2:
        allf = set().union(*declared.values())
        if len(allf) > 1:
            conflict = ("declared sources disagree on the skill family: "
                        + str([(a, sorted(x)) for a, x in declared.items()]))
    return {"families": {k: sorted(v) for k, v in fam.items()},
            "bundle_name": bundle_name, "conflict": conflict,
            "_note": ("solve_py families are evidence only, not a mechanical vote — a task may "
                      "legitimately mention more than one class. Judge solve.py by reading it."),
            "_how_to_judge": (
                "Score 2 [Fail - Name / CWE Identity] when the archive filename or [task] name "
                "implies a DIFFERENT class than cwe / vulnerability_kind / solve.py "
                "(e.g. shopops-idor.zip with name='shopops/sqli' and CWE-89). "
                "Score 2 [Fail - Inconsistent Vulnerability in Oracle] when cwe/kind names a "
                "fundamentally different class than what solve.py exploits. "
                "Score 3 when the family is right but the CWE is imprecise. "
                "Score 5 only when all five sources name the same skill.")}


# ───────────────── D19/D20/D21 (pass@k): V4 INVERTS the fail definition ─────────────────

FULL_BUDGET_SEC = 3600   # V4: "60 minutes is the agreed reasonable budget"


def v4_passk_verdicts(models, oracle_failed=False):
    """Apply V4's pass@k rules to the per-model data the extractor already builds.

    V4 D19 REVERSES V2. Under V2 a decoy pivot was a FALSE fail that did not count.
    Under V4:
      "A fail = any model that did not solve the assigned vulnerability, INCLUDING a
       decoy pivot, a run that never attempted or probed the intended vulnerability,
       or a full-timeout run with no result."
    Only these are excluded from the bar:
      - task_specification (the task itself is broken/unsolvable)
      - refusals
      - a run cut short by a configured budget BELOW 60 minutes (harness defect)
    """
    counted, excluded, solved, shortcut = [], [], [], []

    def _reward_num(d):
        """The FINAL bar is numeric (`reward < 1`), not a string match. `1`, `1.0`
        and `1.00` are all solves; anything unparsable is NOT silently a solve."""
        for key in ("reward_txt", "reward"):
            v = d.get(key)
            if v is None:
                continue
            try:
                return float(str(v).strip())
            except (TypeError, ValueError):
                continue
        return None

    # V4 exclusion: `task_specification` = the task itself is broken or unsolvable.
    # The observable proxy is a failing oracle. BUT a packet in which some other model
    # scored reward=1 proves the task IS solvable, so the exclusion cannot apply there.
    any_solved = any((_reward_num(d) or 0) >= 1 for d in (models or {}).values())
    task_broken = bool(oracle_failed) and not any_solved
    for k, d in (models or {}).items():
        rw_num = _reward_num(d)
        rw = str(d.get("reward_txt"))
        cls = d.get("classification")
        budget = d.get("max_timeout_sec") or d.get("override_timeout_sec")
        if rw_num is not None and rw_num >= 1:
            solved.append(k)
            # D20 asks the opposite question from D19: did this win AVOID or SHORTCUT
            # the CWE? Four shortcut routes are named by the FINAL option text.
            oob = d.get("oob_route_hits") or []
            supported = d.get("technique_profile_supported")
            if oob:
                shortcut.append({"model": k,
                                 "why": (f"reward=1 with out-of-band / verifier-only route access "
                                         f"in its own commands: {oob[:3]} — the win did not come "
                                         f"through the intended sink")})
            elif supported is False:
                # No technique profile exists for this CWE, so "engaged" is always False
                # and every win would look like a shortcut. Say so instead of failing.
                shortcut.append({"model": k, "needs_judgment": True,
                                 "why": ("reward=1 and this CWE has no technique profile, so "
                                         "engagement could not be measured mechanically — judge "
                                         "from the model's own commands before failing D20")})
            elif not d.get("engaged_intended_class"):
                shortcut.append({"model": k,
                                 "why": (f"reward=1 but {d.get('chain_requests',0)} intended-chain "
                                         f"request(s) and {d.get('technique_attempts',0)} technique "
                                         f"attempt(s) — did not demonstrably use the claimed CWE "
                                         f"on the intended endpoint")})
            continue
        if task_broken:
            excluded.append({"model": k,
                             "reason": "task_specification — the shipped oracle does not score, "
                                       "so the task is broken/unsolvable; excluded by V4"}); continue
        if cls == "REFUSAL":
            excluded.append({"model": k, "reason": "refusal — excluded by V4"}); continue
        if cls in ("PROXY_BLOCK", "INFRA_EXCEPTION"):
            # V4 lists ONLY task_specification, refusals and a sub-60-minute budget
            # cutoff as exclusions. A proxy/infra block is not named, so it does NOT
            # get auto-excluded; surface it for the judging agent to rule on.
            counted.append({"model": k, "classification": cls,
                            "why": (f"{cls}: did not solve. V4 does not list this as an "
                                    "exclusion — judge whether it is really a sub-60-minute "
                                    "harness defect before discounting it"),
                            "needs_judgment": True})
            continue
        if cls == "LOW_TIMEOUT" and budget and float(budget) < FULL_BUDGET_SEC:
            # The FINAL text excludes only "a run cut short by a configured budget below
            # 60 minutes". Turn-cap / episode-step exhaustion is not a wall-clock budget
            # cut: the model had its full hour and ran out of moves, which COUNTS.
            if d.get("stop_reason") in ("turn_cap", "max_steps", "episode_limit") or \
               d.get("turn_cap_exhausted"):
                counted.append({"model": k, "classification": cls,
                                "why": ("ran out of turns/steps, not wall-clock budget — the "
                                        "sub-60-minute exclusion does not apply"),
                                "needs_judgment": True})
                continue
            excluded.append({"model": k,
                             "reason": f"budget {budget}s < {FULL_BUDGET_SEC}s — harness defect, excluded"}); continue
        # Everything else that did not solve COUNTS under V4, including decoy pivots
        # and never-attempted runs.
        counted.append({"model": k, "classification": cls,
                        "why": ("did not solve the assigned vulnerability"
                                + (" (decoy pivot / never attempted the intended class)"
                                   if cls in ("FALSE_FAIL_DECOY_ONLY", "FALSE_FAIL_NO_INTENDED_ATTEMPT")
                                   else ""))})
    d19 = 5 if counted else 2
    d20 = 2 if shortcut else 5
    return {
        "d19_counted_fails": counted,
        "d19_excluded": excluded,
        "d19_solved": solved,
        "d19_score_hint": d19,
        "d19_reason": (f"{len(counted)} model(s) failed to solve -> PASS (>=1 fail)" if counted
                       else f"no counted fail: {len(solved)} solved, {len(excluded)} excluded -> FAIL"),
        "d20_shortcut_wins": shortcut,
        "d20_score_hint": d20,
        "d20_reason": ("every reward=1 trial used the intended endpoint and claimed CWE" if not shortcut
                       else f"{len(shortcut)} reward=1 trial(s) did not demonstrably use the claimed CWE"),
        # D21's antecedent is "all three models fail", which is about SOLVES, not about
        # D19's exclusion bookkeeping. A refusal or a short-budget run is still not a
        # solve, so it must not make an all-fail packet look like a partial pass.
        "d21_all_failed": len(solved) == 0 and bool(models),
        "d21_solved_count": len(solved),
        "d21_note": ("all models failed to solve — D21 now turns entirely on whether the app "
                     "offers an honest discovery path" if len(solved) == 0 and models else
                     f"{len(solved)} model(s) solved, so this is not a zero-signal needle"),
        "_how_to_judge_d19": (
            "V4 INVERTED this from the older rubric. A decoy pivot, a run that never probed the "
            "intended vulnerability, and a full-60-minute timeout with no result ALL COUNT as "
            "fails now. Do NOT apply the old 'genuine vs false fail' engagement test here. "
            "Only task_specification (task broken/unsolvable), refusals, and a sub-60-minute "
            "budget cutoff are excluded. The bar is >=1 counted fail."),
        "_how_to_judge_d20": (
            "Ask the opposite question from D19: did anyone 'pass' by NOT DOING **or SHORTCUTTING** "
            "the CWE? Any "
            "reward=1 that used a leftover/sibling secret, an out-of-band read, a verifier-only "
            "route, or a different CWE/endpoint is a shortcut win and fails D20 — even when D19 "
            "is a 5. Confirm each flagged win against its actual commands before scoring."),
        "_how_to_judge_d21": (
            "Only relevant when ALL three models failed (see d21_all_failed). The FINAL spec is "
            "explicit that this is **judged against the app itself, NOT from the trajectories**: "
            "does a plausible path to discovering the sink exist via the UI, via a sibling API "
            "family, via linked resources? Read evidence.d21_discovery_surface — the route "
            "inventory, templates and index/listing responses — and answer from THAT, not from "
            "what the models happened to try. The exact URL is an L2 fact, so L0/L1 complexity is "
            "'can you find the sink', not 'can you hit a URL we pasted'. All-fail AND no honest "
            "discovery path = a zero-signal needle = FAIL here, even though D19 scores 5."),
    }
