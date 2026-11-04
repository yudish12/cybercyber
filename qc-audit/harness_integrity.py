#!/usr/bin/env python3
"""Dimension 23 - Harness Integrity: Agent Sandbox & Verifier Independence.

All four checks the rubric names are static, so this dimension is decided mechanically:

  1. Filesystem  - `main`'s Dockerfile, build context and volume mounts hold no
                   application source, verifier, solution or patch file.
  2. Environment - `main`'s `environment:` block sets no secret-shaped variable.
  3. Service role- `main` is the attacker sandbox: no instruction tier names it as the
                   target host, and its CMD/ENTRYPOINT does not launch app-serving code.
  4. Verifier    - a reference solver called from `tests/test.sh` may only re-derive
                   ground truth; it must not write the submission file, and the reward
                   must not follow from its result alone.

Scope boundaries the rubric states explicitly, and this module honours:
  - Check 4 concerns `tests/solve.py`. `solution/solve.sh` is REQUIRED to write the
    submission file (dimension 13) and is never inspected here.
  - Dimension 17 governs WHEN the disclosure check runs; check 4 governs WHAT the
    solver call may do. Both are scored.
  - Dimension 2 verifies a service named `main` exists; check 3 verifies what it is.
  - Dimension 11 covers network reachability; checks 1 and 2 cover the sandbox's own
    filesystem and environment.
"""
import os
import re

MAX = 2_000_000

# The rubric names these suffixes exactly.
SECRET_SHAPED = re.compile(r"_(?:TOKEN|KEY|SECRET|PASSWORD|FLAG)$", re.I)

# Code that serves the application, as opposed to an attacker shell.
APP_SERVING = re.compile(
    r"\b(?:gunicorn|uvicorn|hypercorn|daphne|waitress-serve)\b"
    r"|\bflask\s+run\b"
    r"|\bpython[0-9.]*\s+(?:-m\s+\S+\s+)?\S*app\.py\b"
    r"|\bmanage\.py\s+runserver\b"
    r"|\bnode\s+\S*(?:server|app)\.js\b", re.I)

# `main` used as a hostname, not the English word and not a filename.
#
# Every loosening here was a reproduced false fail: `curl -s -o main.html` (a filename),
# "target: main application" (a noun phrase), and sibling services called `main-web` or
# `main-db`. Every tightening was a reproduced evasion: real bundles write the target as
# markdown — `**Target**: main`, "Target: `main`" — which a bare `target:\s*main` missed.
# So: `main` must be a complete token (no trailing word char, dot or hyphen) sitting in a
# URL, a host:port, or the value of a host/target field, with markdown decoration allowed.
# `(?![\w.-])` also rejected a terminal period, so "Target: main." evaded the check.
_MAIN = r"main(?![\w-])(?!\.\w)"
MAIN_AS_HOST = re.compile(
    r"https?://" + _MAIN
    + r"|\bmain:\d{2,5}(?![\w-])(?!\.\w)"
    + r"|\b(?:host(?:name)?|target(?:\s+host)?)\s*\**\s*[=:]\s*[`\"'*]*" + _MAIN,
    re.I)

APP_SOURCE_EXT = (".py", ".js", ".ts", ".go", ".rb", ".php", ".jar", ".java")
PATCH_EXT = (".patch", ".diff")

# THE submission file, not merely a path with "submission" in the name. A grader that
# re-derives ground truth into /tmp/expected_submission.txt and diffs the agent's file
# against it is the rubric's score-5 pattern, and treating that scratch file as the
# submission turned it into a fail.
SUB_BASENAME = re.compile(r"^submission(?:[._-]|$)", re.I)
ANY_SUB_PATH = re.compile(r"(/[A-Za-z0-9_./-]*submission[A-Za-z0-9_.]*)")


def _is_submission_path(p):
    return bool(SUB_BASENAME.match(os.path.basename(p)))


def _read(p, limit=MAX):
    try:
        with open(p, "r", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def _strip_sh_comments(text):
    return re.sub(r"(?m)^\s*#[^\n]*$", "", text)


def _under(child, parent):
    """True when `child` is `parent` or sits inside it."""
    child = os.path.normpath(child)
    parent = os.path.normpath(parent)
    return child == parent or child.startswith(parent + os.sep)


def _svc_build(spec):
    """(context, dockerfile) for a service, or (None, None) when it is image-only."""
    b = spec.get("build") if isinstance(spec, dict) else None
    if isinstance(b, str):
        return b, "Dockerfile"
    if isinstance(b, dict):
        return b.get("context", "."), b.get("dockerfile", "Dockerfile")
    return None, None


def _env_keys(spec):
    """Keys of a service's environment:, in either mapping or list form."""
    env = spec.get("environment") if isinstance(spec, dict) else None
    keys = []
    if isinstance(env, dict):
        keys = list(env.keys())
    elif isinstance(env, list):
        for item in env:
            if isinstance(item, str):
                keys.append(item.split("=", 1)[0].strip())
    return [k for k in keys if k]


def _volumes(spec):
    """Host-side paths bind-mounted into a service (named volumes excluded)."""
    out = []
    for v in (spec.get("volumes") or []) if isinstance(spec, dict) else []:
        if isinstance(v, str):
            parts = v.split(":")
            if len(parts) >= 2:
                host, container = parts[0], parts[1]
                if host.startswith((".", "/", "~")) or "/" in host:
                    out.append((host, container))
        elif isinstance(v, dict) and v.get("type", "bind") == "bind" and v.get("source"):
            out.append((v["source"], v.get("target", "")))
    return out


def _copy_sources(dockerfile_text):
    """Source operands of every COPY/ADD, skipping --from=<stage> copies.

    A `COPY --from=builder` pulls from an earlier build stage inside the same
    Dockerfile, not from the build context, so it cannot leak bundle files.
    """
    srcs = []
    text = re.sub(r"\\\n", " ", dockerfile_text)           # join line continuations
    for m in re.finditer(r"^\s*(COPY|ADD)\s+(.+)$", text, re.M | re.I):
        args = m.group(2).strip()
        if re.search(r"--from=", args, re.I):
            continue
        args = re.sub(r"--\S+\s*", "", args)                # drop --chown= etc
        if args.startswith("["):                            # JSON form
            parts = re.findall(r"\"([^\"]+)\"", args)
        else:
            parts = args.split()
        if len(parts) >= 2:
            srcs.extend(parts[:-1])                         # last operand is the dest
    return srcs


def _tree_has_app_source(path, skip=()):
    """Files under `path` that look like application source, tests, or a patch."""
    hits = []
    if os.path.isfile(path):
        if path.endswith(PATCH_EXT) or path.endswith(APP_SOURCE_EXT):
            hits.append(path)
        return hits
    for dp, dns, fns in os.walk(path):
        dns[:] = [d for d in dns if d not in (".git", "__pycache__", "node_modules", ".venv")]
        if any(_under(dp, s) for s in skip):
            dns[:] = []
            continue
        for fn in fns:
            fp = os.path.join(dp, fn)
            if any(_under(fp, s) for s in skip):
                continue
            if fn.endswith(PATCH_EXT) or fn.endswith(APP_SOURCE_EXT):
                hits.append(fp)
    return hits


def _norm_cmd(args):
    """Docker CMD/ENTRYPOINT text, exec (JSON) form normalised to shell form.

    `CMD ["flask", "run"]` and `CMD ["python", "app.py"]` are two of the four examples
    the spec names, and neither matched while the JSON brackets and quotes were left in.
    """
    args = args.strip()
    if args.startswith("["):
        return " ".join(re.findall(r"\"([^\"]*)\"", args)) or args
    return args


def _submission_is_consumed(task_root, test_sh, sub_paths, sub_vars):
    """Is the agent's submission looked at anywhere under tests/, by any means?

    Deliberately verb-agnostic. Anything that MENTIONS the submission counts, except a
    write target and the assignment that merely defines the path -- because enumerating
    reader verbs is what produced the false fails, and the rubric's fail condition is the
    strong one: the grader never looks at what the agent submitted at all.
    """
    if not sub_paths and not sub_vars:
        return False
    blob = test_sh
    tdir = os.path.join(task_root, "tests")
    if os.path.isdir(tdir):
        for dp, dns, fns in os.walk(tdir):
            dns[:] = [d for d in dns if d not in ("__pycache__", ".git")]
            for fn in sorted(fns):
                if fn.endswith((".sh", ".bash", ".py")):
                    p = os.path.join(dp, fn)
                    if os.path.abspath(p) != os.path.abspath(os.path.join(tdir, "test.sh")):
                        blob += "\n" + _read(p)
    blob = _strip_sh_comments(blob)
    # drop write targets and bare path definitions, then see if anything still refers to it
    blob = re.sub(r">>?\s*[\"']?[^\s;|&)\"']*", " ", blob)
    blob = re.sub(r"\b(?:tee|cp|mv|install)\s+[^\n;|&]*", " ", blob)
    blob = re.sub(r"^[ \t]*(?:export\s+|local\s+)?[A-Za-z_]\w*\s*=\s*[\"']?"
                  r"/[A-Za-z0-9_./-]*submission[A-Za-z0-9_.]*[\"']?[ \t]*$", " ", blob, flags=re.M)
    toks = [re.escape(p) for p in sub_paths]
    toks += [r"\$\{?%s\b" % re.escape(v) for v in sub_vars]
    return bool(re.search("|".join(toks), blob))


def check_harness_integrity(task_root, compose, compose_path, instr_files):
    """Score dimension 23. Returns a dict with status, option_key and per-check findings."""
    R = task_root
    cdir = os.path.dirname(compose_path) if compose_path else os.path.join(R, "environment")
    _raw = compose.get("services") if isinstance(compose, dict) else None
    services = _raw if isinstance(_raw, dict) else {}
    main = services.get("main")
    findings = {"filesystem": [], "volumes": [], "environment": [], "service_role": [],
                "verifier": []}
    notes = []

    if not isinstance(main, dict):
        # Dimension 2 owns "a service named main must exist", so checks 1-3 stay silent
        # rather than failing the same bundle twice for one defect. Check 4 does not
        # involve `main` at all, though, so it must still run -- returning early here
        # dropped the verifier-independence clause entirely.
        notes.append("no `main` service in compose; dimension 2 owns that finding, so the "
                     "sandbox checks (1-3) are skipped. Verifier independence (4) still ran.")
        main = {}

    # ---- the paths a sandbox must not hold -------------------------------------------
    main_ctx, main_df = _svc_build(main)
    main_ctx_abs = os.path.normpath(os.path.join(cdir, main_ctx)) if main_ctx else None
    forbidden = []
    for name, spec in services.items():
        if name == "main" or not isinstance(spec, dict):
            continue
        ctx, _ = _svc_build(spec)
        if ctx:
            p = os.path.normpath(os.path.join(cdir, ctx))
            if p != main_ctx_abs:
                forbidden.append(p)
    for d in ("tests", "solution"):
        p = os.path.join(R, d)
        if os.path.isdir(p):
            forbidden.append(os.path.normpath(p))

    # ---- check 1: Dockerfile / build context ------------------------------------------
    if main_ctx_abs:
        df_path = os.path.normpath(os.path.join(main_ctx_abs, main_df))
        df_text = _read(df_path)
        for src in _copy_sources(df_text):
            if re.match(r"^(?:https?|git)://", src):
                continue
            resolved = os.path.normpath(os.path.join(main_ctx_abs, src))
            for f in forbidden:
                if _under(resolved, f) or _under(f, resolved):
                    findings["filesystem"].append(
                        f"{os.path.relpath(df_path, R)}: COPY/ADD {src!r} reaches "
                        f"{os.path.relpath(f, R)}")
                    break
            else:
                # The context itself may straddle app source even when the COPY is broad.
                hits = _tree_has_app_source(resolved, skip=[main_ctx_abs]) \
                    if not _under(resolved, main_ctx_abs) else []
                if hits:
                    findings["filesystem"].append(
                        f"{os.path.relpath(df_path, R)}: COPY/ADD {src!r} brings in "
                        f"{os.path.relpath(hits[0], R)}")
        # main's OWN context was skipped entirely, so a patch file or a duplicated copy of
        # the app sitting beside its Dockerfile was invisible. Scan it narrowly: a patch
        # is always wrong there; an app-source file only counts when the same basename
        # also exists in another service's context, i.e. it is a copy of the app.
        own = _tree_has_app_source(main_ctx_abs)
        other_names = set()
        for f in forbidden:
            for dp, dns, fns in os.walk(f):
                dns[:] = [d for d in dns if d not in (".git", "__pycache__", "node_modules")]
                other_names.update(fns)
        for hit in own:
            base = os.path.basename(hit)
            if hit.endswith(PATCH_EXT):
                findings["filesystem"].append(
                    f"`main` build context holds a patch file: {os.path.relpath(hit, R)}")
            elif base in other_names:
                findings["filesystem"].append(
                    f"`main` build context holds a copy of application source: "
                    f"{os.path.relpath(hit, R)}")

        # A build context that itself contains another service's source leaks on any COPY.
        ctx_hits = [f for f in forbidden if _under(f, main_ctx_abs)]
        if ctx_hits:
            findings["filesystem"].append(
                f"`main` build context {os.path.relpath(main_ctx_abs, R)} contains "
                f"{', '.join(os.path.relpath(h, R) for h in ctx_hits)}")

    # ---- check 1b: volume mounts -------------------------------------------------------
    for host, container in _volumes(main):
        resolved = os.path.normpath(os.path.join(cdir, host))
        matched = False
        for f in forbidden:
            if _under(resolved, f) or _under(f, resolved):
                findings["volumes"].append(
                    f"volume {host}:{container} exposes {os.path.relpath(f, R)}")
                matched = True
                break
        if matched or not os.path.exists(resolved):
            continue
        # Application source does not have to live in a build context to be app source.
        hits = _tree_has_app_source(resolved, skip=[main_ctx_abs] if main_ctx_abs else [])
        if hits:
            findings["volumes"].append(
                f"volume {host}:{container} exposes application source "
                f"{os.path.relpath(hits[0], R)}")

    # ---- check 2: environment ----------------------------------------------------------
    for k in _env_keys(main):
        if SECRET_SHAPED.search(k):
            findings["environment"].append(f"`main` environment sets {k}")

    # ---- check 3: service role ---------------------------------------------------------
    for rel_name in instr_files or []:
        text = _read(os.path.join(R, rel_name))
        for m in MAIN_AS_HOST.finditer(text):
            line = text[:m.start()].count("\n") + 1
            findings["service_role"].append(
                f"{rel_name}:{line} names `main` as the target host ({m.group(0).strip()!r})")
            break
    cmd_sources = []
    if main_ctx_abs:
        df_path = os.path.normpath(os.path.join(main_ctx_abs, main_df))
        df_text = _strip_sh_comments(_read(df_path))
        for m in re.finditer(r"^\s*(?:CMD|ENTRYPOINT)\s+(.+)$", df_text, re.M | re.I):
            cmd_sources.append((os.path.relpath(df_path, R), _norm_cmd(m.group(1))))
    for key in ("command", "entrypoint"):
        val = main.get(key)
        if val:
            cmd_sources.append((f"compose services.main.{key}",
                                " ".join(val) if isinstance(val, list) else str(val)))
    for where, cmd in cmd_sources:
        if APP_SERVING.search(cmd):
            findings["service_role"].append(
                f"{where}: `main` launches app-serving code ({cmd.strip()[:80]!r})")
            continue
        # An entrypoint that only names a wrapper script hides whatever the script execs.
        # Resolve one level: a sandbox whose entrypoint.sh execs gunicorn is still the app.
        if main_ctx_abs:
            for tok in re.findall(r"[\w./-]+\.(?:sh|bash|py)", cmd):
                cand = os.path.normpath(os.path.join(main_ctx_abs, os.path.basename(tok)))
                if not os.path.isfile(cand):
                    continue
                inner = _strip_sh_comments(_read(cand))
                m = APP_SERVING.search(inner)
                if m:
                    findings["service_role"].append(
                        f"{where}: `main`'s entrypoint {os.path.basename(tok)} launches "
                        f"app-serving code ({m.group(0)!r})")
                    break

    # ---- check 4: verifier independence ------------------------------------------------
    test_sh = _read(os.path.join(R, "tests", "test.sh"))
    body = _strip_sh_comments(test_sh)
    sub_paths = {p for p in ANY_SUB_PATH.findall(test_sh) if _is_submission_path(p)}
    sub_vars = set()
    for m in re.finditer(r"^[ \t]*(?:export\s+|local\s+)?([A-Za-z_]\w*)\s*=\s*[^\n]*?"
                         r"(/[A-Za-z0-9_./-]*submission[A-Za-z0-9_.]*)", test_sh, re.M):
        if _is_submission_path(m.group(2)):
            sub_vars.add(m.group(1))
            sub_paths.add(m.group(2))
    solver_call = re.compile(
        r"^[^\n#]*\b(?:python[0-9.]*|python3|sh|bash)?\s*\.?/?(?:tests/)?solve(?:_ref|_oracle)?\.py\b[^\n]*",
        re.M)
    calls = [m.group(0).strip() for m in solver_call.finditer(body)]
    if calls:
        notes.append(f"{len(calls)} reference-solver call(s) in tests/test.sh")
        sub_alt = "|".join(re.escape(p) for p in sub_paths) if sub_paths else None
        var_alt = "|".join(re.escape(v) for v in sub_vars) if sub_vars else None
        writes = []
        for c in calls:
            if sub_alt and re.search(r">>?\s*[\"']?(?:%s)" % sub_alt, c):
                writes.append(c)
            elif var_alt and re.search(r">>?\s*[\"']?\$\{?(?:%s)\b" % var_alt, c):
                writes.append(c)
            elif sub_alt and re.search(r"\|\s*tee\s+[\"']?(?:%s)" % sub_alt, c):
                writes.append(c)
            elif var_alt and re.search(r"\|\s*tee\s+[\"']?\$\{?(?:%s)\b" % var_alt, c):
                writes.append(c)
        for c in writes:
            findings["verifier"].append(
                f"tests/test.sh: the reference-solver call writes the submission file "
                f"({c[:90]!r})")
        # The write need not sit on the solver's own line: `cp $GT $SUBMISSION` a few
        # lines later has exactly the same effect. The submission must be the actual
        # operand though -- an earlier `> /tmp/a` on the same line as a later read of the
        # submission is not a write to it.
        if not writes:
            def _sub_tok(tok):
                tok = tok.strip().strip("\"'")
                if tok.startswith("$"):
                    return tok.lstrip("$").strip("{}") in sub_vars
                return tok in sub_paths
            for ln in body.splitlines():
                if solver_call.match(ln):
                    continue
                hit = None
                for m in re.finditer(r"(?:>>?|\btee\b)\s+([\"']?[^\s;|&]+)", ln):
                    if _sub_tok(m.group(1)):
                        hit = ln
                        break
                if not hit:
                    for seg in re.split(r"[;&]|\|\|", ln):
                        toks = seg.split()
                        if len(toks) >= 3 and toks[0] in ("cp", "mv", "install") \
                                and _sub_tok(toks[-1]):
                            hit = ln
                            break
                if hit:
                    findings["verifier"].append(
                        f"tests/test.sh writes the submission file itself while a reference "
                        f"solver is present ({hit.strip()[:90]!r})")
                    break

        # does the solver script itself write the submission?
        for cand in ("tests/solve.py", "tests/solve_ref.py", "tests/solve_oracle.py"):
            sp = os.path.join(R, cand)
            if not os.path.exists(sp):
                continue
            ssrc = _read(sp)
            names = {m.group(1) for m in re.finditer(
                r"^[ \t]*([A-Za-z_]\w*)\s*=\s*[^\n]*submission", ssrc, re.M | re.I)}
            alt = "|".join(re.escape(n) for n in names) if names else None
            pats = [r"open\s*\([^)]*submission[^)]*,\s*[\"']w",
                    r"Path\s*\([^)]*submission[^)]*\)\s*\.write_text"]
            if alt:
                pats += [r"open\s*\(\s*(?:%s)\s*,\s*[\"']w" % alt,
                         r"Path\s*\(\s*(?:%s)\s*\)\s*\.write_text" % alt,
                         r"(?:%s)\.write_text\s*\(" % alt]
            if any(re.search(p, ssrc, re.I) for p in pats):
                findings["verifier"].append(f"{cand} writes the submission file itself")

        # The rubric's SECOND condition: "the reward must not follow from its result
        # alone". Only the unambiguous form is failed -- the submission is never
        # mentioned anywhere under tests/ except as something being written to. The
        # earlier version whitelisted reader verbs (cat / < / open / read_text) and so
        # false-failed every grader using diff, cmp, grep, head, awk or sed; a real
        # human-passed bundle flipped to FAIL on a one-word change.
        if not _submission_is_consumed(R, test_sh, sub_paths, sub_vars):
            findings["verifier"].append(
                "tests/test.sh calls a reference solver but the submission file is never "
                "read anywhere under tests/, so the reward follows from the solver's own "
                "result rather than from what the agent did")

    # ---- disposition -------------------------------------------------------------------
    # Option order in the rubric, so the caller can pick the verbatim text:
    #   0 build-context COPY/ADD | 1 volume | 2 environment | 3 service role | 4 verifier
    order = [("filesystem", 0), ("volumes", 1), ("environment", 2),
             ("service_role", 3), ("verifier", 4)]
    fired = [(k, i) for k, i in order if findings[k]]
    if fired:
        return {"status": "FAIL", "option_key": fired[0][1], "fired": [k for k, _ in fired],
                "findings": findings, "notes": notes}
    return {"status": "PASS", "option_key": 5, "fired": [], "findings": findings,
            "notes": notes}
