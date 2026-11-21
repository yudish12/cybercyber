#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
en4_finder.py  --  static FINDER layer of the EN4 eval
(Environment: Operational & Reproducibility -- the #1 recurring fail).

*** V19 NOTE: Provenance/Licensing moved to en5_finder.py ***
V11/V14 folded "[Fail - Provenance / Licensing]" into EN4. The official V19
rubric splits it out into its own numbered dimension, {EN5} -- see en5_finder.py
(and its module docstring for a naming-collision warning: V19's official EN5 is
NOT cqc's/custom_finder.py's own "EN5 = Leftover Harness/Seeder Endpoint
Exposure"). This file keeps the image/wheel/NOTICE collection helpers
(collect_images, collect_wheels, find_notice, _row_license, the wheel/license
matchers) as SHARED infra that en5_finder.py imports -- do not remove them even
though en4's own `find()` no longer calls `_provenance`.

READ-ONLY. It POINTS; it does not render the EN4 verdict. Coverage + recall:
enumerate every base image, flag mutable (unpinned) tags, and surface
reproducibility signals for the reader / a boot.

Bias to flag (false fails > missed fails): an unpinned tag is a FAIL-candidate;
runtime-only reproducibility is a LIVE item; nothing is dropped. The reader
opens the Dockerfiles and renders the certain verdict.

V19 EN4 fail labels covered:
  [Fail - Unbounded or Unpinned]   -> unpinned_images
  [Fail - Reproducibility]         -> reproducibility (static signals; rest LIVE)

Usage:  python3 -I en4_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io, zipfile

_LIC = (r"(MIT|BSD-\d-Clause|BSD|Apache-2\.0|Apache|GPL-\d(\.\d)?(-or-later|-only)?|"
        r"LGPL[\w.\-]*|MPL-2\.0|MPL|PSF-2\.0|PSF|Python-2\.0|CNRI[\w.\-]*|ISC|"
        r"Unlicense|CC0[\w.\-]*|Zlib|HPND|0BSD)")
_LIC_RE = re.compile(_LIC)
_INTERNET_RE = re.compile(
    r"(curl\s|wget\s|apt-get\s+(?:update|install)|apk\s+add|pip\s+install(?!.*--no-index)"
    r"|https?://(?!localhost|127\.0\.0\.1|gateway|main|internal|host\.docker))",
    re.I)


def _read(path):
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# images                                                                       #
# --------------------------------------------------------------------------- #
def collect_images(task_dir):
    env = os.path.join(task_dir, "environment")
    imgs = []
    # FROM in every Dockerfile
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if fn == "Dockerfile" or fn.startswith("Dockerfile"):
                full = os.path.join(dp, fn)
                for i, line in enumerate(_read(full).splitlines(), 1):
                    m = re.match(r"\s*FROM\s+(\S+)", line, re.I)
                    if m:
                        imgs.append(_img_rec(m.group(1), os.path.relpath(full, task_dir), i))
    # image: in compose
    for name in ("docker-compose.yaml", "docker-compose.yml"):
        full = os.path.join(env, name)
        for i, line in enumerate(_read(full).splitlines(), 1):
            m = re.match(r"\s*image:\s*(\S+)", line)
            if m:
                imgs.append(_img_rec(m.group(1).strip('"\''), os.path.join("environment", name), i))
    # de-dup by ref
    seen, out = set(), []
    for r in imgs:
        if r["ref"] not in seen:
            seen.add(r["ref"]); out.append(r)
    return out


def _img_rec(ref, src, line):
    pinned = "@sha256:" in ref
    base = ref.split("@", 1)[0]
    repo = base.rsplit(":", 1)[0]
    repo_short = repo.rsplit("/", 1)[-1]
    return {"ref": ref, "base": base, "repo": repo, "repo_short": repo_short,
            "pinned": pinned, "source": src, "line": line}


# --------------------------------------------------------------------------- #
# NOTICE                                                                        #
# --------------------------------------------------------------------------- #
def find_notice(task_dir):
    p = os.path.join(task_dir, "environment", "NOTICE.md")
    if os.path.exists(p):
        return {"present": True, "path": "environment/NOTICE.md",
                "text": _read(p), "abs": p}
    return {"present": False, "path": "environment/NOTICE.md", "text": "", "abs": p}


_LICENSES_PARA_RE = re.compile(r'(?mi)^\s*licen[cs]es?\s*:')


def _row_license(notice_text, key, window=0):
    """Find the NOTICE line mentioning `key`; return the license token on it, within
    `window` lines below it (two-line list formats where the license is on the next
    line), OR in a shared trailing "Licenses:" summary paragraph that names `key` even
    across a blank line (the recurring real-world format: N components bulleted, then
    one combined "Licenses: X ...; Y ...; Z ..." paragraph below -- a fixed small
    window never bridges that gap, which is why this was a long-standing false
    positive every "N images, one shared Licenses: line" bundle tripped)."""
    lines = notice_text.splitlines()
    mentioned = False
    for i, line in enumerate(lines):
        if key and key in line:
            mentioned = True
            for j in range(i, min(i + 1 + window, len(lines))):
                m = _LIC_RE.search(lines[j])
                if m:
                    return m.group(0)
    if mentioned and key:
        # fall back to a shared "Licenses:" summary paragraph anywhere in the doc that
        # also names this component (by its short/repo-style key).
        for i, line in enumerate(lines):
            if _LICENSES_PARA_RE.match(line):
                para = [line]
                for j in range(i + 1, len(lines)):
                    if not lines[j].strip():
                        break
                    para.append(lines[j])
                para_text = " ".join(para)
                if key.lower() in para_text.lower():
                    m = _LIC_RE.search(para_text)
                    if m:
                        return m.group(0)
    # a key can appear more than once (prose + a list row); only fail if NO occurrence
    # has a license within its window or the shared summary paragraph.
    return "" if mentioned else None


# --------------------------------------------------------------------------- #
# wheels                                                                        #
# --------------------------------------------------------------------------- #
def collect_wheels(task_dir):
    env = os.path.join(task_dir, "environment")
    out = []
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if fn.endswith(".whl"):
                full = os.path.join(dp, fn)
                out.append({"file": fn, "rel": os.path.relpath(full, task_dir),
                            "metadata_license": _wheel_license(full)})
    return out


def _wheel_license(whl_path):
    try:
        with zipfile.ZipFile(whl_path) as z:
            metas = [n for n in z.namelist() if n.endswith(".dist-info/METADATA") or n.endswith("/METADATA")]
            if not metas:
                return ""
            text = z.read(metas[0]).decode("utf-8", "replace")
    except Exception:
        return ""
    m = re.search(r"(?mi)^License-Expression:\s*(.+)$", text)
    if m:
        return m.group(1).strip()
    m = re.search(r"(?mi)^License:\s*(.+)$", text)
    if m and m.group(1).strip() and m.group(1).strip().upper() != "UNKNOWN":
        return m.group(1).strip()
    cls = re.findall(r"(?mi)^Classifier:\s*License\s*::\s*(.+)$", text)
    if cls:
        return "; ".join(c.strip() for c in cls)
    return ""


def _lic_token(s):
    m = _LIC_RE.search(s or "")
    return m.group(0) if m else ""


def _lic_family(tok):
    t = (tok or "").lower()
    for key in ("lgpl", "agpl", "gpl", "apache", "bsd", "mpl", "mit", "psf",
                "python", "cnri", "isc", "zlib", "hpnd", "unlicense", "cc0"):
        if key in t:
            return {"agpl": "GPL", "lgpl": "LGPL", "gpl": "GPL",
                    "python": "PSF", "psf": "PSF"}.get(key, key.upper())
    return t.upper()


def _lic_ver(tok):
    m = re.search(r"\d+(?:\.\d+)?", tok or "")
    return m.group(0) if m else ""


def _lic_rel(notice_tok, meta_tok):
    """match / review / fail. Family mismatch = fail; same family, differing
    explicit versions = review; a refinement (one side unversioned) = match."""
    nt, mt = _lic_token(notice_tok), _lic_token(meta_tok)
    if not nt or not mt:
        return "match"          # nothing comparable -> coverage check handles gaps
    if _lic_family(nt) != _lic_family(mt):
        return "fail"
    nv, mv = _lic_ver(nt), _lic_ver(mt)
    if nv and mv and nv != mv:
        return "review"
    return "match"


# --------------------------------------------------------------------------- #
# the two remaining EN4 sub-finders (Provenance/Licensing moved to en5_finder) #
# --------------------------------------------------------------------------- #
def _unpinned(task_dir, images):
    fail = []
    for im in images:
        if not im["pinned"]:
            fail.append({"component": im["ref"], "issue": "mutable tag, no @sha256 digest pin",
                         "source": f'{im["source"]}:{im["line"]}'})
    return {"label": "[Fail - Unbounded or Unpinned]", "fail_candidates": fail,
            "files_to_read": sorted({im["source"] for im in images})}


def _reproducibility(task_dir):
    env = os.path.join(task_dir, "environment")
    cands, live, files = [], [], set()
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if not (fn.endswith(".sh") or fn.startswith("Dockerfile") or fn.endswith((".yaml", ".yml"))):
                continue
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, task_dir)
            for i, line in enumerate(_read(full).splitlines(), 1):
                if _INTERNET_RE.search(line):
                    cands.append({"file": rel, "line": i, "signal": "possible runtime/build internet",
                                  "text": line.strip()[:160]})
                    files.add(rel)
                if re.search(r"ALLOW(ED)?_?IP|NOT_ALLOWED_IP|client[_-]?ip|allowlist", line, re.I):
                    cands.append({"file": rel, "line": i, "signal": "IP allowlist (check vs Docker subnet)",
                                  "text": line.strip()[:160]})
                    files.add(rel)
    live = [
        "boot: run twice -- confirm no flaky boot / service-discovery drift",
        "boot: restart main -- confirm the scored marker does not desync",
        "config: verifier/solver timeout must be >= agent timeout (false infra_error) -- see timeout_budget",
        "boot: confirm the runtime needs no public internet; report-judge host reachable offline",
    ]
    return {"label": "[Fail - Reproducibility]", "candidates": cands, "live_items": live,
            "files_to_read": sorted(files)}


# --------------------------------------------------------------------------- #
# timeout budget (v1.6, the 6afb975e9c3753a2c8232a77 miss): a retry fix that  #
# lengthened behavior.sh's wait to 240s+ left check.py's caller timeout=60 --  #
# the caller killed the callee long before its own budget ran out. Compare    #
# every wait against the thing that waits on it.                              #
# --------------------------------------------------------------------------- #
_NUM = r"(\d+(?:\.\d+)?)"
_CNT_LOOP_RE = re.compile(r"while\s+\[\[?\s*\"?\$\$?\{?\w+\}?\"?\s+-l[te]\s+" + _NUM +
                          r"|for\s+\w+\s+in\s+\$\(\s*seq\s+(?:\d+\s+)?" + _NUM + r"\s*\)"
                          r"|for\s+\w+\s+in\s+\{\d+\.\." + _NUM + r"\}"
                          r"|for\s*\(\(\s*\w+\s*=\s*\d+\s*;\s*\w+\s*<=?\s*" + _NUM)
_OPEN_LOOP_RE = re.compile(r"while\s+(?::|true)(?=[\s;]|$)|until\s+")
_FUNC_DEF_RE = re.compile(r"(?m)^\s*(?:function\s+)?(\w+)\s*\(\)\s*\{")
_DEADLINE_RE = re.compile(r"SECONDS\s*\+\s*" + _NUM + r"|SECONDS\s*\+\s*\$?\{?(\w+)\}?")
_SLEEP_RE = re.compile(r"\bsleep\s+" + _NUM)
_MAXT_RE = re.compile(r"(?:--max-time|--connect-timeout|-m)\s+" + _NUM + r"|\btimeout\s+" + _NUM + r"\b")
_PY_DEADLINE_RE = re.compile(r"(?:time\.time|time\.monotonic|monotonic)\(\)\s*\+\s*" + _NUM)
_PY_RANGE_RE = re.compile(r"for\s+\w+\s+in\s+range\(\s*(?:\d+\s*,\s*)?" + _NUM + r"\s*\)")
_PY_SLEEP_RE = re.compile(r"time\.sleep\(\s*" + _NUM)
_CALLER_PY_RE = re.compile(r"timeout\s*=\s*" + _NUM)
_CALLER_SH_RE = re.compile(r"\btimeout\s+(?:-\w+\s+\S+\s+)*" + _NUM + r"[sm]?\s+(?:bash|sh|python3?|\S+\.sh)")


def _f(x):
    return float(x) if x is not None else None


def _first_num(m):
    return next((float(g) for g in m.groups() if g and re.fullmatch(r"\d+(?:\.\d+)?", g)), None)


def _shell_waits(text, src):
    """every bounded/unbounded wait loop in a shell blob -> [{src, line, kind, floor, worst, unbounded}]"""
    lines = text.splitlines()
    out = []
    assigns = dict(re.findall(r"\b([A-Z_][A-Z0-9_]*)=(\d+)\b", text))
    # shell function bodies, so a loop that calls fetch_audit() picks up its curl --max-time
    funcs = {}
    for fm in _FUNC_DEF_RE.finditer(text):
        body = text[fm.end():]
        end = re.search(r"(?m)^\s*\}\s*$", body)
        funcs[fm.group(1)] = body[:end.start()] if end else body[:800]
    for i, ln in enumerate(lines):
        # loop body = from the head to its MATCHING `done` (do/done depth, so a nested
        # `while read ... done` does not end the outer loop; one-liners end on the same line)
        hm = _CNT_LOOP_RE.search(ln) or _OPEN_LOOP_RE.search(ln)
        if not hm:
            continue
        span = ln[hm.start():] + "\n" + "\n".join(lines[i + 1:i + 40])
        depth, cut = 0, len(span)
        for tm in re.finditer(r"\b(do|done)\b", span):
            depth += 1 if tm.group(1) == "do" else -1
            if depth == 0:
                cut = tm.start()
                break
        win = span[:cut]
        win += " " + " ".join(b for n, b in funcs.items() if re.search(r"\b" + re.escape(n) + r"\b", win)
                              and not re.search(r"\b" + re.escape(n) + r"\s*\(\)", win))
        m = _CNT_LOOP_RE.search(ln)
        if m:
            n = _first_num(m)
            s = sum(float(x) for x in _SLEEP_RE.findall(win))
            t = sum(float(a or b) for a, b in _MAXT_RE.findall(win))
            out.append({"src": src, "line": i + 1, "kind": "attempt loop", "attempts": n,
                        "floor": n * s, "worst": n * (s + t), "unbounded": False,
                        "text": ln.strip()[:150]})
            continue
        if _OPEN_LOOP_RE.search(ln):
            # deadline in the 12 lines before or after the loop head
            ctx = " ".join(lines[max(0, i - 12):i + 12])
            d = _DEADLINE_RE.search(ctx)
            secs = None
            if d:
                secs = _f(d.group(1)) if d.group(1) else _f(assigns.get(d.group(2)))
            if secs is not None:
                out.append({"src": src, "line": i + 1, "kind": "deadline loop", "floor": secs,
                            "worst": secs + 10, "unbounded": False, "text": ln.strip()[:150]})
            elif _SLEEP_RE.search(win) and not re.search(r"read\s+-r|IFS=", ln):
                out.append({"src": src, "line": i + 1, "kind": "open loop (no bound found)",
                            "floor": None, "worst": None, "unbounded": True, "text": ln.strip()[:150]})
    return out


def _py_waits(text, src):
    out = []
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        m = _PY_DEADLINE_RE.search(ln)
        if m:
            out.append({"src": src, "line": i + 1, "kind": "deadline", "floor": float(m.group(1)),
                        "worst": float(m.group(1)) + 10, "unbounded": False, "text": ln.strip()[:150]})
            continue
        m = _PY_RANGE_RE.search(ln)
        if m:
            win = " ".join(lines[i:i + 12])
            s = sum(float(x) for x in _PY_SLEEP_RE.findall(win))
            if s:
                n = float(m.group(1))
                t = sum(float(x) for x in re.findall(r"timeout\s*=\s*" + _NUM, win))
                out.append({"src": src, "line": i + 1, "kind": "attempt loop", "attempts": n,
                            "floor": n * s, "worst": n * (s + t), "unbounded": False,
                            "text": ln.strip()[:150]})
    return out


def _compose_main_block(text):
    m = re.search(r"(?m)^(\s+)main:\s*$", text)
    if not m:
        return text, False
    ind = len(m.group(1))
    rest = text[m.end():].splitlines()
    block = []
    for ln in rest:
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= ind and not ln.lstrip().startswith("#"):
            break
        block.append(ln)
    return "\n".join(block), True


def _verifier_timeout(task_dir):
    t = _read(os.path.join(task_dir, "task.toml"))
    m = re.search(r"(?ms)^\[verifier\]\s*$(.*?)(?=^\[|\Z)", t)
    if m:
        v = re.search(r"(?m)^\s*timeout_sec\s*=\s*" + _NUM, m.group(1))
        if v:
            return float(v.group(1))
    return None


def _timeout_budget(task_dir):
    cands, files = [], set()
    # -- agent: the main container's own service-discovery wait
    comp_rel = next((r for r in ("environment/docker-compose.yaml", "environment/docker-compose.yml")
                     if os.path.isfile(os.path.join(task_dir, r))), None)
    agent = []
    if comp_rel:
        block, found_main = _compose_main_block(_read(os.path.join(task_dir, comp_rel)))
        agent = [w for w in _shell_waits(block, comp_rel + (" (main)" if found_main else ""))
                 if not w["unbounded"] or found_main]
        files.add(comp_rel)
    agent_worst = max((w["worst"] for w in agent if w["worst"] is not None), default=None)
    agent_floor = max((w["floor"] for w in agent if w["floor"] is not None), default=None)

    # -- verifier + solver waits, per script
    waits = {}
    for base in ("tests", "solution"):
        root = os.path.join(task_dir, base)
        for dp, _d, fns in os.walk(root):
            for fn in fns:
                full = os.path.join(dp, fn)
                rel = os.path.relpath(full, task_dir)
                txt = _read(full)
                if fn.endswith(".sh"):
                    ws = _shell_waits(txt, rel)
                elif fn.endswith(".py"):
                    ws = _py_waits(txt, rel) + _shell_waits(
                        "\n".join(re.findall(r"[\"']([^\"']*(?:sleep|curl)[^\"']*)[\"']", txt)), rel)
                else:
                    continue
                if ws:
                    waits[rel] = ws
                    files.add(rel)

    def _wmax(rel, key):
        return max((w[key] for w in waits.get(rel, []) if w[key] is not None), default=None)

    # verifier scope = what the verifier actually runs: test.sh, tests/behavior/*, tests/stages/*,
    # and any tests/ script test.sh names. Standalone QC scripts (isolation_test.sh) are not run.
    test_sh = _read(os.path.join(task_dir, "tests", "test.sh"))
    verifier_rels = [r for r in waits if r.startswith(("tests/behavior/", "tests/stages/"))
                     or r == "tests/test.sh"
                     or (r.startswith("tests/") and os.path.basename(r) in test_sh)]
    solver_rels = [r for r in waits if r.startswith("solution/")]
    v_worst = max((_wmax(r, "worst") or 0 for r in verifier_rels), default=None)
    s_worst = max((_wmax(r, "worst") or 0 for r in solver_rels), default=None)

    # 1. verifier / solver give up before the agent's own wait
    if agent_worst:
        if not verifier_rels:
            cands.append({"issue": "agent waits up to %.0fs for services but no verifier-side wait/retry "
                                   "was found -- a single-shot probe can infra-fail a slow boot" % agent_worst,
                          "where": comp_rel})
        elif v_worst is not None and v_worst < agent_worst:
            cands.append({"issue": "verifier wait budget %.0fs < agent wait budget %.0fs -- verifier gives up "
                                   "first (false infra_error / false 0)" % (v_worst, agent_worst),
                          "where": ", ".join(verifier_rels)})
        if solver_rels and s_worst is not None and s_worst < agent_worst:
            cands.append({"issue": "solver wait budget %.0fs < agent wait budget %.0fs (oracle can flake "
                                   "on a slow boot)" % (s_worst, agent_worst), "where": ", ".join(solver_rels)})

    # 2. caller timeout shorter than the callee's own wait
    callers = []
    for base in ("tests", "solution"):
        root = os.path.join(task_dir, base)
        for dp, _d, fns in os.walk(root):
            for fn in fns:
                if not fn.endswith((".py", ".sh")):
                    continue
                full = os.path.join(dp, fn)
                rel = os.path.relpath(full, task_dir)
                lines = _read(full).splitlines()
                for i, ln in enumerate(lines):
                    rx = _CALLER_PY_RE if fn.endswith(".py") else _CALLER_SH_RE
                    m = rx.search(ln)
                    if not m:
                        continue
                    ctx = " ".join(lines[max(0, i - 3):i + 1])
                    callee = re.search(r"([\w./-]+\.(?:sh|py))", ctx)
                    if not callee:
                        continue
                    cname = os.path.basename(callee.group(1))
                    crel = next((r for r in waits if os.path.basename(r) == cname and r != rel), None)
                    callers.append({"caller": f"{rel}:{i + 1}", "timeout": float(m.group(1)),
                                    "callee": crel or cname})
                    files.add(rel)
                    if not crel:
                        continue
                    floor, worst = _wmax(crel, "floor"), _wmax(crel, "worst")
                    if floor is not None and float(m.group(1)) < floor:
                        cands.append({"issue": "caller timeout %.0fs < callee %s minimum wait %.0fs -- the caller "
                                               "kills the callee before its own budget ends"
                                               % (float(m.group(1)), crel, floor), "where": f"{rel}:{i + 1}"})
                    elif worst is not None and float(m.group(1)) < worst:
                        cands.append({"issue": "caller timeout %.0fs < callee %s worst-case wait %.0fs (may cut a "
                                               "slow boot short)" % (float(m.group(1)), crel, worst),
                                      "where": f"{rel}:{i + 1}"})

    # 3. sum of verifier phases must fit [verifier] timeout_sec
    total = _verifier_timeout(task_dir)
    judge = []
    for rel in ("tests/report/rubric.toml", "tests/stages/rubric.toml"):
        m = re.search(r"(?m)^\s*timeout\s*=\s*" + _NUM, _read(os.path.join(task_dir, rel)))
        if m:
            judge.append({"src": rel, "timeout": float(m.group(1))})
            files.add(rel)
    behavior = max((c["timeout"] for c in callers if c["caller"].startswith("tests/")), default=None)
    if behavior is None:
        behavior = v_worst
    need = (behavior or 0) + sum(j["timeout"] for j in judge)
    if total is not None and need and need > total:
        cands.append({"issue": "verifier phases need ~%.0fs (behavior %.0fs + judges %s) > [verifier] "
                               "timeout_sec %.0fs" % (need, behavior or 0,
                                                      "+".join("%.0f" % j["timeout"] for j in judge) or "0", total),
                      "where": "task.toml [verifier]"})
    for rel, ws in waits.items():
        for w in ws:
            if w["unbounded"]:
                cands.append({"issue": "open wait loop with no attempt bound or deadline found -- confirm it "
                                       "terminates before the caller/verifier timeout", "where": f"{rel}:{w['line']}"})
    files.add("task.toml")
    return {"label": "[Fail - Reproducibility] (timeout budget)", "candidates": cands,
            "agent_wait": {"floor": agent_floor, "worst": agent_worst, "loops": agent},
            "verifier_waits": {r: waits[r] for r in verifier_rels},
            "solver_waits": {r: waits[r] for r in solver_rels},
            "callers": callers, "judge_timeouts": judge, "verifier_timeout_sec": total,
            "files_to_read": sorted(files),
            "note": "every wait must fit inside whatever waits on it: verifier/solver budget >= agent "
                    "budget; caller timeout > callee wait (floor = attempts x sleep, worst adds per-try "
                    "timeouts); behavior + report/stage judges <= [verifier] timeout_sec. Numbers are "
                    "parsed heuristically -- the reader re-derives them from the files."}


# --------------------------------------------------------------------------- #
# entry                                                                        #
# --------------------------------------------------------------------------- #
def find(task_dir):
    images = collect_images(task_dir)
    notice = find_notice(task_dir)
    return {
        "task_dir": os.path.abspath(task_dir),
        "notice": {"present": notice["present"], "path": notice["path"]},
        "images": images,
        "checks": {
            "unpinned_images": _unpinned(task_dir, images),
            "reproducibility": _reproducibility(task_dir),
            "timeout_budget": _timeout_budget(task_dir),
        },
    }


def _summary(r):
    o = [f"EN4 FINDER — {r['task_dir']}  (Provenance/Licensing -> en5_finder.py, V19)",
         f"  NOTICE present: {r['notice']['present']}  images: {len(r['images'])}"]
    up = r["checks"]["unpinned_images"]
    o.append(f"  [Unbounded or Unpinned] FAIL-candidates={len(up['fail_candidates'])}")
    for c in up["fail_candidates"]:
        o.append(f"     FAIL?  {c['component']}  — {c['issue']} ({c['source']})")
    rp = r["checks"]["reproducibility"]
    o.append(f"  [Reproducibility] static signals={len(rp['candidates'])}, LIVE checks={len(rp['live_items'])}")
    for c in rp["candidates"][:15]:
        o.append(f"     signal {c['file']}:{c['line']}  {c['signal']}  — {c['text']}")
    tb = r["checks"]["timeout_budget"]
    aw = tb["agent_wait"]
    o.append(f"  [Timeout budget] agent wait floor/worst={aw['floor']}/{aw['worst']}s  "
             f"verifier timeout_sec={tb['verifier_timeout_sec']}  callers={len(tb['callers'])}  "
             f"FAIL-candidates={len(tb['candidates'])}")
    for c in tb["callers"]:
        o.append(f"     caller {c['caller']}  timeout={c['timeout']:.0f}s -> {c['callee']}")
    for c in tb["candidates"]:
        o.append(f"     FAIL?  {c['issue']}  ({c['where']})")
    o.append("  NOTE: finder only points. The reader opens NOTICE + Dockerfiles + wheels and decides.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: en4_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
