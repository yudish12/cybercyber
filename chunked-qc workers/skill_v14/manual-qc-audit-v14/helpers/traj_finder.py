#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
traj_finder.py  --  static FINDER for the TRAJECTORY group (TR2, TR3).

Decidable from the shipped oracle/noop trajectories (always present pre-pass@k):
  TR2 Noop Earns Nothing   [Fail - Noop Scores]     : the noop trajectory reward must be 0.
  TR3 Solve Is Wired       [Fail - Oracle Unwired]  : the oracle trajectory reward must be 1,
                                                       AND the oracle solve must use the intended
                                                       path (reader reads the oracle trajectory).

Usage:  python3 -I traj_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io
HERE = os.path.dirname(os.path.abspath(__file__))


def _read(p):
    try:
        with io.open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _reward(task_dir, which):
    """Return (value|None, path) for a trajectory's reward."""
    base = os.path.join(task_dir, "trajectories", which)
    for rel in ("reward.txt", "verifier/reward.txt", "reward.json", "verifier/reward.json"):
        p = os.path.join(base, rel)
        if os.path.exists(p):
            t = _read(p).strip()
            if rel.endswith(".json"):
                try:
                    return int(json.loads(t).get("reward")), os.path.relpath(p, task_dir)
                except Exception:
                    continue
            m = re.search(r"-?\d+", t)
            if m:
                return int(m.group(0)), os.path.relpath(p, task_dir)
    return None, f"trajectories/{which}/reward.txt"


def _tr2(task_dir):
    val, path = _reward(task_dir, "noop")
    cands = []
    if val is None:
        cands.append({"file": path, "why": "noop trajectory reward not found (shipped noop required)"})
    elif val != 0:
        cands.append({"file": path, "why": f"noop earns reward {val} (must be 0)"})
    return {"label": "[Fail - Noop Scores]", "noop_reward": val, "candidates": cands,
            "files_to_read": ["trajectories/noop/reward.txt", "trajectories/noop/test.log",
                              "trajectories/noop/agent/trajectory.json"]}


# A line that issues a request. Covers curl/wget/BASE/http AND helper idioms
# get("/x") / post("/x",...) / get_json / post_json / requests.get|post / urlopen.
_REQ_LINE_RE = re.compile(
    r"https?://|\$\{?BASE\}?|\bcurl\b|\bwget\b|post_json|get_json"
    r"|\bget\(|\bpost\(|requests\.(?:get|post)|urlopen", re.I)
_ASSERT_RE = re.compile(r"grep\s+-q|assert|\bfail\b|\bdie\b|\|\|\s*(fail|die|exit)", re.I)
_URLPATH_RE = re.compile(r"(?:\$\{?BASE\}?|https?://[^/\s\"']+)(/[A-Za-z0-9_\-/.]+)")
# A bare quoted absolute path passed to a request helper, e.g. get("/nw-ops/settlements").
_BAREPATH_RE = re.compile(r"[\"'](/[A-Za-z0-9_\-/.]+)[\"']")
# A line that ESTABLISHES a breadcrumb from a fetched response: the `X not in resp: die`
# membership idiom, a grep/assert/regex over a response, or an extraction (contains/locate).
_DISC_CHECK_RE = re.compile(
    r"not\s+in\b|grep|assert|\bdie\b|\bfail\b|re\.(?:match|search|findall)"
    r"|\bin\s+(?:landing|body|resp|response|text|out|page|html|r)\b"
    r"|contains|locate|advertis|extract", re.I)
_DISC_NOISE = {"logs", "verifier", "tmp", "api", "dev", "etc", "work", "opt", "bin", "var",
               "www", "health", "credentials", "index"}


def _hop_segs(line):
    """All candidate path segments named by request literals on a line (prefixed OR bare quoted)."""
    segs = []
    for rx in (_URLPATH_RE, _BAREPATH_RE):
        for m in rx.finditer(line):
            for s in m.group(1).strip("/").split("/"):
                if len(s) >= 3 and not s.isdigit() and s.lower() not in _DISC_NOISE:
                    segs.append(s)
    return segs


def _unverified_discovery(task_dir):
    """TR3 [Fail - Unverified Discovery]. Each later-hop request literal (beyond the entry point)
    that a black-box solver must DISCOVER has to be established from a fetched response BEFORE it is
    used -- a prior discovery-check (`X not in resp: die`, grep -q, assert, a regex over a response,
    or an extraction) naming that segment. Calibration vs the official cyber_quality_check:
      * per-hop, threshold >=1 (never wait for a 2nd uncovered hop -- do not under-flag);
      * fires regardless of whether the file has OTHER assertions (no file-global exculpation);
      * recognises the Python `not in <response>` idiom and extraction-into-variable, so a route
        parsed from a response (get(login_route)) or asserted with `if "x" not in body` is NOT a
        false positive. A route carried in a VARIABLE has no literal here and is correctly ignored
        (it was discovered, not hardcoded)."""
    out = []
    for name in ("solve.sh", "solve.py"):
        p = os.path.join(task_dir, "solution", name)
        if not os.path.exists(p):
            continue
        lines = _read(p).splitlines()
        seen, uncovered = [], []
        for idx, line in enumerate(lines):
            if not _REQ_LINE_RE.search(line):
                continue
            for seg in _hop_segs(line):
                if seg in seen:
                    continue
                entry = not seen
                seen.append(seg)
                if entry:
                    continue
                # covered iff a PRIOR line both names the seg and is a discovery-check
                covered = any(seg in l and _DISC_CHECK_RE.search(l) for l in lines[:idx])
                if not covered:
                    uncovered.append((seg, idx + 1))
        if uncovered:  # >=1 -- bias to flag; the reader confirms each against the solve
            out.append({"file": "solution/" + name,
                        "why": f"{len(uncovered)} hardcoded later-hop literal(s) used in a request with NO "
                               f"prior discovery-assertion naming them (a black-box solver cannot learn them): "
                               + ", ".join(f"{s!r}(L{ln})" for s, ln in uncovered[:8]),
                        "label": "[Fail - Unverified Discovery]"})
    return out


_SHORTCUT_PATH_RE = re.compile(
    r"(?:open\(|cat\s+|read_text\(|readlines\(|Path\()\s*[\"'`]?"
    r"(/[\w./-]*(?:seed|fixture|fresh_state|canary|state\.json|service-accounts|"
    r"doli-creds|\.env|secrets?/)[\w./-]*)",
    re.I)
_SHORTCUT_EXEC_RE = re.compile(r"\bdocker\s+(exec|cp)\b", re.I)
_LOCAL_REQUEST_CONTEXT_RE = re.compile(r"https?://|\bcurl\b|\brequests?\.(get|post)\b|\bget\(|\bpost\(", re.I)


def _shortcut_solve(task_dir):
    """TR3 [Fail - Shortcut Solve]: solve.sh/solve.py reaches the secret via a local
    config/seed/env/leftover-copy read, or a `docker exec`/`docker cp` into a sibling
    container's filesystem, instead of the intended (HTTP-facing) technique. A finder-
    level surface check: a line that reads a seed/state/config-shaped LOCAL path and is
    NOT itself an HTTP request line is surfaced for the reader -- it may be legitimate
    (reading the solve script's OWN scratch output), so this is never auto-failed."""
    out = []
    for name in ("solve.sh", "solve.py"):
        p = os.path.join(task_dir, "solution", name)
        if not os.path.exists(p):
            continue
        for i, line in enumerate(_read(p).splitlines(), 1):
            if _LOCAL_REQUEST_CONTEXT_RE.search(line):
                continue  # this line is itself an HTTP call -- not a local shortcut
            m = _SHORTCUT_PATH_RE.search(line)
            if m:
                out.append({"file": "solution/" + name, "line": i, "path": m.group(1),
                            "text": line.strip()[:160],
                            "why": f"reads a seed/config/state-shaped LOCAL path {m.group(1)!r} "
                                   f"directly, not via the target's HTTP surface -- confirm this "
                                   f"is not bypassing the intended vulnerability"})
            elif _SHORTCUT_EXEC_RE.search(line):
                out.append({"file": "solution/" + name, "line": i, "text": line.strip()[:160],
                            "why": "docker exec/cp reaches a sibling container's filesystem "
                                   "directly -- confirm this is not a shortcut around the "
                                   "intended (HTTP-facing) technique"})
    return out


def _tr3(task_dir):
    val, path = _reward(task_dir, "oracle")
    cands = []
    if val is None:
        cands.append({"file": path, "why": "oracle trajectory reward not found (shipped oracle required)"})
    elif val != 1:
        cands.append({"file": path, "why": f"oracle earns reward {val} (must be 1 — solve not wired)"})
    # TR3 [Fail - No Write]: solve.sh must write the submission file (> file or tee file)
    solve = _read(os.path.join(task_dir, "solution", "solve.sh")) + "\n" + _read(os.path.join(task_dir, "solution", "solve.py"))
    if solve.strip() and not (re.search(r">\s*\S+", solve) or re.search(r"\btee\s+\S+", solve)):
        cands.append({"file": "solution/solve.sh", "why": "no submission-file write (`> file`/`tee`) found in solve.sh",
                      "label": "[Fail - No Write]"})
    # TR3 [Fail - Unverified Discovery]: later-hop request literals with no prior discovery-assertion
    cands += _unverified_discovery(task_dir)
    # TR3 [Fail - Shortcut Solve]: a local config/seed/env read or docker exec/cp, surfaced
    # for the reader (never auto-failed -- may be a legitimate own-scratch-file read)
    for s in _shortcut_solve(task_dir):
        s["label"] = "[Fail - Shortcut Solve]"
        cands.append(s)
    return {"label": "[Fail - Oracle Unwired]", "oracle_reward": val, "candidates": cands,
            "files_to_read": ["trajectories/oracle/reward.txt", "trajectories/oracle/test.log", "solution/solve.sh",
                              "trajectories/oracle/agent/trajectory.json", "solution/solve.sh"],
            "note": "reader reads the oracle trajectory to confirm the solve uses the INTENDED path."}


def find(task_dir):
    return {"task_dir": os.path.abspath(task_dir),
            "checks": {"tr2_noop": _tr2(task_dir), "tr3_oracle": _tr3(task_dir)}}


def _summary(r):
    o = [f"TRAJECTORY FINDER (TR2/TR3) — {r['task_dir']}"]
    t2 = r["checks"]["tr2_noop"]; t3 = r["checks"]["tr3_oracle"]
    o.append(f"  TR2 noop reward={t2['noop_reward']}  candidates={len(t2['candidates'])}")
    for c in t2["candidates"]:
        o.append(f"     FAIL?  {c['file']}  — {c['why']}")
    o.append(f"  TR3 oracle reward={t3['oracle_reward']}  candidates={len(t3['candidates'])}")
    for c in t3["candidates"]:
        o.append(f"     FAIL?  {c['file']}  — {c['why']}")
    o.append("  NOTE: rewards are decidable statically; the reader confirms the oracle used the intended path.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: traj_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
