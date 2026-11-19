#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ev2_finder.py  --  static FINDER layer of the EV2 eval
(Evaluation: Intended-Path-Only Credit) -- the keystone credit-integrity worker.

READ-ONLY. It POINTS; the reader traces the chain and decides. The core move is the
field lesson "trace every reward=1 setter to its WEAKEST guard":

  * [Fail - Exploit-Free Credit]: reward=1 is reachable without the intended exploit --
    gated only on submission==marker, or on a leftover secret / an out-of-band env or
    file read / the provided credentials, with NO proof of the intended technique.
  * [Fail - Verifier Contamination]: the grading path invokes the reference solver or
    writes the submission file itself, so the reward follows from the solver, not the
    agent.
  * [Fail - Shortcut Win on Complexity Packet]: a shipped reward=1 trial reached the
    secret off the intended path -- that is a pass@k/trial check (LIVE), noted here.

Bias to flag (false fails > missed fails): any reward=1 whose nearby guard shows a
marker/secret match but NO proof/technique/audit token is a candidate; the reader reads
the full chain and decides. A proof-gated reward is clean.

Usage:  python3 -I ev2_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io

_REWARD1_RE = re.compile(
    r"reward\s*=\s*1\b|[\"']reward[\"']\s*:\s*1\b|echo\s+[\"']?1[\"']?\s*>[^>].*reward"
    r"|printf[^>]*1[^>]*>[^>].*reward", re.I)
_PROOF_RE = re.compile(
    r"proof|technique|audit|intended|validate|credited|chain|observer|exploit|behavior_gate|gate\b", re.I)
_MATCH_RE = re.compile(
    r"submission|==\s*expected|\$\{?sub\b|[\"']\$sub[\"']|==\s*secret|==\s*flag|expected|marker|fullmatch", re.I)
# OOB = reading the SCORED VALUE out-of-band. Require a secret/flag/marker-named read,
# not any os.environ access (grading code legitimately reads env for config/API keys).
_OOB_RE = re.compile(
    r"os\.environ(?:\.get)?\(?\s*[\[(]?\s*[\"']?\w*(secret|flag|marker|scored|answer|expected)\w*"
    r"|getenv\(\s*[\"']?\w*(secret|flag|marker|scored|answer|expected)"
    r"|cat\s+/\S*(secret|flag)|open\(\s*[\"']/\S*(secret|flag)", re.I)
_CONTAM_RE = re.compile(
    r"/solution/|solve\.sh|solve\.py|>\s*\S*submission\.txt", re.I)


def _read(p):
    try:
        with io.open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _test_files(task_dir):
    out = []
    d = os.path.join(task_dir, "tests")
    for dp, _d, fns in os.walk(d):
        for fn in fns:
            if fn.endswith((".sh", ".py")):
                out.append(os.path.relpath(os.path.join(dp, fn), task_dir))
    return sorted(out)


def _reward_setters(task_dir, files):
    setters = []
    for rel in files:
        txt = _read(os.path.join(task_dir, rel))
        if re.search(r"reward\.(json|txt)|reward\s*=\s*[01]\b|[\"']reward[\"']\s*:\s*[01]\b", txt):
            setters.append(rel)
    return setters


def _exploit_free(task_dir, setters):
    cands, files = [], set()
    for rel in setters:
        files.add(rel)
        lines = _read(os.path.join(task_dir, rel)).splitlines()
        for i, line in enumerate(lines, 1):
            # out-of-band read of the scored value anywhere in a reward setter
            if _OOB_RE.search(line):
                cands.append({"file": rel, "line": i, "text": line.strip()[:180],
                              "why": "out-of-band read of the scored value (env/secret file) in the grading path"})
            if _REWARD1_RE.search(line):
                lo = max(0, i - 7)
                window = "\n".join(lines[lo:i])
                if _MATCH_RE.search(window) and not _PROOF_RE.search(window):
                    cands.append({"file": rel, "line": i, "text": line.strip()[:180],
                                  "why": "reward=1 gated on a marker/secret match with no intended-exploit proof nearby"})
    # de-dup by (file,line,why)
    seen, out = set(), []
    for c in cands:
        k = (c["file"], c["line"], c["why"])
        if k not in seen:
            seen.add(k); out.append(c)
    return {"label": "[Fail - Exploit-Free Credit]", "candidates": out,
            "files_to_read": sorted(files | {"tests/test.sh"}),
            "note": "reader traces: can reward=1 be reached WITHOUT the intended exploit "
                    "(leftover secret, out-of-band read, provided creds, submission-only match)?"}


def _contamination(task_dir, files, setters):
    scan = [f for f in files if f == "tests/test.sh" or f.startswith("tests/behavior/")] + setters
    cands, seen = [], set()
    for rel in dict.fromkeys(scan):
        for i, line in enumerate(_read(os.path.join(task_dir, rel)).splitlines(), 1):
            if _CONTAM_RE.search(line):
                k = (rel, i)
                if k in seen:
                    continue
                seen.add(k)
                cands.append({"file": rel, "line": i, "text": line.strip()[:180],
                              "why": "grading path invokes the reference solver or writes the submission file"})
    return {"label": "[Fail - Verifier Contamination]", "candidates": cands,
            "files_to_read": sorted(dict.fromkeys(scan)),
            "note": "reader confirms the reward does not follow from a solver the grader runs, "
                    "and that the agent (not the grader) writes the submission."}


def _shortcut_win(task_dir):
    return {"label": "[Fail - Shortcut Win on Complexity Packet]",
            "live_items": [
                "pass@k: grep every shipped reward=1 trial -- did it reach the secret off the "
                "intended path (a different endpoint/CWE, a shortcut source, or grading tampering)?"],
            "files_to_read": ["trajectories/pass@k/"]}


def find(task_dir):
    files = _test_files(task_dir)
    setters = _reward_setters(task_dir, files)
    return {
        "task_dir": os.path.abspath(task_dir),
        "reward_setters": setters,
        "test_file_count": len(files),
        "checks": {
            "exploit_free_credit": _exploit_free(task_dir, setters),
            "verifier_contamination": _contamination(task_dir, files, setters),
            "shortcut_win": _shortcut_win(task_dir),
        },
    }


def _summary(r):
    o = [f"EV2 FINDER — {r['task_dir']}",
         f"  reward setters: {r['reward_setters']}"]
    ef = r["checks"]["exploit_free_credit"]
    o.append(f"  [Exploit-Free Credit] candidates={len(ef['candidates'])}")
    for c in ef["candidates"][:15]:
        o.append(f"     FAIL?  {c['file']}:{c['line']}  {c['why']}  — {c['text']}")
    vc = r["checks"]["verifier_contamination"]
    o.append(f"  [Verifier Contamination] candidates={len(vc['candidates'])}")
    for c in vc["candidates"][:10]:
        o.append(f"     FAIL?  {c['file']}:{c['line']}  — {c['text']}")
    o.append(f"  [Shortcut Win] LIVE pass@k check (grep shipped reward=1 trials)")
    o.append("  NOTE: finder points. The reader opens the reward setters and traces the credit chain.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: ev2_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
