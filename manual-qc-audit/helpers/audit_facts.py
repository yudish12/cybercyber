#!/usr/bin/env python3
"""audit_facts.py <task_root> — deterministic facts for a manual V10 QC audit.

FACTS ONLY. This scores NOTHING. It gathers the few things that are tedious to do by eye across many
files — per-trial behavior values, the recorded tier, mtime freshness, and a danger-sweep index — so the
auditor can then OPEN every flagged file and the decision-relevant files and score each dimension by hand.

Usage:  python3 audit_facts.py /path/to/task        (the dir containing task.toml)
Run with -I on untrusted bundles:  python3 -I audit_facts.py /path/to/task
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: audit_facts.py <task_root>")
    root = Path(sys.argv[1]).resolve()
    if not (root / "task.toml").exists():
        sys.exit(f"ERROR: {root}/task.toml not found — pass the inner task/ dir")

    print(f"# audit_facts for {root}\n")

    # ---- identity (facts; still read task.toml yourself) ----
    toml = (root / "task.toml").read_text(errors="replace")
    def grab(k):
        m = re.search(rf'^{k}\s*=\s*"([^"]*)"', toml, re.M)
        return m.group(1) if m else "(not found)"
    print("## identity")
    for k in ("name", "cwe", "vulnerability_kind", "version"):
        print(f"  {k}: {grab(k)}")

    # ---- EV5: per-trial behavior gate + panel + tier ----
    print("\n## EV5 — per-trial BEHAVIOR gate (verifier/reward.json; NOT reward.txt, NOT staged)")
    pk_root = root / "trajectories" / "pass@k"
    jobs = sorted([p for p in pk_root.glob("task-*") if p.is_dir()]) if pk_root.exists() else []
    if not jobs:
        print("  (no pass@k job dir found)")
    for job in jobs:
        print(f"  job: {job.name}")
        # tier from run.log (one level up, or in job)
        tier = "(not recorded)"
        for logp in (job.parent / "run.log", job / "run.log"):
            if logp.exists():
                m = re.search(r"Using tier (L\d+)", logp.read_text(errors="replace"))
                if m:
                    tier = m.group(1)
                break
        print(f"    recorded tier: {tier}")
        # result.json panel stats
        rj = job / "result.json"
        if rj.exists():
            try:
                st = json.loads(rj.read_text())["stats"]
                ev = list(st.get("evals", {}).values())
                if ev:
                    e = ev[0]
                    print(f"    model: {list(st['evals'].keys())[0]}")
                    print(f"    n_trials: {e.get('n_trials')}  n_errors: {e.get('n_errors')}  mean: {e['metrics'][0]['mean'] if e.get('metrics') else '?'}")
            except Exception as ex:
                print(f"    (result.json parse error: {ex})")
        # per-trial behavior
        solves = nonsolves = 0
        for trial in sorted(job.glob("*deepseek*")):
            if not trial.is_dir():
                continue
            rpath = trial / "verifier" / "reward.json"
            bv = "?"
            if rpath.exists():
                try:
                    bv = json.loads(rpath.read_text()).get("reward")
                except Exception:
                    bv = "(parse error)"
            if bv == 1.0:
                solves += 1
            elif bv == 0.0:
                nonsolves += 1
            # staged score + per-stage for context (diagnostic only)
            sd = trial / "verifier" / "stages" / "reward-details.json"
            stginfo = ""
            if sd.exists():
                try:
                    crit = json.loads(sd.read_text())["reward"]["criteria"]
                    fired = [c["name"].split("_")[0] for c in crit if c.get("value") == 1.0]
                    stginfo = f"  staged[{','.join(fired)}]"
                except Exception:
                    pass
            print(f"    {trial.name}: behavior={bv}{stginfo}")
        total = solves + nonsolves
        if total:
            print(f"    -> behavior solve rate: {solves}/{total}"
                  f"  ({'PASS <100%' if solves < total else 'FAIL: 5/5 too easy'});"
                  f" genuine-non-solve candidates to VERIFY by reading the trajectory: {nonsolves}")
        print("    NOTE: open each non-solve's agent/terminus_2.pane + result.json and prove it is genuine")
        print("          (0 refusals, exception_info=null, real HTTP responses) — never trust a 'REFUSAL' label.")

    # ---- freshness: graded source vs pass@k artifacts (mtime) ----
    print("\n## EVIDENCE FRESHNESS — graded source vs pass@k artifacts (mtime)")
    graded = []
    for pat in ("environment/**/app.py", "environment/**/setup.py", "tests/**/*.sh", "tests/**/*.py",
                "tests/**/*.toml", "task.toml", "instruction*.md"):
        graded += list(root.glob(pat))
    art = []
    for job in jobs:
        art += list(job.glob("**/trajectory.json")) + list(job.glob("**/verifier/reward.json"))
        if (job / "run.log").exists():
            art.append(job / "run.log")
        elif (job.parent / "run.log").exists():
            art.append(job.parent / "run.log")
    art_mtime = max((p.stat().st_mtime for p in art), default=0)
    if art_mtime:
        import datetime
        def ts(t): return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  newest pass@k artifact mtime: {ts(art_mtime)}")
        newer = [(p, p.stat().st_mtime) for p in graded if p.stat().st_mtime > art_mtime]
        if newer:
            print("  !! GRADED SOURCE NEWER THAN THE PASS@K EVIDENCE (stale → recommend a re-run):")
            for p, m in sorted(newer, key=lambda x: -x[1]):
                print(f"     {ts(m)}  {p.relative_to(root)}")
        else:
            print("  ok: no graded-source file is newer than the pass@k artifacts")
    else:
        print("  (no pass@k artifacts to compare)")

    # ---- danger-sweep index: OPEN every file that hits ----
    print("\n## DANGER SWEEP — open every file that hits (grounds VU2 / VU5 / EV2 / F5 / VU1)")
    api = next((p for p in root.glob("environment/**/app/api") if p.is_dir()), None)
    lib = next((p for p in root.glob("environment/**/lib") if p.is_dir()), None)
    targets = [d for d in (api, lib) if d]
    patterns = {
        "body-spread (2nd mass-assignment?)": r"\.\.\.\(?(body|req|await|result)",
        "secret/seed/token disclosure": r"/seed/|concierge|conciergeAccessToken|CONCIERGE|[^a-z]marker|MARKER",
        "file read w/ possible user path": r"readFile|readFileSync|createReadStream|sendFile",
        "code exec / raw sql": r"eval\(|child_process|[^a-z]exec\(|sql\.raw|\.raw\(",
    }
    for label, pat in patterns.items():
        print(f"  [{label}]")
        hits = 0
        for d in targets:
            try:
                out = subprocess.run(["grep", "-rnE", "--include=*.ts", "--include=*.js", pat, str(d)],
                                     capture_output=True, text=True, timeout=60).stdout
            except Exception:
                out = ""
            for line in out.splitlines():
                if ".test.ts:" in line:   # test fixtures are not served routes
                    continue
                hits += 1
                print("    " + line.replace(str(root) + "/", ""))
        if not hits:
            print("    (none)")
    print("\n  Reminder: exactly ONE body-spread should exist (the intended sink). Secret/seed access should")
    print("  be the single intended disclosure route. File reads must use hardcoded paths. Any other hit is a finding.")

if __name__ == "__main__":
    main()
