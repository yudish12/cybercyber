#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
trial_finder.py  --  static FINDER for the pass@k TRIAL group (EV6, TR4).

Custom dimensions the official cyber_quality_check adds (not official V11 rows), ported from
its trial_behavior_status / trial_fairness_signals:

  EV6 Technique Fidelity  [Fail - Technique Mismatch]: a solved+valid trial whose touched paths
      never reach the intended vulnerable endpoints (the solve's own endpoints) — it "solved"
      off the intended mechanism.
  TR4 Fair Trial          [Fail - Unfair Trial]: a valid trial that did not get a fair shot —
      no/too-few agent steps, a refusal, or the same tool output repeated in a loop
      (scaffold/tooling malfunction).

Both read trajectories/pass@k/trials/*. If no pass@k is shipped, both are DEFERRED (pre-pass@k).

Usage:  python3 -I trial_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io

_VERIFIER_CRASH_RE = re.compile(
    r"Traceback \(most recent call last\)|OOMKilled|\bKilled\b|exec failed|Segmentation fault|"
    r"MemoryError|No space left|Connection refused|Cannot connect|infra_error|ERROR_INFRA|"
    r"docker:? .*(error|failed)|container .*(died|exited)", re.I)
_SIBLING_CRASH_RE = re.compile(
    r"report.?rubric|ANTHROPIC_BASE_URL|refusing to grade report|judge_error|rubric-?selftest|"
    r"litellm|model_prices|cost.?map|raw\.githubusercontent", re.I)
_REFUSAL_RE = re.compile(
    r"\b(i cannot assist|i can'?t help|i won'?t provide|unable to comply|i must decline|"
    r"against (my|the) (guidelines|policy)|i'?m not able to help|i cannot help with)\b", re.I)
_PATH_SEG_RE = re.compile(r"/([A-Za-z0-9_][A-Za-z0-9_\-.]{2,})")
_MIN_AGENT_STEPS = 5
_MAX_REPEATED_OBSERVATION = 5
_NOISE = {"logs", "verifier", "tmp", "api", "dev", "etc", "work", "opt", "bin", "var", "www",
          "bash", "null", "usr", "home", "index", "json", "title", "password", "txt", "log",
          "service-accounts", "credentials", "cookie", "health"}


def _read(p):
    try:
        return io.open(p, "r", encoding="utf-8", errors="replace").read()
    except Exception:
        return ""


def _trial_dirs(task_dir):
    base = os.path.join(task_dir, "trajectories", "pass@k", "trials")
    if not os.path.isdir(base):
        base = os.path.join(task_dir, "trajectories", "pass@k")
    if not os.path.isdir(base):
        return []
    return sorted(os.path.join(base, d) for d in os.listdir(base) if os.path.isdir(os.path.join(base, d)))


def _status(trial_dir):
    rp = os.path.join(trial_dir, "verifier", "reward.json")
    if not os.path.exists(rp):
        return {"solved": None, "valid": False, "reason": "no verifier/reward.json"}
    try:
        reward = json.loads(_read(rp)).get("reward")
    except Exception:
        reward = None
    if reward is None:
        return {"solved": None, "valid": False, "reason": "reward.json has no reward"}
    stdout = _read(os.path.join(trial_dir, "verifier", "test-stdout.txt")) or _read(os.path.join(trial_dir, "verifier", "test.log"))
    crash_lines = [l for l in stdout.splitlines() if _VERIFIER_CRASH_RE.search(l)] if stdout else []
    if crash_lines:
        # exculpate a crash confined to a NON-gating sibling sub-reward (report-rubric judge,
        # ANTHROPIC_BASE_URL, LiteLLM cost-map fetch) -- it does not invalidate a genuine non-solve
        nongating = any(not _SIBLING_CRASH_RE.search(l) for l in crash_lines)
        if nongating:
            return {"solved": None, "valid": False, "reason": "verifier output shows an infra crash in the gating path"}
    return {"solved": reward >= 1.0, "valid": True, "reason": None}


def _fairness(trial_dir):
    tp = os.path.join(trial_dir, "agent", "trajectory.json")
    if not os.path.exists(tp):
        return {"fair": None, "issue": "no agent/trajectory.json", "step_count": 0}
    try:
        data = json.loads(_read(tp))
    except Exception as e:
        return {"fair": None, "issue": f"trajectory.json unparsable: {e}", "step_count": 0}
    agent_steps = [s for s in (data.get("steps") or []) if s.get("source") == "agent"]
    n = len(agent_steps)
    if n == 0:
        return {"fair": False, "issue": "no agent steps recorded", "step_count": 0}
    if n < _MIN_AGENT_STEPS:
        return {"fair": False, "issue": f"only {n} agent step(s) -- barely attempted", "step_count": n}
    for s in agent_steps:
        txt = (s.get("message") or "") + " " + (s.get("reasoning_content") or "")
        if _REFUSAL_RE.search(txt):
            return {"fair": False, "issue": f"refusal language at step {s.get('step_id')}", "step_count": n}
    obs = []
    for s in agent_steps:
        for r in (s.get("observation") or {}).get("results") or []:
            obs.append((r.get("content") or "")[:200])
    run = mx = 1
    for i in range(1, len(obs)):
        run = run + 1 if obs[i] and obs[i] == obs[i - 1] else 1
        mx = max(mx, run)
    if mx >= _MAX_REPEATED_OBSERVATION:
        return {"fair": False, "issue": f"same tool output repeated {mx} times in a row -- possible scaffold/tooling malfunction", "step_count": n}
    return {"fair": True, "issue": None, "step_count": n}


def _touched_segments(trial_dir):
    txt = _read(os.path.join(trial_dir, "agent", "trajectory.json")) + "\n" + _read(os.path.join(trial_dir, "agent", "terminus_2.pane"))
    segs = set()
    for m in _PATH_SEG_RE.finditer(txt):
        s = m.group(1)
        if len(s) >= 3 and not s.isdigit() and s.lower() not in _NOISE:
            segs.add(s)
    return segs


def _intended_segments(task_dir):
    solve = _read(os.path.join(task_dir, "solution", "solve.sh")) + "\n" + _read(os.path.join(task_dir, "solution", "solve.py"))
    segs = set()
    for ln in solve.splitlines():
        if not re.search(r"https?://|\$\{?BASE\}?|\bcurl\b|post_json|get_json|\bwget\b", ln):
            continue
        for m in re.finditer(r"(?:\$\{?BASE\}?|https?://[^/\s\"']+)(/[A-Za-z0-9_\-/.]+)", ln):
            for seg in m.group(1).strip("/").split("/"):
                if len(seg) >= 3 and not seg.isdigit() and seg.lower() not in _NOISE:
                    segs.add(seg)
        # query-param endpoints (Joomla index.php?option=com_content&view=category&task=...)
        for qm in re.finditer(r"(?:option|view|task|layout)=([A-Za-z0-9_.]+)", ln):
            if qm.group(1).lower() not in _NOISE:
                segs.add(qm.group(1))
    return segs


def find(task_dir):
    trials = _trial_dirs(task_dir)
    if not trials:
        return {"task_dir": os.path.abspath(task_dir),
                "checks": {"ev6_technique_fidelity": {"label": "[Fail - Technique Mismatch]", "status": "DEFERRED",
                                                      "candidates": [], "note": "no pass@k shipped — EV6 DEFERRED (pre-pass@k)"},
                           # TR4 fails CLOSED on missing trials (official: [Fail - No Trials])
                           "tr4_fair_trial": {"label": "[Fail - No Trials]", "status": "POST-PASS@K",
                                              "candidates": [{"trial": "-", "issue": "trajectories/pass@k/ missing or no trial directories — [Fail - No Trials]"}],
                                              "note": "no pass@k trials -> TR4 FAIL (not deferred)"}}}
    intended = _intended_segments(task_dir)
    ev6, tr4, rows = [], [], []
    for td in trials:
        name = os.path.basename(td)
        st = _status(td)
        fr = _fairness(td)
        reached, missing = [], []
        if st["solved"] and st["valid"]:
            touched = _touched_segments(td)
            reached = sorted(intended & touched)
            missing = sorted(intended - touched)
            if intended and not reached:
                ev6.append({"trial": name, "reached": reached, "missing_intended": missing[:12],
                            "why": "solved+valid trial whose touched paths reach NONE of the intended endpoints -- possible technique mismatch/shortcut"})
        if st["valid"] and fr.get("fair") is False:
            tr4.append({"trial": name, "issue": fr["issue"], "step_count": fr["step_count"]})
        rows.append({"trial": name, **st, "fair": fr.get("fair"), "fair_issue": fr.get("issue")})
    return {"task_dir": os.path.abspath(task_dir),
            "trial_count": len(trials), "intended_segments": sorted(intended), "trials": rows,
            "checks": {
                "ev6_technique_fidelity": {"label": "[Fail - Technique Mismatch]", "status": "POST-PASS@K",
                    "candidates": ev6, "files_to_read": ["trajectories/pass@k/", "solution/solve.sh"],
                    "note": "reader confirms each: does the solved trial's trajectory actually exercise the intended "
                            "mechanism? (path extraction can miss POST-only endpoints -- read the trajectory)."},
                "tr4_fair_trial": {"label": "[Fail - Unfair Trial]", "status": "POST-PASS@K",
                    "candidates": tr4, "files_to_read": ["trajectories/pass@k/"],
                    "note": "reader confirms the trial was genuinely unfair (scaffold malfunction/refusal), not real difficulty."}}}


def _summary(r):
    o = [f"TRIAL FINDER (EV6/TR4) — {r['task_dir']}"]
    if r["checks"]["ev6_technique_fidelity"].get("status") == "DEFERRED":
        o.append("  no pass@k shipped -> EV6 + TR4 DEFERRED")
        return "\n".join(o)
    o.append(f"  trials={r['trial_count']}  intended segments={r['intended_segments'][:10]}")
    for t in r["trials"]:
        o.append(f"    {t['trial']:16} solved={t['solved']} valid={t['valid']} fair={t['fair']} {t.get('fair_issue') or ''}")
    e6 = r["checks"]["ev6_technique_fidelity"]["candidates"]
    o.append(f"  EV6 [Technique Mismatch] candidates={len(e6)}")
    for c in e6:
        o.append(f"     FAIL?  {c['trial']}  reached={c['reached']}  missing={c['missing_intended'][:6]}")
    t4 = r["checks"]["tr4_fair_trial"]["candidates"]
    o.append(f"  TR4 [Unfair Trial] candidates={len(t4)}")
    for c in t4:
        o.append(f"     FAIL?  {c['trial']}  {c['issue']}")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: trial_finder.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    r = find(argv[0])
    if "--json" in argv:
        json.dump(r, open(argv[argv.index("--json") + 1], "w"), indent=2)
    print(_summary(r)); return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
