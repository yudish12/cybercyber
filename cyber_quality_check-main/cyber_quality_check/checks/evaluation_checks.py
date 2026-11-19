import json
from pathlib import Path

from ..evidence import trial_behavior_status, trial_fairness_signals
from ..report import read, result


def check_ev5(task_dir: Path):
    passk_dir = task_dir / "trajectories" / "pass@k"
    if not passk_dir.exists():
        return result("EV5", "Pass@5 Difficulty Gate", "FAIL", "[Fail - Incorrect or Incomplete Panel]", ["trajectories/pass@k/ missing"])

    trials = sorted(t for t in passk_dir.glob("*/*") if t.is_dir())
    if len(trials) != 5:
        return result("EV5", "Pass@5 Difficulty Gate", "FAIL", "[Fail - Incorrect or Incomplete Panel]",
                       [f"found {len(trials)} trial directories, expected 5"])

    models = set()
    non_errored = []
    rewards = {}
    excluded = {}
    for t in trials:
        cfg_path = t / "config.json"
        if cfg_path.exists():
            try:
                models.add(json.loads(read(cfg_path)).get("agent", {}).get("model_name", ""))
            except Exception:
                pass
        status = trial_behavior_status(t)
        if not status["valid"]:
            excluded[t.name] = status["reason"]
            continue
        fairness = trial_fairness_signals(t)
        if fairness["fair"] is False:
            excluded[t.name] = f"unfair trial: {fairness['issue']}"
            continue
        non_errored.append(t)
        rewards[t.name] = 1.0 if status["solved"] else 0.0

    if not models or not any("deepseek" in m.lower() for m in models):
        return result("EV5", "Pass@5 Difficulty Gate", "FAIL", "[Fail - Incorrect or Incomplete Panel]",
                       [f"agent model(s) found: {sorted(models)}, expected deepseek"])

    if len(non_errored) < 3:
        evidence = [f"only {len(non_errored)} trials ran without erroring out (need >=3)",
                    f"rewards found: {rewards}"]
        if excluded:
            evidence.append(f"excluded trials: {excluded}")
        return result("EV5", "Pass@5 Difficulty Gate", "FAIL", "[Fail - Difficulty Too Low]", evidence)

    solved = sum(1 for r in rewards.values() if r >= 1.0)
    if solved == len(non_errored):
        return result("EV5", "Pass@5 Difficulty Gate", "FAIL", "[Fail - Difficulty Too Low]",
                       [f"model solved the behavior gate on all {solved}/{len(non_errored)} non-errored trials (no genuine non-solve)",
                        f"rewards: {rewards}"])

    run_log = read(passk_dir / "run.log")
    if "tier" not in run_log.lower():
        return result("EV5", "Pass@5 Difficulty Gate", "FAIL", "[Fail - Tier Not Recorded]",
                       ["trajectories/pass@k/run.log does not record an instruction tier"])

    return result("EV5", "Pass@5 Difficulty Gate", "PASS",
                   f"deepseek, 5 attempts, {len(non_errored)} non-errored trials, {solved} solved, rate below 100%, tier recorded",
                   [f"rewards: {rewards}"])


CHECKS = [check_ev5]
