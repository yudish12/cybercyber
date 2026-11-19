import re
from pathlib import Path

from ..constants import SHORTCUT_PATH_RE
from ..evidence import dir_evidence, oracle_discoverability_gaps, resolve_reward_value, trial_fairness_signals
from ..llm_judge import judge_dimension
from ..report import read, result

ORACLE_RIGOR_INSTRUCTIONS = (
    "Beyond the discovery-assertion check above, also check solve.sh against four further "
    "oracle-rigor requirements, three from skills/qc_task_content/oracle_solution.md plus one "
    "custom extension (not from that doc). Each is independent -- fail on the FIRST one "
    "violated, using the bracketed label given:\n\n"
    "1. CREDENTIAL TRANSPORT SELF-TEST (custom, not from oracle_solution.md) -- if solve.sh "
    "presents a credential (bearer token, API key, session id) to a scored/gating endpoint via "
    "some transport other than exactly how the backend's own access-control code extracts it "
    "(e.g. the backend code also accepts it as a query-string param or JSON/form body field, "
    "not only its Authorization header), solve.sh should prove the grading/credit logic isn't "
    "narrower than that acceptance by re-presenting the SAME credential via at least one such "
    "alternate transport and asserting the response/credit is still granted. A green oracle "
    "that only ever exercises the one transport it happens to use proves that transport works, "
    "not that a solver using a different, equally-valid transport would still get credit. If "
    "the backend genuinely accepts only one transport, this does not apply. If it accepts more "
    "than one and solve.sh never tests an alternate, fail with "
    "'[Fail - Transport Parity Unverified]'.\n\n"
    "2. EXIT-CODE TAXONOMY -- solve.sh (or a die()/fail() helper it defines) should exit 10 "
    "for an INFRA preflight failure (environment not up/reachable) and exit 11 for a failure "
    "of a specific intended-chain stage, with that failing stage's name/id in the message "
    "(e.g. 'S5 registry_token_presented: ...'), matching tests/stages/stages.toml's stage "
    "spine if present. If solve.sh uses a flat/undifferentiated exit code (e.g. always 'exit "
    "1' or 'set -e' with no distinct infra-vs-stage codes, or a stage failure with no stage "
    "name in the message), fail with '[Fail - No Exit-Code Taxonomy]'. If stages.toml is "
    "absent or solve.sh has no stage-oriented structure at all, this requirement does not "
    "apply -- do not fail on it.\n\n"
    "3. SIBLING/DECOY ACTIVELY PROBED -- if the intended chain has a sibling or decoy endpoint "
    "that exists specifically to prove isolation (a membership-gated twin of the real sink, a "
    "raw-value probe against a later service before the real exchange), solve.sh itself should "
    "actually send a request to it and log what happened (refused/disclosed/inconclusive), not "
    "just skip straight to the real path because the author already knows it works. If such a "
    "sibling exists in the environment (per VU2 evidence or the app's own routes) but solve.sh "
    "never requests it, fail with '[Fail - Sibling Not Probed]'. If no such sibling/decoy is "
    "part of the intended chain at all, this does not apply.\n\n"
    "4. RESPONSE ACTUALLY PARSED -- at each key step, solve.sh should check the real response "
    "body or a specific field/status (e.g. grep/jq against the fetched content for an expected "
    "value), not just infer success from a non-erroring exit code or curl's own status alone. "
    "If a key step (recovering the secret, confirming a mass-assignment/privilege change took "
    "effect, etc.) only checks '$?' / absence of a curl error with no inspection of what the "
    "response actually contains, fail with '[Fail - Response Not Validated]'.\n\n"
    "If none of these four apply or all are satisfied, evaluate the dimension normally against "
    "its own two rubric options."
)


def check_tr2(task_dir: Path):
    val = resolve_reward_value(task_dir / "trajectories" / "noop")
    if val is None:
        return result("TR2", "Noop Earns Nothing", "FAIL", "[Fail - No-Op Succeeds]", ["trajectories/noop/reward.txt missing"])
    if val not in ("0", "0.0"):
        return result("TR2", "Noop Earns Nothing", "FAIL", "[Fail - No-Op Succeeds]", [f"reward = {val!r}, expected 0"])
    return result("TR2", "Noop Earns Nothing", "PASS", "fresh noop run scores reward 0")


def check_tr3(task_dir: Path):
    solve_text = read(task_dir / "solution" / "solve.sh")
    write_m = re.search(r">\s*([^\s>]+)\s*$", solve_text, re.MULTILINE) or re.search(r"tee\s+([^\s]+)", solve_text)
    if not write_m:
        return result("TR3", "Solve Is Wired and Intended", "FAIL", "[Fail - No Write]",
                       ["no obvious submission-file write found in solve.sh"])

    gaps = oracle_discoverability_gaps(task_dir)
    for rel_path, uncovered, has_any_assertion in gaps:
        if not has_any_assertion and len(uncovered) >= 2:
            detail = ", ".join(f"{seg!r} (line {ln})" for seg, ln in uncovered[:8])
            return result(
                "TR3", "Solve Is Wired and Intended", "FAIL", "[Fail - Unverified Discovery]",
                [
                    f"{rel_path} submits {len(uncovered)} later-hop value(s) with NO "
                    f"discovery-assertion anywhere in the file: {detail}",
                    "For every hardcoded hostname/route/param beyond the first request that a "
                    "black-box solver would have to discover (not merely reuse from an earlier "
                    "response), add an explicit assertion that its breadcrumb text is present in "
                    "a response this same script already fetched, placed before the line that "
                    "uses the hardcoded value -- e.g. grep -q \"<breadcrumb>\" <<< "
                    "\"$EARLIER_RESPONSE\" || fail \"breadcrumb for <X> missing -- a black-box "
                    "solver has no way to learn this\". A green oracle that never checks this "
                    "proves the values work, not that a solver without the script could ever "
                    "find them.",
                ]
            )

    evidence = {
        "solution/solve.sh": solve_text,
        "tests/test.sh": read(task_dir / "tests" / "test.sh"),
    }
    solve_py = task_dir / "solution" / "solve.py"
    if solve_py.exists():
        evidence["solution/solve.py"] = read(solve_py)
    stages_toml = task_dir / "tests" / "stages" / "stages.toml"
    if stages_toml.exists():
        evidence["tests/stages/stages.toml"] = read(stages_toml)
    evidence.update(dir_evidence(task_dir, "tests/behavior"))
    suspicious = SHORTCUT_PATH_RE.search(solve_text)
    if suspicious:
        evidence["suspicious_pattern_matched"] = suspicious.group(0)
    evidence["oracle_rigor_instructions"] = ORACLE_RIGOR_INSTRUCTIONS
    if gaps:
        evidence["oracle_discoverability_gaps (later-hop literals with no discovery-assertion found before their use -- confirm each is either recovered from an earlier response in this run, or has its own grep-q/assert/fail check proving its breadcrumb was disclosed before this line uses it)"] = "\n".join(
            f"{rel_path}: " + ", ".join(f"{seg!r} (line {ln})" for seg, ln in uncovered[:8])
            for rel_path, uncovered, _ in gaps
        )
    return judge_dimension("TR3", evidence)


def check_tr4(task_dir: Path):
    """Not a V11 rubric dimension -- a custom extension surfacing whether each pass@k
    trial was a fair, complete attempt (not barely attempted, no refusal, no
    scaffold-error loop), independent of whether the verifier/reward itself is valid
    (EV5's job) and independent of whether the agent finished -- running out of the turn
    budget mid-task on a genuinely hard task is a valid failure, not an unfairness signal.
    """
    passk_dir = task_dir / "trajectories" / "pass@k"
    if not passk_dir.exists():
        return result("TR4", "Fair Trial Signals", "FAIL", "[Fail - No Trials]", ["trajectories/pass@k/ missing"])

    trials = sorted(t for t in passk_dir.glob("*/*") if t.is_dir())
    if not trials:
        return result("TR4", "Fair Trial Signals", "FAIL", "[Fail - No Trials]", ["no trial directories found"])

    unfair = {}
    fair_count = 0
    for t in trials:
        signals = trial_fairness_signals(t)
        if signals["fair"] is False:
            unfair[t.name] = signals["issue"]
        elif signals["fair"] is True:
            fair_count += 1

    if unfair:
        detail = [f"{name}: {issue}" for name, issue in unfair.items()]
        return result(
            "TR4", "Fair Trial Signals", "FAIL", "[Fail - Unfair Trial]",
            [f"{len(unfair)}/{len(trials)} trial(s) show signs of an unfair/incomplete run -- not a genuine "
             "measurement of model skill on this task:"] + detail,
        )

    return result(
        "TR4", "Fair Trial Signals", "PASS",
        f"all {fair_count}/{len(trials)} trials show a normal, complete attempt "
        "(explicit completion, no refusal, no scaffold-error loops)",
    )


CHECKS = [check_tr2, check_tr3, check_tr4]
