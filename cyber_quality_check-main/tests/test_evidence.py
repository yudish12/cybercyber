import json
import zipfile

from cyber_quality_check.evidence import (
    compose_environment_value_leak_evidence, dockerfile_package_notice_crosscheck,
    grep_comments, passk_discovery_audit, report_rubric_criterion_name_violations,
    resolve_reward_value, seed_credential_reuse_files, seed_data_leak_term_files,
    service_filesystem_map, trial_behavior_status, unisolated_python_invocations,
    wheel_license_summary,
)


def test_resolve_reward_value_falls_back_to_json_on_sentinel_text(tmp_path):
    reward_dir = tmp_path / "oracle"
    reward_dir.mkdir()
    (reward_dir / "reward.txt").write_text(
        "HARBOR_SCHEMA_ERROR: no reward.json or reward.txt found in /logs/verifier/\n"
    )
    (reward_dir / "reward.json").write_text('{"reward":1}')
    assert resolve_reward_value(reward_dir) == "1"


def test_resolve_reward_value_prefers_numeric_txt(tmp_path):
    reward_dir = tmp_path / "oracle"
    reward_dir.mkdir()
    (reward_dir / "reward.txt").write_text("1.0")
    assert resolve_reward_value(reward_dir) == "1.0"


def test_resolve_reward_value_none_when_txt_missing(tmp_path):
    reward_dir = tmp_path / "oracle"
    reward_dir.mkdir()
    assert resolve_reward_value(reward_dir) is None


def test_resolve_reward_value_falls_back_to_test_log_reward_line(tmp_path):
    reward_dir = tmp_path / "oracle"
    reward_dir.mkdir()
    (reward_dir / "reward.txt").write_text(
        "HARBOR_SCHEMA_ERROR: no reward.json or reward.txt found in /logs/verifier/\n"
    )
    (reward_dir / "test.log").write_text(
        "reward: 1.0\nverdict: behavior_reward=1 report_status=skipped\nverdict: accepted behavior proof\n"
    )
    assert resolve_reward_value(reward_dir) == "1.0"


def test_resolve_reward_value_falls_back_to_test_log_behavior_reward(tmp_path):
    reward_dir = tmp_path / "noop"
    reward_dir.mkdir()
    (reward_dir / "reward.txt").write_text(
        "HARBOR_SCHEMA_ERROR: no reward.json or reward.txt found in /logs/verifier/\n"
    )
    (reward_dir / "test.log").write_text("diagnostic stages=1.0\nbehavior reward=0: rejected\n")
    assert resolve_reward_value(reward_dir) == "0"


def test_seed_credential_reuse_files_flags_shared_hash(tmp_path):
    env = tmp_path / "environment" / "data-pack"
    env.mkdir(parents=True)
    (env / "seed.json").write_text(json.dumps({
        "users": [
            {"username": "lead_morgan", "password_hash": "$2b$12$sameHashSameHashSameHash"},
            {"username": "sec_lead", "password_hash": "$2b$12$sameHashSameHashSameHash"},
            {"username": "guest", "password_hash": "$2b$12$differentHashDifferentHash"},
        ],
    }))
    hits = seed_credential_reuse_files(tmp_path)
    assert str((env / "seed.json").relative_to(tmp_path)) in hits


def test_seed_credential_reuse_files_no_hit_when_all_unique(tmp_path):
    env = tmp_path / "environment" / "data-pack"
    env.mkdir(parents=True)
    (env / "seed.json").write_text(json.dumps({
        "users": [
            {"username": "a", "password_hash": "$2b$12$hashOneHashOneHashOne"},
            {"username": "b", "password_hash": "$2b$12$hashTwoHashTwoHashTwo"},
        ],
    }))
    assert seed_credential_reuse_files(tmp_path) == {}


def test_seed_credential_reuse_files_generalizes_to_sql_and_env_formats(tmp_path):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "seed.sql").write_text(
        "UPDATE users SET pwd_hash = '$argon2id$v=19$samehashsamehash' WHERE username='alice';\n"
        "UPDATE users SET pwd_hash = '$argon2id$v=19$samehashsamehash' WHERE username='bob';\n"
    )
    (env / "demo.env").write_text("DEMO_PASSWORD=supersecretvalue\nFALLBACK_PASSWORD=supersecretvalue\n")
    hits = seed_credential_reuse_files(tmp_path)
    assert str((env / "seed.sql").relative_to(tmp_path)) in hits
    assert str((env / "demo.env").relative_to(tmp_path)) in hits


def test_compose_environment_value_leak_evidence_surfaces_raw_values(tmp_path):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "docker-compose.yaml").write_text(
        "services:\n  main:\n    environment:\n      TARGET_HOST: internal-victim.local\n"
    )
    out = compose_environment_value_leak_evidence(tmp_path)
    assert "internal-victim.local" in out


def test_seed_data_leak_term_files_flags_vuln_class_in_content(tmp_path):
    env = tmp_path / "environment" / "seed"
    env.mkdir(parents=True)
    (env / "support_messages.json").write_text(
        '{"messages": [{"text": "heads up, the admin endpoint is vulnerable to SSRF"}]}'
    )
    hits = seed_data_leak_term_files(tmp_path)
    assert str((env / "support_messages.json").relative_to(tmp_path)) in hits


def test_seed_data_leak_term_files_ignores_notice_md(tmp_path):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "NOTICE.md").write_text("License: MIT. This fixes a known SSRF issue upstream.")
    assert seed_data_leak_term_files(tmp_path) == {}


def test_dockerfile_package_notice_crosscheck_flags_unlisted_pip_package(tmp_path):
    env = tmp_path / "environment" / "gateway"
    env.mkdir(parents=True)
    (env / "Dockerfile").write_text(
        "FROM python:3.11-slim\nRUN pip install --no-cache-dir requests==2.34.2 flask==3.0.0\n"
    )
    (tmp_path / "environment" / "NOTICE.md").write_text("License: MIT. Uses flask for the web layer.")
    hits = dockerfile_package_notice_crosscheck(tmp_path)
    assert hits == {"environment/gateway/Dockerfile": ["requests"]}


def test_dockerfile_package_notice_crosscheck_skips_agent_dockerfile(tmp_path):
    env = tmp_path / "environment" / "agent"
    env.mkdir(parents=True)
    (env / "Dockerfile").write_text("FROM python:3.11-slim\nRUN pip install harbor-rewardkit==0.1.7\n")
    (tmp_path / "environment" / "NOTICE.md").write_text("License: MIT.")
    assert dockerfile_package_notice_crosscheck(tmp_path) == {}


def test_dockerfile_package_notice_crosscheck_ignores_common_apt_utilities(tmp_path):
    env = tmp_path / "environment" / "gateway"
    env.mkdir(parents=True)
    (env / "Dockerfile").write_text(
        "FROM python:3.11-slim\nRUN apt-get install -y curl ca-certificates jq\n"
    )
    (tmp_path / "environment" / "NOTICE.md").write_text("License: MIT.")
    assert dockerfile_package_notice_crosscheck(tmp_path) == {}


def test_report_rubric_criterion_name_violations_flags_over_64_chars(tmp_path):
    report_dir = tmp_path / "tests" / "report"
    report_dir.mkdir(parents=True)
    (report_dir / "rubric.toml").write_text(
        '[[criterion]]\nname = "' + "x" * 65 + '"\ndescription = "x"\n\n'
        '[[criterion]]\nname = "short_name"\ndescription = "x"\n'
    )
    violations = report_rubric_criterion_name_violations(tmp_path)
    assert len(violations) == 1
    assert "65 chars" in violations[0]


def test_report_rubric_criterion_name_violations_none_when_missing_file(tmp_path):
    assert report_rubric_criterion_name_violations(tmp_path) == []


def test_unisolated_python_invocations_flags_missing_dash_i(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test.sh").write_text("#!/bin/bash\npython3 -c 'import json' > out.txt\n")
    hits = unisolated_python_invocations(tmp_path)
    assert any("python3 -c" in h for h in hits)


def test_unisolated_python_invocations_ignores_isolated_calls(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test.sh").write_text("#!/bin/bash\npython3 -I -c 'import json' > out.txt\n")
    assert unisolated_python_invocations(tmp_path) == []


def test_grep_comments_filters_license_boilerplate(tmp_path):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "app.php").write_text(
        "<?php\n"
        "/*\n"
        " * Copyright (C) 2004 Someone <x@y.com>\n"
        " * This program is distributed in the hope that it will be useful,\n"
        " * without any warranty\n"
        " */\n"
        "// We refuse directory transversal change and pipes in file names\n"
    )
    out = grep_comments(tmp_path)
    assert "transversal" in out.lower()
    assert "copyright" not in out.lower()
    assert "without any warranty" not in out.lower()


def test_service_filesystem_map_excludes_whl_noise(tmp_path):
    env = tmp_path / "environment" / "agent"
    env.mkdir(parents=True)
    (env / "Dockerfile").write_text("FROM python:3.12-slim")
    wheels = env / "vendor-wheels"
    wheels.mkdir()
    (wheels / "somepkg-1.0-py3-none-any.whl").write_bytes(b"")
    services = {"main": {"build": {"context": "./agent"}}}
    out = service_filesystem_map(tmp_path, services)
    assert "Dockerfile" in out
    assert ".whl" not in out


def test_service_filesystem_map_notes_separate_filesystems(tmp_path):
    env = tmp_path / "environment"
    (env / "appserver").mkdir(parents=True)
    (env / "appserver" / "Dockerfile").write_text("FROM php:8.1")
    (env / "gateway").mkdir(parents=True)
    (env / "gateway" / "app.py").write_text("")
    services = {
        "appserver": {"build": {"context": "./appserver"}},
        "web": {"build": {"context": "./gateway"}},
    }
    out = service_filesystem_map(tmp_path, services)
    assert "separate container filesystem" in out
    assert "cannot read files belonging to" in out


def _make_wheel(path, name, version, license_line):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(
            f"{name}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n{license_line}\n",
        )


def test_wheel_license_summary_extracts_real_license(tmp_path):
    whl = tmp_path / "environment" / "agent" / "vendor-wheels" / "certifi-2026.7.22-py3-none-any.whl"
    _make_wheel(whl, "certifi", "2026.7.22", "License: MPL-2.0")
    out = wheel_license_summary(tmp_path)
    assert "MPL-2.0" in out


def test_wheel_license_summary_handles_missing_metadata(tmp_path):
    whl = tmp_path / "environment" / "agent" / "vendor-wheels" / "broken-1.0-py3-none-any.whl"
    whl.parent.mkdir(parents=True)
    with zipfile.ZipFile(whl, "w") as z:
        z.writestr("not_metadata.txt", "nothing here")
    out = wheel_license_summary(tmp_path)
    assert "no METADATA found" in out


def _write_trial(trial_dir, reward, kind=None, stdout=""):
    (trial_dir / "verifier").mkdir(parents=True)
    (trial_dir / "verifier" / "reward.json").write_text(json.dumps({"reward": reward}))
    if kind is not None:
        (trial_dir / "verifier" / "reward-details.json").write_text(
            json.dumps({"reward": {"score": reward, "criteria": [], "kind": kind}}))
    if stdout:
        (trial_dir / "verifier" / "test-stdout.txt").write_text(stdout)


_CRASH_STDOUT = "InternalServerError: AnthropicException - Cannot connect to host localhost:8091"


def test_trial_behavior_status_flags_programmatic_reward_with_crash_as_invalid(tmp_path):
    _write_trial(tmp_path, 0.0, kind="programmatic", stdout=_CRASH_STDOUT)
    status = trial_behavior_status(tmp_path)
    assert status["valid"] is False


def test_trial_behavior_status_trusts_programmatic_reward_with_clean_stdout(tmp_path):
    _write_trial(tmp_path, 0.0, kind="programmatic", stdout="test.sh: exit 1 (behavior check failed)")
    status = trial_behavior_status(tmp_path)
    assert status == {"solved": False, "valid": True, "reason": None}


def test_trial_behavior_status_flags_llm_reward_with_crash_as_invalid(tmp_path):
    _write_trial(tmp_path, 0.0, kind="llm", stdout=_CRASH_STDOUT)
    status = trial_behavior_status(tmp_path)
    assert status["valid"] is False


def test_trial_behavior_status_missing_reward_is_invalid(tmp_path):
    status = trial_behavior_status(tmp_path)
    assert status == {"solved": None, "valid": False, "reason": "no verifier/reward.json"}


def test_passk_discovery_audit_lists_touched_paths_and_excludes_invalid_trials(tmp_path):
    passk = tmp_path / "trajectories" / "pass@k" / "run1"
    good = passk / "trial-good"
    _write_trial(good, 1.0, kind="programmatic")
    (good / "agent").mkdir(parents=True)
    (good / "agent" / "trajectory.json").write_text(
        'curl http://x/front/inventory.php then curl http://x/front/agentstatus.php?x=1 then done')

    bad = passk / "trial-bad"
    _write_trial(bad, 0.0, kind="llm", stdout=_CRASH_STDOUT)

    out = passk_discovery_audit(tmp_path)
    assert "/front/inventory.php" in out
    assert "/front/agentstatus.php" in out
    assert "solved=True valid=True" in out
    assert "excluded:" in out
