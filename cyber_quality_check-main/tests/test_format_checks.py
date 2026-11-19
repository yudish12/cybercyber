import json
import os
import time

from cyber_quality_check.checks.format_checks import check_f1, check_f2, check_f5


def _write_f1_baseline(tmp_path):
    for name in (
        "task.toml", "instruction.md", "instruction_L0.md", "instruction_L1.md",
        "instruction_L2.md", "fresh_state.json",
    ):
        (tmp_path / name).write_text("[task]\nname = \"x\"\n" if name == "task.toml" else "{}" if name == "fresh_state.json" else "x")
    env = tmp_path / "environment"
    env.mkdir()
    (env / "docker-compose.yaml").write_text("services:\n  main: {}\n")
    (env / "NOTICE.md").write_text("x")
    solution = tmp_path / "solution"
    solution.mkdir()
    (solution / "solve.sh").write_text("#!/bin/bash\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test.sh").write_text("#!/bin/bash\n")
    (tests / "isolation_test.sh").write_text("#!/bin/bash\n")
    traj = tmp_path / "trajectories"
    traj.mkdir()
    oracle = traj / "oracle"
    oracle.mkdir()
    (oracle / "reward.txt").write_text("1")
    return tmp_path

COMPOSE_NO_MAIN_ONLY = """
services:
  web:
    ports:
      - '8080'
"""

COMPOSE_MAIN_WITH_STATIC_PORT = """
services:
  main:
    ports:
      - '9000:9000'
"""

COMPOSE_CLEAN = """
services:
  main:
    ports:
      - '8080'
"""


def _write_compose(tmp_path, text):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "docker-compose.yaml").write_text(text)
    return tmp_path


def test_no_main_service_only_flags_that_category(tmp_path):
    task_dir = _write_compose(tmp_path, COMPOSE_NO_MAIN_ONLY)
    r = check_f2(task_dir)
    assert r["verdict"] == "FAIL"
    assert "No `main` Service" in r["detail"]
    assert "Static Ports/IPs" not in r["detail"]


def test_static_port_only_flags_that_category(tmp_path):
    task_dir = _write_compose(tmp_path, COMPOSE_MAIN_WITH_STATIC_PORT)
    r = check_f2(task_dir)
    assert r["verdict"] == "FAIL"
    assert "Static Ports/IPs" in r["detail"]
    assert "No `main` Service" not in r["detail"]


def test_bare_container_port_with_main_passes(tmp_path):
    task_dir = _write_compose(tmp_path, COMPOSE_CLEAN)
    (task_dir / "task.toml").write_text(
        "[environment]\ncpus = 2\n\n[agent]\ntimeout_sec = 36000\n"
    )
    r = check_f2(task_dir)
    assert r["verdict"] == "PASS"


def test_missing_agent_timeout_and_environment_cpus_fails(tmp_path):
    task_dir = _write_compose(tmp_path, COMPOSE_CLEAN)
    (task_dir / "task.toml").write_text("[environment]\nos = \"linux\"\n")
    r = check_f2(task_dir)
    assert r["verdict"] == "FAIL"
    assert "Missing/Wrong agent.timeout_sec" in r["detail"]
    assert "Missing/Wrong environment.cpus" in r["detail"]


def test_compose_shorthand_resource_on_main_fails(tmp_path):
    compose = """
services:
  main:
    ports:
      - '8080'
    cpus: 1.5
    mem_limit: 512m
"""
    task_dir = _write_compose(tmp_path, compose)
    (task_dir / "task.toml").write_text(
        "[environment]\ncpus = 2\n\n[agent]\ntimeout_sec = 36000\n"
    )
    r = check_f2(task_dir)
    assert r["verdict"] == "FAIL"
    assert "Compose Shorthand/Long-Form Resource Conflict" in r["detail"]


def _write_f5_baseline(tmp_path, agent_dockerfile_text):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "docker-compose.yaml").write_text(COMPOSE_CLEAN)
    agent_dir = env / "agent"
    agent_dir.mkdir()
    (agent_dir / "Dockerfile").write_text(agent_dockerfile_text)
    (tmp_path / "task.toml").write_text('[agent]\nuser = "agent"\n')
    (tmp_path / "fresh_state.json").write_text(json.dumps({}))
    return tmp_path


def test_agent_dockerfile_missing_tmux_asciinema_fails(tmp_path):
    task_dir = _write_f5_baseline(
        tmp_path,
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nRUN apt-get install -y curl\n",
    )
    r = check_f5(task_dir)
    assert r["verdict"] == "FAIL"
    assert any("tmux" in e and "asciinema" in e for e in r["evidence"])


def test_agent_dockerfile_with_tmux_asciinema_passes(tmp_path):
    task_dir = _write_f5_baseline(
        tmp_path,
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nRUN apt-get install -y tmux asciinema\n",
    )
    r = check_f5(task_dir)
    assert r["verdict"] == "PASS"


def test_missing_agent_dockerfile_fails(tmp_path):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "docker-compose.yaml").write_text(COMPOSE_CLEAN)
    (tmp_path / "task.toml").write_text('[agent]\nuser = "agent"\n')
    (tmp_path / "fresh_state.json").write_text(json.dumps({}))
    r = check_f5(tmp_path)
    assert r["verdict"] == "FAIL"
    assert any("environment/agent/Dockerfile missing" in e for e in r["evidence"])


def test_pass_at_k_backup_folder_not_flagged_as_stray(tmp_path):
    task_dir = _write_f1_baseline(tmp_path)
    (task_dir / "trajectories" / "pass@k.bak-20261113-063425").mkdir()
    r = check_f1(task_dir)
    assert r["verdict"] == "PASS"


def test_unrelated_stray_folder_still_flagged(tmp_path):
    task_dir = _write_f1_baseline(tmp_path)
    (task_dir / "trajectories" / "some_random_debug_dir").mkdir()
    r = check_f1(task_dir)
    assert r["verdict"] == "FAIL"
    assert any("unexpected entries" in e for e in r["evidence"])


def test_oracle_reward_sentinel_falls_back_to_json(tmp_path):
    task_dir = _write_f1_baseline(tmp_path)
    oracle = task_dir / "trajectories" / "oracle"
    (oracle / "reward.txt").write_text(
        "HARBOR_SCHEMA_ERROR: no reward.json or reward.txt found in /logs/verifier/\n"
    )
    (oracle / "reward.json").write_text('{"reward":1}')
    r = check_f1(task_dir)
    assert r["verdict"] == "PASS"


def _touch(path, when):
    os.utime(path, (when, when))


def test_f1_flags_oracle_evidence_older_than_solve_sh(tmp_path):
    task_dir = _write_f1_baseline(tmp_path)
    now = time.time()
    oracle = task_dir / "trajectories" / "oracle"
    (oracle / "test.log").write_text("reward: 1.0\n")
    _touch(oracle / "reward.txt", now - 10000)
    _touch(oracle / "test.log", now - 10000)
    _touch(task_dir / "solution" / "solve.sh", now)
    r = check_f1(task_dir)
    assert r["verdict"] == "FAIL"
    assert any("never re-captured" in e for e in r["evidence"])


def test_f1_flags_only_reward_txt_restamped_while_test_log_stale(tmp_path):
    task_dir = _write_f1_baseline(tmp_path)
    now = time.time()
    oracle = task_dir / "trajectories" / "oracle"
    (oracle / "test.log").write_text("reward: 1.0\n")
    _touch(task_dir / "solution" / "solve.sh", now - 5000)
    _touch(oracle / "test.log", now - 5000)
    _touch(oracle / "reward.txt", now)
    r = check_f1(task_dir)
    assert r["verdict"] == "FAIL"
    assert any("only reward.txt appears to have been re-stamped" in e for e in r["evidence"])


def test_f1_no_staleness_flag_when_evidence_matches_source(tmp_path):
    task_dir = _write_f1_baseline(tmp_path)
    now = time.time()
    oracle = task_dir / "trajectories" / "oracle"
    (oracle / "test.log").write_text("reward: 1.0\n")
    _touch(task_dir / "solution" / "solve.sh", now - 5000)
    _touch(oracle / "test.log", now)
    _touch(oracle / "reward.txt", now)
    r = check_f1(task_dir)
    assert r["verdict"] == "PASS"
