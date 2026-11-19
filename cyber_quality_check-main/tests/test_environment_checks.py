from cyber_quality_check.checks.environment_checks import (
    check_en2, check_en3, check_en4, _network_mode_compliance_note,
)

PASSING_COMPOSE = """
services:
  appserver:
    environment:
      MYSQL_PASSWORD_FILE: /dbcreds/app_pw
      DOLI_ADMIN_LOGIN: admin
      NO_PROXY: web,localhost,127.0.0.1,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
"""

FAILING_COMPOSE_CRED = """
services:
  appserver:
    environment:
      ADMIN_PASSWORD: hunter2
"""

FAILING_COMPOSE_EGRESS = """
services:
  web:
    environment:
      NO_PROXY: web,appserver,localhost,127.0.0.1
"""


def _write_compose(tmp_path, text):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "docker-compose.yaml").write_text(text)
    (tmp_path / "task.toml").write_text("")
    return tmp_path


def test_secret_file_reference_is_not_flagged(tmp_path):
    task_dir = _write_compose(tmp_path, PASSING_COMPOSE)
    r = check_en3(task_dir)
    assert r["verdict"] == "PASS", r["evidence"]


def test_login_username_field_is_not_flagged(tmp_path):
    task_dir = _write_compose(tmp_path, PASSING_COMPOSE)
    r = check_en3(task_dir)
    assert not any("DOLI_ADMIN_LOGIN" in e for e in r["evidence"])


def test_real_hardcoded_password_is_flagged(tmp_path):
    task_dir = _write_compose(tmp_path, FAILING_COMPOSE_CRED)
    r = check_en3(task_dir)
    assert r["verdict"] == "FAIL"
    assert "Credential Hygiene" in r["detail"]
    assert "Egress Hygiene" not in r["detail"]


def test_hostname_only_no_proxy_is_flagged(tmp_path):
    task_dir = _write_compose(tmp_path, FAILING_COMPOSE_EGRESS)
    r = check_en3(task_dir)
    assert r["verdict"] == "FAIL"
    assert "Egress Hygiene" in r["detail"]
    assert "Credential Hygiene" not in r["detail"]


def test_seed_data_credential_reuse_defers_to_judge_instead_of_passing(tmp_path):
    import json as _json
    task_dir = _write_compose(tmp_path, PASSING_COMPOSE)
    data_pack = task_dir / "environment" / "data-pack"
    data_pack.mkdir()
    (data_pack / "security-review.json").write_text(_json.dumps({
        "users": [
            {"username": "lead_morgan", "password_hash": "$2b$12$sameHashSameHashSameHash"},
            {"username": "sec_lead", "password_hash": "$2b$12$sameHashSameHashSameHash"},
        ],
    }))
    r = check_en3(task_dir)
    assert r["verdict"] != "PASS"


def test_allowlist_scoped_to_own_services_is_not_a_violation():
    toml_text = '[agent]\nnetwork_mode = "allowlist"\nallowed_hosts = ["gateway"]\n'
    issue, note = _network_mode_compliance_note(toml_text, {"main", "gateway", "backend"})
    assert issue is None
    assert "gateway" in note
    assert "no external internet access" in note


def test_allowlist_naming_external_host_is_a_violation():
    toml_text = '[agent]\nnetwork_mode = "allowlist"\nallowed_hosts = ["evil.example.com"]\n'
    issue, note = _network_mode_compliance_note(toml_text, {"main", "gateway"})
    assert issue is not None
    assert "evil.example.com" in issue


def test_no_network_is_not_a_violation():
    toml_text = '[agent]\nnetwork_mode = "no-network"\n'
    issue, note = _network_mode_compliance_note(toml_text, {"main"})
    assert issue is None


def test_check_en2_fails_on_allowlist_naming_external_host(tmp_path):
    task_dir = _write_compose(
        tmp_path,
        """
services:
  main: {}
  gateway: {}
""",
    )
    (task_dir / "task.toml").write_text(
        '[agent]\nnetwork_mode = "allowlist"\nallowed_hosts = ["evil.example.com"]\n'
    )
    r = check_en2(task_dir)
    assert r["verdict"] == "FAIL"
    assert any("evil.example.com" in e for e in r["evidence"])


def _write_en4_baseline(tmp_path):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "NOTICE.md").write_text("License: MIT. Provenance: first-party. sha256 pinned base images.")
    (env / "docker-compose.yaml").write_text("services:\n  main: {}\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test.sh").write_text("#!/bin/bash\n")
    return tmp_path


def test_en4_fails_on_oversized_report_criterion_name(tmp_path):
    task_dir = _write_en4_baseline(tmp_path)
    report_dir = task_dir / "tests" / "report"
    report_dir.mkdir()
    (report_dir / "rubric.toml").write_text(
        '[[criterion]]\nname = "' + "x" * 65 + '"\ndescription = "x"\n'
    )
    r = check_en4(task_dir)
    assert r["verdict"] == "FAIL"
    assert "[Fail - Reproducibility]" in r["detail"]


def test_en4_passes_report_criterion_within_limit(tmp_path):
    task_dir = _write_en4_baseline(tmp_path)
    report_dir = task_dir / "tests" / "report"
    report_dir.mkdir()
    (report_dir / "rubric.toml").write_text(
        '[[criterion]]\nname = "' + "x" * 64 + '"\ndescription = "x"\n'
    )
    r = check_en4(task_dir)
    assert r["verdict"] != "FAIL"
