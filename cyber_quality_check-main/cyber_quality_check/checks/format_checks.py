import json
import re
from pathlib import Path

from ..compose_utils import find_compose_services, static_host_ports
from ..constants import (
    COMPOSE_IMAGE_RE, DIGEST_PIN_RE, FLAG_PREFIX_RE, FROM_IMAGE_RE,
    LEAK_TERMS, SUBNET_LITERAL_RE,
)
from ..evidence import resolve_reward_value, trajectory_staleness_issues
from ..llm_judge import judge_dimension
from ..report import read, result


def check_f1(task_dir: Path):
    missing = []
    required_files = [
        "task.toml", "instruction.md", "instruction_L0.md", "instruction_L1.md",
        "instruction_L2.md", "fresh_state.json", "environment/docker-compose.yaml",
        "environment/NOTICE.md", "solution/solve.sh", "tests/test.sh",
        "tests/isolation_test.sh",
    ]
    for rel in required_files:
        p = task_dir / rel
        if not p.exists() or p.stat().st_size == 0:
            missing.append(rel)

    for rel, kind in [("task.toml", "toml"), ("environment/docker-compose.yaml", "yaml"), ("fresh_state.json", "json")]:
        p = task_dir / rel
        if not p.exists():
            continue
        text = read(p)
        if kind == "json":
            try:
                json.loads(text)
            except Exception as e:
                missing.append(f"{rel} (unparsable JSON: {e})")
        elif kind == "toml":
            if "[task]" not in text or not re.search(r"\[task\][^\[]*name\s*=", text, re.DOTALL):
                missing.append(f"{rel} (no [task] name)")

    for rel in ["solution/solve.sh", "tests/test.sh", "tests/isolation_test.sh"]:
        p = task_dir / rel
        if not p.exists():
            continue
        text = read(p)
        executable = (p.stat().st_mode & 0o111) != 0
        shebang = text.startswith("#!")
        if not executable and not shebang:
            missing.append(f"{rel} (no exec bit, no shebang)")

    oracle_val = resolve_reward_value(task_dir / "trajectories" / "oracle")
    if oracle_val is None:
        missing.append("trajectories/oracle/reward.txt missing")
    else:
        try:
            if float(oracle_val) <= 0:
                missing.append(f"trajectories/oracle reward = {oracle_val!r}, expected non-zero (oracle solve should earn credit)")
        except ValueError:
            missing.append(f"trajectories/oracle reward unparseable: {oracle_val!r}")

    trajectories_dir = task_dir / "trajectories"
    if trajectories_dir.is_dir():
        allowed = {"oracle", "noop", "pass@k"}
        backup_re = re.compile(r"^pass@k\.bak-\d{8}-\d{6}$")
        extras = sorted(
            p.name for p in trajectories_dir.iterdir()
            if p.name not in allowed and not p.name.startswith(".") and not backup_re.match(p.name)
        )
        if extras:
            missing.append(f"trajectories/ has unexpected entries beyond oracle/noop/pass@k: {extras}")

    missing.extend(trajectory_staleness_issues(task_dir))

    if missing:
        return result("F1", "Structure & Artifacts", "FAIL", "[Fail - Required Structure]", missing)
    return result("F1", "Structure & Artifacts", "PASS",
                   "all required files present, parseable, executable; oracle earns credit; "
                   "trajectories/ has no stray entries")


def _toml_section(text: str, name: str):
    m = re.search(rf'(?ms)^\[{re.escape(name)}\]\s*\n(.*?)(?=^\[[^.\]]+\]|\Z)', text)
    return m.group(1) if m else None


def _toml_number_field(section_text: str, field: str):
    if section_text is None:
        return None
    m = re.search(rf'^\s*{re.escape(field)}\s*=\s*([0-9.]+)', section_text, re.MULTILINE)
    return float(m.group(1)) if m else None


def check_f2(task_dir: Path):
    compose_text, services = find_compose_services(task_dir)
    issues = []
    labels = []
    if "main" not in services:
        issues.append(f"no service named exactly 'main' (found: {sorted(services)})")
        labels.append("[Fail - No `main` Service]")

    host_ports = static_host_ports(services)
    if host_ports:
        issues.append(f"static host:container port mapping(s) found: {host_ports}")
        labels.append("[Fail - Static Ports/IPs]")

    main_svc = services.get("main", {})
    if main_svc.get("networks") is not None:
        issues.append(
            "main service declares its own 'networks:' key in docker-compose.yaml -- Harbor's "
            "egress sidecar sets network_mode: service:<sidecar> on main at deploy time, which "
            "conflicts with any task-declared networks: key on the same service ('docker "
            "compose up failed: service main declares mutually exclusive network_mode and "
            "networks'). Remove networks: from main; join the web/gateway-equivalent service "
            "to default (+ its existing internal networks) instead."
        )
        labels.append("[Fail - Sidecar Network Conflict]")

    toml_text = read(task_dir / "task.toml")
    other_services = [name for name in services if name != "main"]
    if re.search(r'network_mode\s*=\s*"no-network"', toml_text) and other_services:
        issues.append(
            f"task.toml sets network_mode = \"no-network\" but docker-compose.yaml has other "
            f"service(s) besides main ({sorted(other_services)}) -- no-network blocks any "
            f"in-compose target the agent must reach (e.g. web/gateway); use "
            f"network_mode = \"allowlist\" with an explicit allowed_hosts list instead."
        )
        labels.append("[Fail - No-Network Blocks In-Compose Target]")

    agent_timeout = _toml_number_field(_toml_section(toml_text, "agent"), "timeout_sec")
    if agent_timeout != 36000:
        issues.append(
            f"task.toml [agent].timeout_sec = {agent_timeout!r}, expected exactly 36000 -- "
            "required on every task so a long-running boot/verify doesn't get killed early"
        )
        labels.append("[Fail - Missing/Wrong agent.timeout_sec]")

    env_cpus = _toml_number_field(_toml_section(toml_text, "environment"), "cpus")
    if env_cpus != 2:
        issues.append(
            f"task.toml [environment].cpus = {env_cpus!r}, expected exactly 2"
        )
        labels.append("[Fail - Missing/Wrong environment.cpus]")

    shorthand_hits = {k: main_svc.get(k) for k in ("cpus", "mem_limit", "pids_limit") if main_svc.get(k) is not None}
    if shorthand_hits:
        issues.append(
            f"main service in docker-compose.yaml sets Compose-v2 shorthand resource field(s) "
            f"{shorthand_hits} -- Harbor writes its own resource override from task.toml's "
            "[environment].cpus as long-form deploy.resources.*, and Compose refuses to merge "
            "shorthand and long-form representations of the same field for one service "
            "('docker compose up' then fails to boot). Remove these from main in "
            "docker-compose.yaml; task.toml's [environment].cpus is the only place this "
            "belongs."
        )
        labels.append("[Fail - Compose Shorthand/Long-Form Resource Conflict]")

    if issues:
        return result("F2", "Compose Contract", "FAIL", " / ".join(labels), issues)

    subnet_hits = SUBNET_LITERAL_RE.findall(compose_text)
    if subnet_hits:
        return judge_dimension("F2", {
            "docker-compose.yaml (subnet/IP excerpt)": compose_text,
            "subnet_or_ip_literals_found": str(subnet_hits),
            "task.toml": toml_text,
        })
    return result("F2", "Compose Contract", "PASS",
                   "main service present, no static host ports, no literal subnets, no sidecar "
                   "network conflict, no-network doesn't block an in-compose target, "
                   "agent.timeout_sec=36000 and environment.cpus=2 set, no compose shorthand/"
                   "long-form resource conflict on main")


def check_f3(task_dir: Path):
    files = ["instruction.md", "instruction_L0.md", "instruction_L1.md", "instruction_L2.md"]
    prefixes_by_file = {}
    leaks = []
    for name in files:
        p = task_dir / name
        if not p.exists():
            continue
        text = read(p)
        prefixes = sorted(set(m.group(1) for m in FLAG_PREFIX_RE.finditer(text)))
        if prefixes:
            prefixes_by_file[name] = prefixes
        for prefix in prefixes:
            for term in LEAK_TERMS:
                if term.replace(" ", "") in prefix.lower().replace("_", ""):
                    leaks.append(f"{name}: flag prefix '{prefix}=' leaks vulnerability class via {term!r}")

    if leaks:
        return result("F3", "Flag/Marker Format", "FAIL", "[Fail - Prefix Vulnerability Leakage]", leaks)

    all_prefixes = {p for ps in prefixes_by_file.values() for p in ps}
    if len(prefixes_by_file) >= 2 and len(all_prefixes) > 1:
        return result("F3", "Flag/Marker Format", "FAIL", "[Fail - Flag Consistency]",
                       [f"{k}: {v}" for k, v in prefixes_by_file.items()])

    evidence = {name: read(task_dir / name) for name in files if (task_dir / name).exists()}
    format_hint_re = re.compile(r"[^.\n]*\b\d+\b[^.\n]{0,24}?\b(hex|hexadecimal|character|char|digit|byte)[^.\n]*", re.I)
    hints = {}
    for name, text in evidence.items():
        hints[name] = [m.group(0).strip() for m in format_hint_re.finditer(text)] or ["(no length/character-class format description found)"]
    evidence["marker_format_descriptions_per_file (compare these across files for the consistency check)"] = "\n".join(
        f"{k}: {v}" for k, v in hints.items()
    )
    return judge_dimension("F3", evidence)


def check_f5(task_dir: Path):
    issues = []
    dockerfiles = list(task_dir.glob("environment/**/Dockerfile"))
    compose_text = read(task_dir / "environment" / "docker-compose.yaml")
    for df in dockerfiles:
        text = read(df)
        for m in FROM_IMAGE_RE.finditer(text):
            if not DIGEST_PIN_RE.search(m.group(0) + text[m.end():m.end() + 80]):
                issues.append(f"{df}: FROM {m.group(1)} not digest-pinned")
    for m in COMPOSE_IMAGE_RE.finditer(compose_text):
        if "@sha256:" not in m.group(1):
            issues.append(f"docker-compose.yaml: image {m.group(1)} not digest-pinned")

    for name in LEAK_TERMS:
        for p in (task_dir / "environment").rglob("*"):
            if p.is_file() and p.suffix in (".py", ".js", ".php", ".md", ".yaml", ".yml"):
                text = read(p)
                if re.search(r"#.*\b" + re.escape(name) + r"\b", text, re.I) or \
                   re.search(r"//.*\b" + re.escape(name) + r"\b", text, re.I):
                    issues.append(f"{p}: possible exploit-narration comment naming {name!r}")
                    break

    fresh_state = task_dir / "fresh_state.json"
    if not fresh_state.exists():
        issues.append("fresh_state.json missing")
    else:
        try:
            json.loads(read(fresh_state))
        except Exception as e:
            issues.append(f"fresh_state.json invalid: {e}")

    toml_text = read(task_dir / "task.toml")
    if not re.search(r"(agent_user|user)\s*=\s*\"?(?!root)", toml_text):
        issues.append("task.toml: no non-root agent identity field found")

    agent_dockerfile = task_dir / "environment" / "agent" / "Dockerfile"
    if not agent_dockerfile.exists():
        issues.append("environment/agent/Dockerfile missing")
    else:
        agent_text = read(agent_dockerfile)
        missing_tools = [t for t in ("tmux", "asciinema") if not re.search(rf"\b{t}\b", agent_text)]
        if missing_tools:
            issues.append(
                f"environment/agent/Dockerfile does not install {missing_tools} -- terminus-2's "
                "tmux session needs tmux installed in the agent container (pty allocation fails "
                "without it), and asciinema is required for session recording"
            )

    if issues:
        return result("F5", "Packaging Hygiene", "FAIL", "[Fail - Packaging Hygiene]", issues)
    return result("F5", "Packaging Hygiene", "PASS",
                   "digest-pinned, narration clean, non-root, fresh_state.json valid, "
                   "agent Dockerfile has tmux + asciinema")


CHECKS = [check_f1, check_f2, check_f3, check_f5]
