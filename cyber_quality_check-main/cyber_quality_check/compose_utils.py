from pathlib import Path

import yaml

from .report import read


def find_compose_services(task_dir: Path):
    text = read(task_dir / "environment" / "docker-compose.yaml")
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        data = {}
    services = data.get("services") or {}
    return text, {k: (v or {}) for k, v in services.items()}


def static_host_ports(services: dict):
    hits = []
    for name, svc in (services or {}).items():
        for p in (svc.get("ports") or []):
            if isinstance(p, dict):
                if p.get("published") not in (None, "", 0):
                    hits.append(f"{name}: {p}")
            elif isinstance(p, str):
                left = p.split("/")[0]
                if ":" in left:
                    hits.append(f"{name}: {p}")
            # a bare int or a colon-free string is a container-only port (ephemeral host port), not static
    return hits
