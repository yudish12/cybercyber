from cyber_quality_check.compose_utils import find_compose_services, static_host_ports

COMPOSE_WITH_MAIN = """
services:
  db:
    image: mariadb:10.11@sha256:deadbeef
  web:
    build:
      context: ./gateway
    ports:
      - '8080'
  main:
    build:
      context: ./agent
    volumes:
      - vchan:/vchan:ro
volumes:
  vchan: null
"""

COMPOSE_WITH_STATIC_PORT = """
services:
  main:
    build:
      context: ./agent
    ports:
      - '9000:9000'
"""


def _write_compose(tmp_path, text):
    env = tmp_path / "environment"
    env.mkdir()
    (env / "docker-compose.yaml").write_text(text)
    return tmp_path


def test_finds_main_among_several_services(tmp_path):
    task_dir = _write_compose(tmp_path, COMPOSE_WITH_MAIN)
    _, services = find_compose_services(task_dir)
    assert set(services) == {"db", "web", "main"}


def test_bare_container_port_is_not_static(tmp_path):
    task_dir = _write_compose(tmp_path, COMPOSE_WITH_MAIN)
    _, services = find_compose_services(task_dir)
    assert static_host_ports(services) == []


def test_host_colon_container_port_is_static(tmp_path):
    task_dir = _write_compose(tmp_path, COMPOSE_WITH_STATIC_PORT)
    _, services = find_compose_services(task_dir)
    hits = static_host_ports(services)
    assert len(hits) == 1
    assert "main" in hits[0]


def test_dict_form_published_port_is_static():
    services = {"main": {"ports": [{"target": 8080, "published": 8080}]}}
    assert static_host_ports(services) != []


def test_dict_form_without_published_is_not_static():
    services = {"main": {"ports": [{"target": 8080}]}}
    assert static_host_ports(services) == []
