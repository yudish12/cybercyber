# Provenance & Third-Party Notices

## Base images (digest-pinned)

- **grafana** — `grafana/grafana:13.3.1@sha256:0615ec4fbd4072004b7d86b46ded63013a74b7d6eb1119273dd89e8fa25c13cf`
  - License: **AGPL-3.0-only** (Grafana Labs; Grafana OSS is AGPLv3 since 8.0).
  - Official image is Alpine-based; bundled OS components include **BusyBox (GPL-2.0-only)** and
    **musl libc (MIT)**.
  - The backend binary is rebuilt from the upstream `v13.3.1` source in a multi-stage build; the
    rebuild overlays a single file under `pkg/api/pluginproxy/` and is otherwise stock upstream.
- **golang (build stage only)** — `golang:1.27.3-bookworm@sha256:a5406f41680f17b4aa0b49de641e00f116215f5c8829d548d29cb44c4f85aa4f`
  - License: **BSD-3-Clause** (Go toolchain); Debian `bookworm` base userland under its respective
    Debian/GPL/MIT/BSD licenses. Build stage only; not shipped in the runtime images.
- **internal_service** — `python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e`
  - License: **PSF-2.0** (CPython); Debian `bookworm-slim` base userland under its respective licenses.
- **gateway (web)** — `python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e`
  - License: **PSF-2.0** (CPython); Debian `bookworm-slim` base userland under its respective licenses.
- **agent (main)** — `python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1`
  - License: **PSF-2.0** (CPython); Debian `bookworm-slim` base userland under its respective licenses.

## Python packages (installed per service, at the pinned version)

- **gateway (web)** — direct: `flask==3.0.0` (BSD-3-Clause), `requests==2.31.0` (Apache-2.0),
  `gunicorn==21.2.0` (MIT). Transitive: Werkzeug, Jinja2, MarkupSafe, click, itsdangerous
  (BSD-3-Clause), blinker (MIT); certifi (**MPL-2.0**), urllib3 (MIT), idna (BSD-3-Clause),
  charset-normalizer (MIT); packaging (Apache-2.0 OR BSD-2-Clause).
- **internal_service** — direct: `flask==3.0.0` (BSD-3-Clause), `gunicorn==21.2.0` (MIT);
  same transitive set as the gateway.
- **agent (main)** — OS packages via Debian apt: `curl` (MIT-style/curl), `dnsutils` (bind9,
  MPL-2.0), `jq` (MIT), `tmux` (ISC), **`asciinema` (GPL-3.0)**, `procps` (GPL-2.0),
  `ca-certificates` (MPL-2.0 bundle). Python packages are installed OFFLINE from the committed
  wheels in `environment/agent/vendor-wheels/` (harbor-rewardkit + requests + their full
  dependency closure, 61 wheels). Each wheel's METADATA license (all commercial-use-compatible;
  no restrictive/non-commercial license):
  - **Apache-2.0**: `harbor-rewardkit`, `requests`, `boto3`, `botocore`, `s3transfer`, `openai`,
    `huggingface_hub`, `hf_xet`, `importlib_metadata`, `aiohttp` (AND MIT), `aiosignal`,
    `frozenlist`, `multidict`, `propcache`, `yarl`, `regex` (AND CNRI-Python), `tokenizers`.
  - **MIT**: `litellm`, `pydantic`, `pydantic_core`, `pydantic_settings`, `jsonschema`,
    `jsonschema_specifications`, `referencing`, `rpds_py`, `tiktoken`, `jiter`, `jmespath`,
    `annotated_types`, `anyio`, `attrs`, `charset_normalizer`, `filelock`, `h11`, `h2`, `hpack`,
    `hyperframe`, `pyyaml`, `six`, `sniffio` (OR Apache-2.0), `truststore`, `typing_inspection`,
    `urllib3`, `zipp`.
  - **BSD-3-Clause**: `click`, `fastuuid`, `fsspec`, `httpcore`, `httpcore2`, `httpx`, `httpx2`,
    `idna`, `jinja2`, `markupsafe`, `python_dotenv`, `python_dateutil` (AND Apache-2.0 — METADATA
    "Dual License", BSD-3-Clause + Apache-2.0 classifiers).
  - **MPL-2.0**: `certifi`, `tqdm` (AND MIT).
  - **PSF-2.0**: `aiohappyeyeballs`, `typing_extensions`; `packaging` (Apache-2.0 OR BSD-2-Clause).

## First-party code

The task gateway (`gateway/app.py`, `setup.py`, `_vchan.py`, `boot.sh`), the internal
observability service (`internal_service/app.py`, `boot.sh`), the Grafana standup entrypoint
(`grafana/entrypoint.sh`), and the provisioning/dashboards are first-party and **Proprietary**
(authored for this assessment); no third-party provenance applies.

## Build determinism

No database layer — Grafana uses its embedded SQLite (pure-Go `modernc.org/sqlite`, static
`CGO_ENABLED=0`). Runtime is offline (`network_mode = allowlist`, agent reaches only the gateway);
no runtime package fetches.
