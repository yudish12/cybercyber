# PR #197 compatibility checklist

Source: scaleapi/cyber-sample-tasks#197 (`batch_01: let the agent reach only
web so tasks run on Scale Sandbox`, plus its 4 follow-up commits). Run this
checklist against every multi-container task before shipping, including ones
not in batch_01 — the failure modes are infra-level (Lighthouse / Scale
Sandbox), not task-specific.

## 1. Network isolation vs Harbor's egress sidecar

**Symptom:** `docker compose up failed: service main declares mutually
exclusive network_mode and networks`.

**Cause:** Harbor's sidecar sets `network_mode: service:<sidecar>` on `main`;
a task-declared `networks:` on `main` conflicts with it. `no-network` also
blocks any in-compose target the agent must reach (e.g. `web`/`gateway`).

**Check:**
- [ ] `docker-compose.yaml`: `main` has no `networks:` key at all.
- [ ] `docker-compose.yaml`: the web/gateway-equivalent service joins
      `default` (+ its existing internal networks, e.g. `backend`).
- [ ] `docker-compose.yaml`: any now-unused bridge network (e.g. `frontend`)
      is removed from the top-level `networks:` block.
- [ ] `task.toml`: `[environment]` and `[agent]` use
      `network_mode = "allowlist"` with `allowed_hosts = [...]` listing every
      host `main` actually talks to (not `no-network`).

## 2. tmux + asciinema in the agent image

**Symptom:** `RuntimeError: Failed to start tmux session (return code 127)`
or similar for asciinema.

**Cause:** Terminus-2 drives `main` through a tmux session and records it
with asciinema by default. Under `allowlist` network mode, a build-time
`apt-get install` works (build has network access) but a run-time install
inside the agent's own setup does not — any run-time host list for the agent
should not need to include install sources.

**Check:**
- [ ] `environment/agent/Dockerfile`'s `apt-get install` line includes both
      `tmux` and `asciinema`.
- [ ] If the Dockerfile builds with `network: none` (fully-offline-build
      tasks), both packages are vendored as `.deb`s and `dpkg -i`'d instead
      (watch for `asciinema`'s own dependency, `python3-pkg-resources`).
- [ ] Live-verify in the built image: `which tmux && tmux -V && which
      asciinema && asciinema --version`.

## 3. `web`/target-IP discovery accepts a blocked-but-not-refused connection

**Symptom:** only relevant if the task's compose file has a shell loop that
probes candidate IPs for the web/target service and writes the winner to
`/vchan/web_ip` or similar.

**Cause:** the sidecar accepts and then drops blocked connections (curl exit
52), which is neither "refused" (7) nor "timed out" (28) — a loop that
treats "not refused and not timed out" as success can pick an unreachable IP.

**Check:**
- [ ] Only applies if `docker-compose.yaml` has a `WEB_IP`/candidate-IP
      picking loop at all (grep for `WEB_IP` or similar).
- [ ] Where present, the success condition requires an actual HTTP response
      (`curl` exit code `0`), not just "exit code isn't 7 or 28".

## 4. Dolibarr `db` entrypoint loses its exec bit

**Symptom:** only relevant for tasks with a custom
`environment/dolibarr/db-entrypoint.sh` (or similarly named) mounted into the
`db` service with a bare `entrypoint: [/db-entrypoint.sh]`.

**Cause:** Lighthouse unzips tasks without preserving exec bits, so a script
relying on its own `+x` bit to run fails to start.

**Check:**
- [ ] Only applies if `docker-compose.yaml`'s `db` service has a custom
      entrypoint script mounted as a volume/COPY.
- [ ] Where present, `entrypoint:` is `[/bin/sh, /db-entrypoint.sh]` (or
      equivalent), not a bare path.
- [ ] Live-verify: `docker compose up -d db`, confirm it reaches `healthy`.

## 5. `harbor-rewardkit` install falls back to PyPI when `vendor-wheels/` is absent

**Symptom:** only relevant if `vendor-wheels/` is untracked/gitignored (i.e.
not shipped inside the delivered zip) — Docker's classic builder fails a
`COPY` whose wildcard source matches nothing.

**Cause:** `COPY vendor-wheels /tmp/vendor-wheels` requires the directory to
exist with at least one file; if it's empty or absent at build time, the
build fails.

**Check:**
- [ ] If the task ships real `.whl` files inside `vendor-wheels/` in the
      delivered zip (the normal case for this batch), this does **not**
      apply — skip it.
- [ ] If `vendor-wheels/` can legitimately be empty/absent at build time, use
      `COPY Dockerfile vendor-wheels* /tmp/vendor-wheels/` (always gives COPY
      a real source file) and a shell fallback:
      ```
      RUN if ls /tmp/vendor-wheels/*.whl >/dev/null 2>&1; then \
            pip install --no-cache-dir --no-index --find-links=/tmp/vendor-wheels harbor-rewardkit==0.1.7; \
          else \
            pip install --no-cache-dir harbor-rewardkit==0.1.7; \
          fi
      ```

## 6. `cpus` declared in `task.toml`

**Check:**
- [ ] `[environment]` declares `cpus = 2` (Lighthouse pre-flight warns/fails
      without it). Confirmed standing convention for this batch — do not
      omit it.
- [ ] If `docker-compose.yaml`'s `main` also sets a `cpus:`/`mem_limit:`/
      `pids_limit:` shorthand, it must match what Harbor injects via
      `deploy.resources.limits.*` exactly, or be removed — otherwise
      `docker compose up` fails with "can't set distinct values on 'X' and
      'deploy.resources.limits.X'".

## Applicability summary (as audited on 310_7–310_14 + dolibarr-fieldcalc-eval-rce)

| Task | §1 network | §2 tmux/asciinema | §3 web-IP | §4 db entrypoint | §5 wheels fallback |
|---|---|---|---|---|---|
| jiro-image-cache-deception | done | done | n/a | n/a | n/a (wheels shipped) |
| jiro-react2shell-rce | done | done | n/a | n/a | n/a (wheels shipped) |
| jiro-rsc-source-exposure | done | done | n/a | n/a | n/a (wheels shipped) |
| w-task_2_jwt-none | done | done | done | n/a | n/a |
| httpd-estate-cve-2025-58098 | done | done | done | n/a | n/a |
| dolibarr-estate-cve-2026-81730 | done | done | n/a | done | n/a (wheels shipped) |
| dolibarr-estate-cve-2025-67486 | done | done | n/a | done | n/a (wheels shipped) |
| dolibarr-estate-cve-2025-56588 | done | done | n/a | done | n/a (wheels shipped) |
| dolibarr-fieldcalc-eval-rce | done | done | n/a | n/a (own db/Dockerfile, no custom entrypoint) | n/a (own vendor-debs/wheels pattern) |
