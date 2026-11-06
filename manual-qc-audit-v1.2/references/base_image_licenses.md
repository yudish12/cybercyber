# Base-image license reference (for EN4 Provenance / Licensing)

EN4 requires the top-level `environment/NOTICE.md` to state a **correct** license for every shipped base
image (and the app). A **digest pin is not a license**, and a license **stated incorrectly counts as missing**
(calibration case 3). Use this table to catch a wrong license; when a version/image isn't here, **verify
against the image's own `LICENSE` or the project's license page** rather than guessing — licenses change
across versions.

| Base image | Correct license | Trap / note |
|---|---|---|
| `busybox` | **GPL-2.0-only (GPLv2)** | **Classic wrong label: it is NOT BSD.** (busybox.net/license.html) |
| `python` / CPython (incl. `-slim`) | **PSF License** (Python Software Foundation License Agreement) | NOT MIT, NOT BSD. `-slim` adds Debian packages (mixed). |
| `node` / `node:alpine` | **MIT** (Node.js core) | alpine variant also ships Alpine + **musl (MIT)** + **busybox (GPL-2.0)**. |
| `alpine` | **MIT** (Alpine base) | ships **busybox (GPL-2.0)** + **musl (MIT)**. |
| `debian`, `ubuntu`, `*-slim` | **Mixed** (GPL/LGPL/MIT/BSD/… per package) | State "multiple; see the distro copyright", not a single SPDX id. |
| `gitea/gitea` | **MIT** | |
| `golang` / `go` | **BSD-3-Clause** | |
| `nginx` | **BSD-2-Clause** | |
| `postgres` | **PostgreSQL License** (BSD/MIT-style) | |
| `redis` | **BSD-3-Clause** (≤7.2) · **RSALv2 + SSPLv1** (7.4–7.x) · **AGPLv3** (8.0+) | version-dependent — check the tag. |
| `mysql` | **GPLv2** (+ FOSS exception) | |
| `mariadb` | **GPLv2** | |

## How to score it
1. List every base image: each `FROM` in `environment/**/Dockerfile*` + every `image:` in the compose.
2. For each, find its line in the **top-level** `environment/NOTICE.md` and the license stated next to it.
3. Fail EN4 **[Fail - Provenance / Licensing]** if, for any image (or the app): the image isn't mentioned,
   no license is stated, only a digest pin is given, **or the stated license contradicts the table above**.
4. A sibling/nested `environment/<app>/NOTICE.md` does **not** satisfy EN4 — only the top-level file counts.

`helpers/audit_facts.py` prints a per-image verdict (`LICENSE ok` / `MENTIONED but NO license` /
`license '<x>' may be WRONG for <base> ... VERIFY` / `NOT MENTIONED`) — treat a "may be WRONG" as a finding
to confirm against this table, not an auto-fail.

## ⚠ Scoring divergence (grounded, calibration case 7)

This table states FACTS (busybox IS GPL-2.0, etc.). But base-image **licensing is scored inconsistently**:
calibration case 3 **FAILED** EN4 for labeling busybox "BSD-3-Clause" + a python no-license, yet case 7
(`w-estate/ssrf-imds-rawip`, a labelled **PASS**) ships the **identical** busybox-"BSD-3-Clause" mislabel AND
no license for python:3.11/3.12-slim or the app, and **PASSED EN4 5/5**. So: keep citing the correct license
from this table, but **surface a wrong/missing base-image license as a CANDIDATE and flag the divergence — do
not auto-fail EN4 on it.** EN4 is the noisiest dimension in the corpus (every sub-pattern — base-image license,
restart re-mint, vendored-wheel/gateway-dep provenance, report-judge fail-close — appears in both fail and pass
bundles).
