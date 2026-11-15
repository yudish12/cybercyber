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
| `debian`, `ubuntu` (as base images) | **Mixed** (GPL/LGPL/MIT/BSD/… per package) | State "multiple; see the distro copyright", not a single SPDX id. A `python:*-slim` image is labeled **PSF** (CPython) — QC passed that in cases 8/9 — optionally noting that its Debian layer is mixed. |
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
4. A sibling/nested `environment/<app>/NOTICE.md` does **not** satisfy EN4 — only the top-level file counts. A
   false statement in ANY shipped NOTICE, nested or top-level, is still Tier A (calibration case 5; policy 11).

`qc_selfcheck.py` (v1.3e) checks each image's license and gates Tier A when it is wrong or missing; compose
`image:` refs are included, also in the mutable-tag scan. `helpers/audit_facts.py` prints a per-image verdict
(`LICENSE ok` / `MENTIONED but NO license` / `license '<x>' may be WRONG for <base> ... VERIFY` /
`NOT MENTIONED`) — confirm a "may be WRONG" against this table (both tools' matches are approximate), then score it.

## Tier (SKILL.md rule 5) and the one dissent

A wrong or missing base-image/app license is **Tier A**: QC failed it in calibration cases 2 and 3, and the
case 3→9 fix (busybox relabeled GPL-2.0, python licensed PSF) flipped EN4 to PASS. Calibration case 7
(`w-estate/ssrf-imds-rawip`, a labeled **PASS**) ships the identical busybox-"BSD-3-Clause" mislabel AND no
license for python:3.11/3.12-slim or the app, yet **passed EN4 5/5** — the lone PASS dissent among the logged
cases (base-image lines are not logged for cases 1, 4, 6, 10 and 11). This skill scores case 7 EN4 = FAIL anyway:
a deliberate disagreement with QC (policy 6). Do not let the dissent lower a Tier A score; name it in the report
as the known disagreement. Vendored wheels, pip and npm deps are classified separately (misstated blanket =
Tier A, e.g. case 6's npm NOTICE; undocumented = Tier B (i) — SKILL.md Step 1.5 #11).
