# Base-image license reference (for EN5 Provenance / Licensing)

**V17 split:** Provenance / Licensing is now its own scored dimension **EN5** (graded 2/3/5), split out of
EN4 (EN4 keeps Reproducibility + digest-pinning / `Unbounded or Unpinned`). EN5 wants the top-level
`environment/NOTICE.md` to state a **correct** license for every shipped **third-party** component (base
images, the app, gateway/app pip deps, vendored wheels). First-party (self-written) code needs **no**
provenance. A **digest pin is not a license**, and a license **stated incorrectly counts as a false
attribution**. When a version/image isn't in the table, **verify against the image's own `LICENSE` or the
project's license page** rather than guessing — licenses change across versions.

| Base image | Correct license | Trap / note |
|---|---|---|
| `busybox` | **GPL-2.0-only (GPLv2)** | **Classic wrong label: it is NOT BSD.** (busybox.net/license.html) |
| `python` / CPython (incl. `-slim`) | **PSF License** (Python Software Foundation License Agreement) | NOT MIT, NOT BSD. `-slim` adds Debian packages (mixed). |
| `node` / `node:alpine` | **MIT** (Node.js core) | alpine variant also ships Alpine + **musl (MIT)** + **busybox (GPL-2.0)**. |
| `alpine` | **MIT** (Alpine base) | ships **busybox (GPL-2.0)** + **musl (MIT)**. |
| `debian`, `ubuntu` (as base images) | **Mixed** (GPL/LGPL/MIT/BSD/… per package) | State "multiple; see the distro copyright", not a single SPDX id. A `python:*-slim` image is labeled **PSF** (CPython), optionally noting its Debian layer is mixed. |
| `gitea/gitea` | **MIT** | |
| `golang` / `go` | **BSD-3-Clause** | |
| `nginx` | **BSD-2-Clause** | |
| `postgres` | **PostgreSQL License** (BSD/MIT-style) | |
| `redis` | **BSD-3-Clause** (≤7.2) · **RSALv2 + SSPLv1** (7.4–7.x) · **AGPLv3** (8.0+) | version-dependent — check the tag. RSALv2/SSPL are source-available, not OSI-free, but still permit commercial use. |
| `mysql` | **GPLv2** (+ FOSS exception) | |
| `mariadb` | **GPLv2** | |
| `grafana/grafana` | **AGPL-3.0** (≥ 8.0; Apache-2.0 before) | version-dependent — ≥8.0 is AGPL. |

## How to score it (V17 — graded 2/3/5)
1. List every third-party component: each `FROM` in `environment/**/Dockerfile*`, every `image:` in the
   compose, every service's pip deps, every vendored `*.whl`, and the app itself.
2. For each, find its license in the **top-level** `environment/NOTICE.md`.
3. **Score 5** — every third-party component has a correct license **in `environment/NOTICE.md`**.
4. **Score 3 (Non-Fail)** — a component is **not** attributed in the top-level `NOTICE.md` **but is credited
   elsewhere in the task files** (a nested `NOTICE`, a service `LICENSE`, a header). V17 softened this: a
   missing top-level entry is **no longer an automatic fail** if the license is disclosed somewhere in the
   bundle. (This reverses the old "only the top-level `NOTICE.md` can satisfy it" rule — that rule now only
   governs the **5 vs 3** line, not pass vs fail.)
5. **Score 2 (Fail)** — any of:
   - a third-party component is attributed **nowhere** in the task files (no license, anywhere); **or**
   - a stated license is **wrong / contradicts the table above** (a false attribution — e.g. busybox "BSD");
     a provenance pointer to a file the bundle does not ship is also a false statement; **or**
   - a third-party component **cannot be legally used for commercial purposes** (a non-commercial /
     no-commercial-use license — CC-BY-**NC**, PolyForm Noncommercial, Prosperity, a "Commons Clause"
     rider, "not for commercial use"). This is the **V17 new hard-fail condition** — check each component's
     actual license, not just that it is attributed.

`qc_selfcheck.py` `check_EN5` gates a wrong/misstated license as Tier A (Fail) and reports a merely
undocumented-in-NOTICE component as Tier B (the V17 score-3 Non-Fail — confirm whether it is credited
elsewhere before calling it a hard fail), and scans vendored-wheel METADATA + the NOTICE for non-commercial
licenses. `helpers/audit_facts.py` prints a per-image verdict under **EN5 WHEEL LICENSES** / base-image
rows (`LICENSE ok` / `MENTIONED but NO license` / `license '<x>' may be WRONG for <base> … VERIFY` /
`NOT MENTIONED`) — confirm a "may be WRONG" against this table (both tools' matches are approximate), then
score it.

## Calibration notes (re-read under V17)
A **wrong or missing** base-image/app license was scored **Tier A** under V13 (QC failed calibration cases 2
and 3; the case 3→9 fix — busybox relabeled GPL-2.0, python licensed PSF — flipped the dimension to PASS).
Under **V17** the mapping is finer: a **wrong** license stays a **Fail (2)**; a license present only in a
**nested/sibling** NOTICE (old case 2) is now a **Non-Fail (3)**, not a hard fail. Calibration case 7
(`w-estate/ssrf-imds-rawip`, a labeled PASS) ships the busybox-"BSD-3-Clause" mislabel — a **wrong** label,
so still a **Fail (2)** under V17 (the skill's documented dissent with QC; policy 6). Vendored wheels, pip
and npm deps: a **misstated** blanket is a Fail (2); an **undocumented** one is a score-3 Non-Fail unless
licensed nowhere. The old `references/calibration_log.md` predates V17 and tags these "EN4" — read those as
**EN5**, and against this 2/3/5 grading.
