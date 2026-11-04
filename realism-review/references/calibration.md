# Calibration — what this scanner is measured to do

**Corpus:** the eleven bundles present in `~/Cybersecurity OTS/Tasks to audit/` that carry
a security label from 2026-09-18. Four labelled bundles are not on disk
(`...685`, `...687`, `...68b` — all *very bad* — and `...84281`, unlabelled);
`...688` (*very bad*) is under `QC Pass - Task/`.

**The labels are not a realism ground truth.** Only three of the fifteen have a written
security review (`cyber-qh-feedback.md`). The provenance of the other twelve labels is
unknown, and the buckets compress away concerns the written reviews do list. Read this
file as "what does the scanner find", not "how accurate is the predictor".

## Measured output

| Label | Task | Disposition | On-path blockers | Findings |
|---|---|---|---|---|
| good | `publishhub/idor` | needs substantial rework | 4 | 12 |
| good | `shopops/path-traversal` | needs substantial rework | 5 | 13 |
| good | `joomla-estate/config-leak` | **no mechanical realism lead** | 0 | 4 |
| bad | `publishhub/mass-assignment` | needs substantial rework | 3 | 8 |
| bad | `publishhub/sqli` | needs substantial rework | 4 | 10 |
| bad | `shopops/mass-assignment` | needs substantial rework | 6 | 13 |
| bad | `shopops/ssrf` | needs substantial rework | 3 | 9 |
| bad | `couchdb-estate/privesc` | needs substantial rework | 2 | 4 |
| bad | `apisix-estate/aclbypass` | good foundation, fix list attached | 0 | 3 |
| bad | `httpd-estate/task_1_path_traversal` | needs substantial rework | 4 | 7 |
| bad | `httpd-estate/task_2_path_traversal` | needs substantial rework | 3 | 4 |

Ten of eleven are flagged. The one bundle that comes back clean —
`joomla-estate/config-leak` — is also the only one in the corpus whose review asked for
no redesign. That is a single data point, not a validated pass.

## What it recovers from the thirteen written concerns

| # | Written concern | Check | Recovered |
|---|---|---|---|
| 1 | IDOR: workspace has no join/leave/switch process | RC8.2 | yes |
| 2 | IDOR: workspace field not visible in profile responses | RC8.1 | **partial** — see limits |
| 3 | IDOR: audit should record user, workspace, draft, time | RC7.1 | yes |
| 4 | PathTrav: export workflow stores a filename and writes no file | RC1.1, RC1.2 | yes |
| 5 | PathTrav: export ownership not enforced on list/download | RC6.2 | **no** — the unscoped read is a collection `SELECT` with no path parameter |
| 6 | PathTrav: server trusts a caller-supplied storage path | — | n/a, this is the intended flaw |
| 7 | PathTrav: final path not confined | RC4.2 | partial |
| 8 | PathTrav: fallback verifier credential in source + diag returning secrets | RC5.1, RC5.2 | yes |
| 9 | SSRF: internal status returns an unauth token beside a fake `svc_flag` | RC3.1 | yes |
| 10 | SSRF: egress filter too narrowly tailored | RC4.1 | n/a on the shipped bundle — it has **no** filter at all, caught by RC6.4 as the intended sink |
| 11 | SSRF: redirect endpoint needs a legitimate purpose | RC2.1 | **no** — the shipped version states a purpose in its docstring and is listed in the API index; whether a stated purpose is genuine is a judgment |
| 12 | SSRF: diagnostics expose the answer key | RC5.2 | yes |
| 13 | SSRF: should preserve stronger request evidence | RC7.1 | yes |

Eight of thirteen recovered outright, three partial, two not. The two misses are both
cases where the check would need to judge intent, not read structure.

## Findings security has not raised, that the scanner adds

All in bundles that passed the 23-dimension gate:

- `shopops/path-traversal` `web/app.py:542` — `update_user` interpolates into SQL. Not in
  any review or findings file.
- `shopops/path-traversal` `web/app.py:283` — `get_order` selects by id with no ownership
  predicate and returns `ORDER_FLAG=`, directly above a scoped sibling.
- `shopops/path-traversal` `web/app.py:513` — `allowed_columns` accepts `is_admin`,
  `username`, `api_key`. The SSRF sibling fixed this to three fields; the fix never
  propagated.
- `shopops/path-traversal` `web/app.py:375` — `test_webhook` fetches any URL with no
  egress policy.
- `publishhub/idor` `web/app.py:617` — `/api/import-url` is a live SSRF to
  `moderation:8081/secret`, in the bundle rated "closest to ready".
- `shopops/ssrf` `web/app.py:528` — `update_user` interpolates into SQL here too.

## Known limits

- **It does not reproduce the good / bad / very-bad bucketing, and does not try to.**
  The two bundles labelled good that flag here flag for concerns their own reviews list.
- **`apisix-estate/aclbypass` is an unexplained miss** at 0 on-path blockers. Whatever
  made it bad is not encoded. Do not read a clean result on a gateway-wrapper bundle as
  meaningful until this is understood.
- **RC8.1 asks "is this field returned anywhere the caller can reach", not "is it
  returned by the object's own canonical read endpoint".** In `publishhub/idor`
  `workspace` does appear in a caller-scoped `SELECT * FROM users` inside
  `/api/reports/author-activity`, so RC8.1 stays quiet while RC8.2 fires. Security's
  narrower point — the *profile* response does not show it — is for the judgment pass.
- **Python/Flask and `http.server` only.** A Go, Node or Java app parses as zero routes.
  The scanner reports `routes=0` and says a zero-route result does not clear the bundle;
  the selftest pins that wording.
- **RC2 cannot tell a genuine purpose from a stated one.** An endpoint with a plausible
  docstring and an index entry passes. This is why SKILL.md requires narrating every
  on-path step by hand.

## Re-running

```bash
python3 calibrate.py                 # corpus, with drift detection against the table above
python3 calibrate.py --corpus <dir>  # elsewhere
python3 selftest.py                  # 21 data-free cases, no corpus needed
```

`calibrate.py` exits non-zero on drift. Update its `BASELINE` and this table together
when a change is intended.
