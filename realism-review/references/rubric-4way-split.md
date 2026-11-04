# The four-way split — kept for if granularity is wanted later

The live spec ships **one** dimension, `Application Realism - Believable App & Business
Logic`, with four graded options. This file records the four-dimension form it replaces,
and what is lost by merging.

## Why one dimension works here

The spec's CSV format allows several answer options per dimension, each with its own
error category — the precedent is `Metadata Accuracy - CWE / Vulnerability Kind
Accuracy`, which ships three fail options plus a score-3 `[Non-Fail]`. So the merged
dimension still records *which* realism failure fired on the auditor form:

| Option | Score | Was dimension |
|---|---|---|
| `[Fail - Unrealistic or Puzzle-Built Application]` | 2 | 24 |
| `[Fail - Benchmark Scaffolding Presented as Application Features]` | 2 | 25 |
| `[Fail - Unintended Exploitable Weakness]` | 2 | 26 |
| `[Non-Fail - Thin Disclosure Record]` | 3 | 27 |
| believable | 5 | — |

The disclosure-record clause became a **score-3 `[Non-Fail]`** rather than a fail. That
matches how security actually treated it: they raised it on two of the three bundles they
reviewed in depth and rated both of those bundles good anyway. As a fail clause it would
sink almost every bundle in the corpus on a point nobody has treated as blocking.

## What the merge costs

1. **One score, four causes.** A bundle whose app is believable but whose chain is pure
   scaffolding scores 2/5 on "Application Realism", which reads as a realism problem
   rather than a scaffolding problem. The error category carries the distinction; the
   number does not. Cite the fired option by name in feedback, never just the score.
2. **No partial credit across clauses.** A bundle can only fail once, so a bundle failing
   three clauses looks the same as one failing one. Enumerate every fired clause in the
   justification.
3. **Trend data is coarser.** Across 1000 tasks, four dimensions would show which
   authoring habit is most common. One dimension plus error categories can still answer
   that, but only if the categories are recorded consistently.

## If you split it later

Restore `_id` 24–27 with these titles, questions and fail categories. The option text is
already written as four self-contained blocks in
`~/Cybersecurity OTS/QC Spec/application-realism-dimension.csv`; each becomes that
dimension's sole fail option.

| `_id` | Title | Question |
|---|---|---|
| 24 | Application Realism - Believable App & Business Logic | Is the application believable as real software, with the planted vulnerability its only unrealistic element? |
| 25 | Application Realism - Feature Justification (No Benchmark Scaffolding) | Does every feature, gate and field the exploit chain touches have a business reason independent of the grader? |
| 26 | Application Realism - Unintended Vulnerability Sweep | Is the planted flaw the only exploitable weakness in the bundle? |
| 27 | Application Realism - Security Evidence Quality | When protected data is disclosed, does the application record an investigable security event? |

The argument for splitting, if it is ever needed: `couchdb-estate/privesc` and
`httpd-estate/task_1_path_traversal` pass every clause of dimension 24 as originally
drafted and are still not shippable, because their problem is entirely dimension 25. That
evidence is what forced the scaffolding clause into the merged dimension — it is the
clause most likely to be dropped by an auditor reading quickly, and the one that explains
six of the eight bad-labelled bundles our own gate called mechanical fixes.
