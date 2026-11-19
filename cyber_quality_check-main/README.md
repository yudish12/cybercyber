# cyber_quality_check

Checks a Harbor task directory or `.zip` against 19 of the 21 dimensions in
`reference/QC_rubric_V11.csv` (ground truth: F1-F5, EN2-EN4, VU1-VU5, TR2-TR3,
EV1/EV2/EV5, RB1 -- Spam Check is excluded, since its explanation fields live
in the submitted form, not the task package; EN1 is excluded by request).
Every dimension resolves to
PASS or FAIL -- there is no manual/human-review verdict. Dimensions that are
inherently a judgment call (not reliably regex-checkable) are resolved by an
LLM judge call grounded in evidence gathered from the task's own files,
instead of being left for a person to eyeball.

## Setup

```
export ANTHROPIC_API_KEY=...
export ANTHROPIC_BASE_URL=https://api.anthropic.com   # optional, defaults to this
export CYBER_QC_MODEL=anthropic/claude-sonnet-5        # optional, this is the default
```

## Usage

```
python3 -m cyber_quality_check <task_dir_or_zip> [--json out.json]
```

Run from the repo root (the parent of `cyber_quality_check/`), or add the
repo root to `PYTHONPATH`.

## Testing

```
python3 -m pytest tests/ -q
```

`tests/` holds regression tests for every deterministic-logic bug found during
development against real Harbor task archives: a broken compose-file parser
that silently returned zero services, credential-detection regexes that
flagged `*_FILE` secret references and username fields, a shortcut-detector
regex that matched inside `os.environ`, and a pass@k trial-counting glob that
counted sibling metadata files (`config.json`, `lock.json`, ...) as trial
directories. Run this before trusting a change to any deterministic check.

## Verdicts

- `PASS`  -- check ran (deterministically or via LLM) and found no violation
- `FAIL`  -- check found a violation; `detail` cites the rubric's fail
  category or the LLM's chosen fail option
- `ERROR` -- the check itself crashed, or the LLM call failed / wasn't
  configured (missing `ANTHROPIC_API_KEY`) -- not a verdict on the task

## How each dimension is resolved

| Dimension | Method |
|---|---|
| F1, F2, F3, F5, EN3, TR2, EV5 | fully deterministic (file presence/parse/exec-bit, prefix regex, reward value, compose YAML, reward.json + run.log ground truth) |
| EN2, EN4, VU1, VU3 | deterministic fast-fail on clear violations; LLM judge for the remaining qualitative call when no violation is found statically |
| F4, TR3, VU2, VU4, VU5, EV1, EV2, RB1 | fully LLM-judged, grounded in file evidence gathered per dimension |

The LLM judge (`llm_judge.py`) loads the exact question text, description,
and scored answer options for a dimension from `reference/QC_rubric_V11.csv`,
sends them with the gathered evidence, and requires the model to pick one
answer option verbatim and score it -- never a free-form verdict disconnected
from the rubric's own wording. When evidence can't fully confirm a dimension
that normally needs a live boot or a human walkthrough (e.g. EN4's
replay-fails requirement), the judge is instructed to fail closed rather than
guess a pass, matching this rubric's own "report-judge must fail-close to 0"
philosophy (EN4).

## Known limitations

The litellm proxy route used here rejects `temperature` ("deprecated for
this model"), so LLM-judged dimensions that sit right at the fail-closed
boundary -- evidence that is close to but not quite sufficient to confirm a
pass, like EN4's live-boot-only properties -- can occasionally flip between
PASS and FAIL across runs on byte-identical evidence. This was observed
directly: 3 consecutive calls on the same task returned PASS, while one
earlier run on the same unchanged evidence returned FAIL. There is no API
parameter available on this route to eliminate it. Treat a single FAIL on
these dimensions as provisional and worth a rerun before acting on it;
a verdict that reproduces across repeated runs is real, a one-off flip is
not.

## Layout

```
cyber_quality_check/             (repo root)
  cyber_quality_check/           (importable package)
    cli.py / __main__.py         entrypoint, zip extraction, report printing
    runner.py                    orchestrates all 19 dimensions
    report.py                    result() dict shape, file-read helper
    compose_utils.py             docker-compose.yaml service-block parsing
    constants.py                 shared regexes and the vulnerability-class term list
    evidence.py                  evidence gatherers (file reads, route grep, pass@k sample)
    rubric_loader.py             parses reference/QC_rubric_V11.csv into per-dimension structs
    llm_client.py                minimal Anthropic Messages API client (stdlib only)
    llm_judge.py                 judge_dimension(): builds the rubric-grounded prompt, calls the LLM, parses the verdict
    checks/
      format_checks.py           F1, F2, F3, F5
      environment_checks.py      EN2, EN3, EN4
      vulnerability_checks.py    VU1, VU3
      trajectory_checks.py       TR2, TR3
      evaluation_checks.py       EV5
      llm_checks.py              F4, VU2, VU4, VU5, EV1, EV2, RB1
    reference/
      QC_rubric_V11.csv          bundled copy of the ground-truth rubric
```
