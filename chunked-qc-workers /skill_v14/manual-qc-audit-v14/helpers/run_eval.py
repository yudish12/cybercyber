#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_eval.py  --  the AUTO-RUNNER for the chunked QC eval workers.

For each requested dimension it: runs the FINDER, inlines the decision-relevant files into
the fenced READER prompt (with line numbers so the reader can cite file:line), calls the
LLM to execute the reader, parses the verdict JSON, and aggregates a scorecard. The reader
is fenced by construction: it sees ONLY this task's files + its own de-anecdoted rulebook,
so it cannot compare to another task.

LLM call uses the Anthropic Messages API via stdlib urllib (no pip deps), reading
ANTHROPIC_API_KEY and ANTHROPIC_BASE_URL (same as the report judge), model from
ANTHROPIC_MODEL or --model.

  python3 -I run_eval.py <task_dir> [--dim vu3,en4,...|all] [--model M] [--dry-run] [--json OUT]

--dry-run assembles and prints each reader prompt (with token estimate) and makes NO API
call -- offline-testable. Without a key, --dry-run is forced.
"""
import os, re, sys, json, io, importlib, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

DIMS = ["format", "env", "vu1", "vu2", "vu3", "vu4", "vu5", "en3", "en4",
        "traj", "trial", "ev2", "eval", "rb1", "spam", "custom"]
_TEXT_EXT = (".py", ".php", ".sh", ".ts", ".tsx", ".js", ".jsx", ".md", ".toml", ".yaml",
             ".yml", ".json", ".conf", ".cfg", ".ini", ".sql", ".env", ".txt")
_PER_FILE_CAP = 16000      # chars per inlined file
_TOTAL_CAP = 160000        # chars of inlined files per reader prompt


def _read(p, cap=None):
    try:
        with io.open(p, "r", encoding="utf-8", errors="replace") as f:
            t = f.read()
    except Exception as e:
        return f"<<unreadable: {e}>>"
    return t if cap is None else t[:cap]


def _number(text):
    return "\n".join(f"{i:>5}\t{ln}" for i, ln in enumerate(text.splitlines(), 1))


def assemble_prompt(dim, task_dir):
    """Run the finder + reader packet; inline the files; return (prompt, meta)."""
    reader = importlib.import_module(f"{dim}_reader")
    pkt = reader.build_reader_packet(task_dir)
    parts = [pkt["rulebook"], "", "## This task's class / context",
             json.dumps({k: v for k, v in pkt.items()
                         if k in ("class", "rubric", "notice", "reward_setters",
                                  "distinct_surface_count", "one_trick_candidate", "discoverability")},
                        indent=2, default=str),
             "", "## Finder leads (candidates to CONFIRM or CLEAR by reading)",
             json.dumps(pkt.get("finder_candidates") or pkt.get("finder_signals")
                        or pkt.get("multi_sibling_groups") or {}, indent=2, default=str)[:12000],
             "", "## Files — OPEN AND READ these (line-numbered). Cite file:line in every verdict."]
    total, included, skipped = 0, [], []
    files = pkt.get("files_to_open", {})
    # files_to_open may be {path: {...}} or a list
    paths = list(files.keys()) if isinstance(files, dict) else list(files)
    for rel in paths:
        ext = os.path.splitext(rel)[1].lower()
        base = os.path.basename(rel)
        is_text = ext in _TEXT_EXT or base.startswith(("Dockerfile", ".env"))
        full = os.path.join(task_dir, rel)
        if not is_text or not os.path.isfile(full):
            skipped.append(rel); continue
        if total >= _TOTAL_CAP:
            skipped.append(rel); continue
        body = _read(full, _PER_FILE_CAP)
        total += len(body)
        included.append(rel)
        parts.append(f"\n----- FILE: {rel} -----\n{_number(body)}")
    if skipped:
        parts.append("\n## Not inlined (binary/capped — use the finder facts above, or note as open_item): "
                     + ", ".join(skipped[:40]))
    parts.append("\n## Now return ONLY the verdict JSON specified in the output contract above.")
    prompt = "\n".join(parts)
    return prompt, {"dim": dim, "included": included, "skipped": skipped,
                    "approx_tokens": len(prompt) // 4}


def call_llm(prompt, model):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    base = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    url = base + "/v1/messages"
    payload = json.dumps({
        "model": model, "max_tokens": 2000,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(url, data=payload, headers={
        "content-type": "application/json", "x-api-key": key,
        "anthropic-version": "2023-06-01"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = json.loads(r.read())
    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    return text


def _extract_json(text):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {"_parse_error": "no JSON found", "_raw": text[:500]}
    try:
        return json.loads(m.group(0))
    except Exception as e:
        return {"_parse_error": str(e), "_raw": text[:500]}


def run(task_dir, dims, model, dry_run):
    results = {}
    for dim in dims:
        prompt, meta = assemble_prompt(dim, task_dir)
        if dry_run:
            results[dim] = {"dry_run": True, **meta}
            continue
        try:
            verdict = _extract_json(call_llm(prompt, model))
        except Exception as e:
            verdict = {"_error": str(e)}
        results[dim] = {"verdict": verdict, **meta}
    return results


def _scorecard(results):
    rows = []
    worst = 5
    if all(r.get("dry_run") for r in results.values()):
        rows = [f"  {d.upper():4}  DRY-RUN  files={r['included'] and len(r['included'])} "
                f"skipped={len(r['skipped'])} ~{r['approx_tokens']}tok" for d, r in results.items()]
        return "DRY-RUN — prompts assembled, no LLM call\n" + "\n".join(rows)
    # FAIL-CLOSED (calibrated to cyber_quality_check): a dimension is READY only when it is a
    # confirmed PASS at max score (5). Any FAIL, any unconfirmed state (REVIEW/LIVE/DEFERRED),
    # a score below 5 (incl. a score-3 Non-Fail), or an error BLOCKS the ship.
    blockers = 0
    for dim, r in results.items():
        if r.get("dry_run"):
            rows.append(f"  {dim.upper():7} DRY-RUN  files={len(r['included'])} skipped={len(r['skipped'])} ~{r['approx_tokens']}tok")
            continue
        v = r.get("verdict", {})
        score = v.get(f"{dim}_score") or v.get("score")
        subs = v.get("verdicts", [])
        fails = [x.get("sub_label") or x.get("dimension") for x in subs if x.get("verdict") == "FAIL"]
        unconfirmed = [x.get("sub_label") or x.get("dimension") for x in subs if x.get("verdict") in ("REVIEW", "LIVE", "DEFERRED")]
        err = v.get("_error") or v.get("_parse_error")
        ready = (score == 5) and not fails and not unconfirmed and not err
        if not ready:
            blockers += 1
        tag = "FAIL" if fails else ("UNCONF" if unconfirmed else ("ERR" if err else "PASS"))
        detail = "; ".join([f for f in fails if f] or [u + "?" for u in unconfirmed if u])[:80]
        rows.append(f"  {dim.upper():7} {tag:7} score={score}  {detail}")
    head = "SHIP" if blockers == 0 else f"NOT READY ({blockers} dim(s) failing or unconfirmed — fail-closed)"
    return f"SCORECARD — {head}\n" + "\n".join(rows)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: run_eval.py <task_dir> [--dim vu3,en4|all] [--model M] [--dry-run] [--json OUT]", file=sys.stderr)
        return 2
    task_dir = argv[0]
    dsel = "all"
    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
    dry = "--dry-run" in argv
    if "--dim" in argv:
        dsel = argv[argv.index("--dim") + 1]
    if "--model" in argv:
        model = argv[argv.index("--model") + 1]
    dims = DIMS if dsel == "all" else [d.strip().lower() for d in dsel.split(",") if d.strip()]
    bad = [d for d in dims if d not in DIMS]
    if bad:
        print(f"unknown dims: {bad}; valid: {DIMS}", file=sys.stderr); return 2
    # --emit DIR: write each group's full reader prompt to a file (no API key needed).
    # In Claude Code, hand each file to a subagent (or read it yourself) to render the verdict.
    if "--emit" in argv:
        outdir = argv[argv.index("--emit") + 1]
        os.makedirs(outdir, exist_ok=True)
        print(f"NO-API emit — reader prompts written to {outdir}/ (feed each to a subagent):")
        for dim in dims:
            prompt, meta = assemble_prompt(dim, task_dir)
            p = os.path.join(outdir, f"{dim}_reader_prompt.txt")
            with open(p, "w") as f:
                f.write(prompt)
            print(f"  {dim:7} {p}  (~{meta['approx_tokens']} tok, {len(meta['included'])} files inlined)")
        return 0
    if not dry and not os.environ.get("ANTHROPIC_API_KEY"):
        print("[no ANTHROPIC_API_KEY -> forcing --dry-run]", file=sys.stderr)
        dry = True
    results = run(task_dir, dims, model, dry)
    print(_scorecard(results))
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(results, f, indent=2, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
