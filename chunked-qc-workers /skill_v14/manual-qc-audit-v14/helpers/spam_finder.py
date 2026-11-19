#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
spam_finder.py  --  static FINDER for the SPAM CHECK (V14 dimension 21, Explanations).

Surfaces the task's explanation fields (difficulty_explanation, model_failure_reason, and any
operator/report explanation) and flags trivially-spammy ones (empty, too short, or highly
repetitive). The reader judges substance vs spam.
"""
import os, re, sys, json, io
def _read(p):
    try:
        return io.open(p, "r", encoding="utf-8", errors="replace").read()
    except Exception:
        return ""
def _repetitive(s):
    s = s.strip()
    if len(s) < 40:
        return False
    words = re.findall(r"\w+", s.lower())
    return bool(words) and len(set(words)) / len(words) < 0.3
def find(task_dir):
    fields, cands, deferred = [], [], []
    toml = _read(os.path.join(task_dir, "task.toml"))
    for key in ("difficulty_explanation", "model_failure_reason"):
        m = re.search(r'(?is)' + key + r'\s*=\s*("""|\'\'\'|")(.*?)\1', toml)
        if m:
            body = m.group(2).strip()
            fields.append({"field": key, "len": len(body)})
            if len(body) < 40:
                cands.append({"field": key, "why": f"{key} is very short ({len(body)} chars) — possible spam/filler"})
            elif _repetitive(body):
                cands.append({"field": key, "why": f"{key} is highly repetitive — possible spam"})
        elif key == "difficulty_explanation":
            cands.append({"field": key, "why": "difficulty_explanation missing from task.toml"})
        else:
            # model_failure_reason is a submission-form field; absence from task.toml is not a fail
            deferred.append(f"{key} not in task.toml — confirm it on the submission form (MANUAL)")
    return {"task_dir": os.path.abspath(task_dir),
            "checks": {"spam_check": {"label": "[Fail - Spam]", "fields": fields, "candidates": cands,
                       "deferred": deferred, "files_to_read": ["task.toml"],
                       "note": "reader judges whether each explanation is substantive (real reasoning) vs spam/filler/boilerplate."}}}
def _summary(r):
    c = r["checks"]["spam_check"]
    o = [f"SPAM FINDER — {r['task_dir']}", f"  explanation fields: {c['fields']}  candidates: {len(c['candidates'])}"]
    for x in c["candidates"]:
        o.append(f"     FAIL?  {x['field']}  — {x['why']}")
    return "\n".join(o)
def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: spam_finder.py <task_dir> [--json OUT]", file=sys.stderr); return 2
    r = find(argv[0])
    if "--json" in argv:
        json.dump(r, open(argv[argv.index("--json")+1], "w"), indent=2)
    print(_summary(r)); return 0
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
