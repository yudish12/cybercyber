#!/usr/bin/env python3
"""Re-run the labelled corpus and report drift.

The labels are the security team's good / bad / very-bad ratings supplied 2026-09-18.
They are NOT a realism ground truth -- see references/calibration.md. This script
exists to detect regression in what the scanner finds, not to fit the labels.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS_DEFAULT = os.path.expanduser("~/Cybersecurity OTS/Tasks to audit")

# task id -> (security label, task name as shipped in task.toml)
LABELS = {
    "6aa0578411b328360a727683": ("good", "publishhub/idor"),
    "6aa0578411b328360a72768a": ("good", "shopops/path-traversal"),
    "6aa4219af13d451666f8427b": ("good", "joomla-estate/config-leak"),
    "6aa0578411b328360a727684": ("bad", "publishhub/mass-assignment"),
    "6aa0578411b328360a727686": ("bad", "publishhub/sqli"),
    "6aa0578411b328360a727689": ("bad", "shopops/mass-assignment"),
    "6aa0578411b328360a72768c": ("bad", "shopops/ssrf"),
    "6aa4219af13d451666f8427c": ("bad", "couchdb-estate/privesc"),
    "6aa4219af13d451666f8427e": ("bad", "apisix-estate/aclbypass"),
    "6aa4219af13d451666f8427f": ("bad", "httpd-estate/task_1_path_traversal"),
    "6aa4219af13d451666f84280": ("bad", "httpd-estate/task_2_path_traversal"),
}

# What the scanner produced when references/calibration.md was written.
BASELINE = {
    "6aa0578411b328360a727683": 4, "6aa0578411b328360a72768a": 5,
    "6aa4219af13d451666f8427b": 0, "6aa0578411b328360a727684": 3,
    "6aa0578411b328360a727686": 4, "6aa0578411b328360a727689": 6,
    "6aa0578411b328360a72768c": 3, "6aa4219af13d451666f8427c": 2,
    "6aa4219af13d451666f8427e": 0, "6aa4219af13d451666f8427f": 4,
    "6aa4219af13d451666f84280": 3,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=CORPUS_DEFAULT)
    a = ap.parse_args()

    rows, drift, missing = [], [], []
    for tid, (label, name) in sorted(LABELS.items(), key=lambda kv: kv[1][0]):
        tgz = os.path.join(a.corpus, f"{tid}_task.tar.gz")
        if not os.path.exists(tgz):
            missing.append(tid)
            continue
        out = subprocess.run(
            [sys.executable, os.path.join(HERE, "realism_checks.py"), tgz,
             "--out", "/dev/stdout", "--quiet"],
            capture_output=True, text=True)
        try:
            pack = json.loads(out.stdout)
        except json.JSONDecodeError:
            rows.append((label, name, "PARSE-FAIL", "", ""))
            continue
        got = pack["verdict"]["counts"]["on_path_blockers"]
        base = BASELINE.get(tid)
        if base is not None and got != base:
            drift.append(f"{name}: on-path blockers {base} -> {got}")
        rows.append((label, pack["task_name"], pack["verdict"]["disposition"],
                     got, len(pack["findings"])))

    w = max((len(r[1]) for r in rows), default=20)
    print(f"{'label':5}  {'task':{w}}  {'disposition':34}  on-path  findings")
    for label, name, dis, on, total in rows:
        print(f"{label:5}  {name:{w}}  {str(dis):34}  {str(on):>7}  {total}")

    if missing:
        print(f"\nnot present in {a.corpus}: {', '.join(missing)}")
    if drift:
        print("\nDRIFT vs the baseline recorded in references/calibration.md:")
        for d in drift:
            print(f"  {d}")
        print("Update BASELINE and calibration.md if the change is intended.")
        return 1
    print("\nno drift vs baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
