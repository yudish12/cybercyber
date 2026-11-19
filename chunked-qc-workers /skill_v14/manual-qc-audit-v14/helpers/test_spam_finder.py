#!/usr/bin/env python3
"""TDD tests for spam_finder.py."""
import os, sys, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spam_finder
def _w(p, c):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(c)
P = F = 0
def ck(n, c):
    global P, F; P += c; F += (not c); print(f"  {'ok  ' if c else 'FAIL'} {n}")
def main():
    dirs = []
    try:
        g = tempfile.mkdtemp(); dirs.append(g)
        _w(os.path.join(g, "task/task.toml"),
           'difficulty_explanation = """The agent must reach the report endpoint and inject a crafted expression that the document engine evaluates, deriving the scored value from the ledger account files."""\nmodel_failure_reason = """The model stalls at the stateful ticket preparation step and never reaches the document engine."""\n')
        gr = spam_finder.find(os.path.join(g, "task"))
        ck("GOOD: substantive explanations -> no candidate", len(gr["checks"]["spam_check"]["candidates"]) == 0)
        b = tempfile.mkdtemp(); dirs.append(b)
        _w(os.path.join(b, "task/task.toml"), 'difficulty_explanation = """hard hard hard hard hard hard hard hard hard hard hard hard"""\n')
        br = spam_finder.find(os.path.join(b, "task"))
        ck("BAD: repetitive + missing field -> candidates", len(br["checks"]["spam_check"]["candidates"]) >= 1)
        print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)
if __name__ == "__main__":
    main()
