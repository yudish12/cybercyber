#!/usr/bin/env python3
"""
TDD tests for ev2_finder.py — static FINDER layer of the EV2 eval
(Evaluation: Intended-Path-Only Credit) — the keystone credit-integrity worker.

Design: trace every reward=1 setter to its weakest guard.
  - [Fail - Exploit-Free Credit]: reward=1 gated only on submission==marker (or on a
    leftover secret / out-of-band env/file read / provided creds), with NO proof of the
    intended exploit (no technique/audit/proof gate).
  - [Fail - Verifier Contamination]: the grader invokes the reference solver or writes
    the submission file itself.
  - Shortcut-win on shipped trials is pass@k/LIVE (noted, not static).
Bias to flag; the reader traces the full chain and decides.

Run:  python3 -I test_ev2_finder.py
"""
import os, sys, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ev2_finder  # noqa: E402


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))


def build_good(root):
    t = os.path.join(root, "task")
    _w(os.path.join(t, "tests", "test.sh"),
       "#!/bin/bash\nexec python3 -I /tests/behavior/verify.py\n")
    _w(os.path.join(t, "tests", "behavior", "verify.py"), '''
        def grade(audit, submission):
            proof_valid, reason = validate_behavior_proof(details, audit, submission)
            reward = 1 if proof_valid else 0      # gated on the protected audit chain
            atomic('reward.json', '{"reward":%d}' % reward)
            return reward
    ''')
    return t


def build_exploit_free(root):
    t = os.path.join(root, "task")
    # reward purely on submission == a leftover secret file; no exploit proof
    _w(os.path.join(t, "tests", "test.sh"), '''
        #!/bin/bash
        expected=$(cat /secret/flag.txt)
        sub=$(cat /logs/verifier/submission.txt)
        if [ "$sub" = "$expected" ]; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi
    ''')
    return t


def build_contaminated(root):
    t = os.path.join(root, "task")
    _w(os.path.join(t, "tests", "test.sh"), '''
        #!/bin/bash
        bash /solution/solve.sh > /logs/verifier/submission.txt
        python3 /tests/behavior/verify.py
    ''')
    return t


def build_oob(root):
    t = os.path.join(root, "task")
    _w(os.path.join(t, "tests", "behavior", "verify.py"), '''
        import os
        def grade(submission):
            secret = os.environ["SCORED_SECRET"]       # out-of-band read of the scored value
            reward = 1 if submission == secret else 0
            return reward
    ''')
    return t


PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def sig(r, key):
    return r["checks"][key]["candidates"]


def main():
    dirs = []
    try:
        g = tempfile.mkdtemp(); dirs.append(g); gr = ev2_finder.find(build_good(g))
        e = tempfile.mkdtemp(); dirs.append(e); er = ev2_finder.find(build_exploit_free(e))
        c = tempfile.mkdtemp(); dirs.append(c); cr = ev2_finder.find(build_contaminated(c))
        o = tempfile.mkdtemp(); dirs.append(o); orr = ev2_finder.find(build_oob(o))

        def anyfile(items, needle):
            return any(needle in str(it.get("file", "")) for it in items)

        # reward setters discovered
        check("GOOD: reward setter file discovered",
              any("verify.py" in f for f in gr["reward_setters"]))

        # 1. GOOD: proof-gated reward -> NO exploit-free candidate
        check("GOOD: proof-gated reward -> no exploit-free candidate",
              len(sig(gr, "exploit_free_credit")) == 0)

        # 2. exploit-free: submission==leftover-secret -> candidate
        check("exploit-free: submission==secret with no proof -> candidate",
              anyfile(sig(er, "exploit_free_credit"), "test.sh"))

        # 3. out-of-band env read of the scored value -> candidate
        check("OOB: os.environ scored secret -> exploit-free candidate",
              anyfile(sig(orr, "exploit_free_credit"), "verify.py"))

        # 4. verifier contamination: solver writes submission -> candidate
        check("contamination: solver invoked / writes submission -> candidate",
              anyfile(sig(cr, "verifier_contamination"), "test.sh"))

        # 5. GOOD: not flagged as contaminated
        check("GOOD: no contamination candidate",
              len(sig(gr, "verifier_contamination")) == 0)

        # 6. shortcut-win noted as LIVE/pass@k
        check("shortcut-win surfaced as a LIVE/pass@k item",
              len(gr["checks"]["shortcut_win"]["live_items"]) >= 1)

        # 7. files_to_read populated
        check("files_to_read includes a reward setter",
              any("test.sh" in f or "verify.py" in f
                  for f in gr["checks"]["exploit_free_credit"]["files_to_read"]))

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
