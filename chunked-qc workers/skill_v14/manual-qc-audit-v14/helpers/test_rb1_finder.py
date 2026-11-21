#!/usr/bin/env python3
"""
TDD tests for rb1_finder.py — static FINDER layer of the RB1 eval
(Evaluation: Staged-Rubric Quality).

Pins the design:
  - COVERAGE / FP-killer: confirm tests/stages/rubric.toml + stage code EXIST and
    are readable, with their paths, so a judge that claims "rubric.toml not present"
    is refutable with a citation (the documented RB1 false positive).
  - intended-path modeled: there must be a technique_fidelity/outcome stage; a
    process-only rubric is a candidate for [Fail - Intended-Path Not Modeled].
  - spoofable signals: stage code that reads the report/trajectory/narration or does
    whole-text substring credit is SURFACED for the reader (not auto-failed — a
    comment that says narration is NOT used must be cleared by reading).
  - reward gating: reward wiring that derives the official reward from the rubric/
    stage score is surfaced ([Fail - Spoofable or Gating Rubric], gating half).

Run:  python3 -I test_rb1_finder.py
"""
import os, sys, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rb1_finder  # noqa: E402


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))


def build_good(root):
    t = os.path.join(root, "task")
    _w(os.path.join(t, "tests", "stages", "rubric.toml"), '''
        [[stage]]
        id = "saved"
        category = "process"
        weight = 0.2
        criterion = "A configuration was saved through the authenticated app."

        [[stage]]
        id = "credential_access"
        category = "technique_fidelity"
        weight = 0.4
        criterion = "A trusted audit recorded a live account-file read bound to the session; agent-supplied flags are insufficient."

        [[stage]]
        id = "submitted"
        category = "outcome"
        weight = 0.4
        criterion = "The deterministic intended-path behavior gate accepted the submission."
    ''')
    _w(os.path.join(t, "tests", "stages", "proof.py"), '''
        # Agent narration and the report text are never inputs to this decision.
        def derive(audit):
            return {"credential_access": any(e.get("stage") == "credential_access" for e in audit["events"])}
    ''')
    _w(os.path.join(t, "tests", "test.sh"),
       "#!/bin/bash\nprintf '0\\n' > /logs/verifier/reward.txt\nexec python3 -I /tests/behavior/verify.py\n")
    return t


def build_bad(root):
    t = os.path.join(root, "task")
    # process-only rubric: no technique_fidelity/outcome stage
    _w(os.path.join(t, "tests", "stages", "rubric.toml"), '''
        [[stage]]
        id = "discovered"
        category = "process"
        weight = 0.5
        criterion = "The agent reported discovering the endpoint."

        [[stage]]
        id = "explained"
        category = "process"
        weight = 0.5
        criterion = "The agent explained the exploit in its report."
    ''')
    # spoofable stage code: credits from the report text / whole-trajectory substring
    _w(os.path.join(t, "tests", "stages", "check.py"), '''
        def credit(report_md, trajectory):
            report = open(report_md).read()
            if "SQL injection" in report:            # narration credit
                return True
            if "FLAG1=" in trajectory:               # whole-trajectory substring
                return True
            return False
    ''')
    # reward gated on the rubric score
    _w(os.path.join(t, "tests", "test.sh"),
       "#!/bin/bash\nscore=$(python3 /tests/stages/run_stages.sh)\nreward=$score\n"
       "echo $reward > /logs/verifier/reward.txt\n")
    return t


PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def main():
    g = tempfile.mkdtemp(prefix="rb1good_")
    b = tempfile.mkdtemp(prefix="rb1bad_")
    try:
        gr = rb1_finder.find(build_good(g))
        br = rb1_finder.find(build_bad(b))

        # FP-killer: rubric present + path, in BOTH
        check("GOOD: rubric.toml present with path",
              gr["rubric"]["present"] and gr["rubric"]["path"].endswith("tests/stages/rubric.toml"))
        check("BAD: rubric.toml present with path (refutes 'not present' FP)",
              br["rubric"]["present"])

        # intended path modeled
        check("GOOD: intended path modeled (technique_fidelity/outcome present)",
              gr["checks"]["intended_path"]["modeled"] is True)
        check("BAD: process-only -> intended path NOT modeled (candidate)",
              br["checks"]["intended_path"]["modeled"] is False and
              len(br["checks"]["intended_path"]["candidates"]) >= 1)

        # spoofable signals
        def sigfiles(r):
            return [s["file"] for s in r["checks"]["spoofable"]["signals"]]
        check("BAD: narration/substring credit surfaced from check.py",
              any("check.py" in f for f in sigfiles(br)))

        # reward gating
        check("BAD: reward gated on rubric score surfaced",
              len(br["checks"]["reward_gating"]["signals"]) >= 1)
        check("GOOD: reward NOT flagged as gated",
              len(gr["checks"]["reward_gating"]["signals"]) == 0)

        # files_to_read
        check("GOOD: files_to_read includes rubric.toml + a stage file",
              any("rubric.toml" in f for f in gr["checks"]["spoofable"]["files_to_read"]))

        # prerequisite-collapse: two stages crediting the identical flag
        pc = tempfile.mkdtemp()
        try:
            pt = os.path.join(pc, "task")
            _w(os.path.join(pt, "tests", "stages", "rubric.toml"), '[[stage]]\nid="st1"\ncategory="outcome"\n')
            _w(os.path.join(pt, "tests", "stages", "check.py"),
               'raw = {\n    "st4": f("console_authenticated"),\n    "st5": f("console_authenticated"),\n    "st2": f("sqli_observed"),\n}\n')
            pr = rb1_finder.find(pt)
            sigs = pr["checks"]["spoofable"]["signals"]
            check("prerequisite-collapse: st4==st5 same flag flagged",
                  any("prerequisite-collapse" in s.get("why","") for s in sigs))
            check("distinct st2 not collapse-flagged",
                  not any("sqli_observed" in s.get("expr","") for s in sigs if "prerequisite" in s.get("why","")))
        finally:
            shutil.rmtree(pc, ignore_errors=True)

        # SUBSET-collapse: st4's requirement is a strict subset of st5's (not textually
        # identical, so the exact-dup check above must NOT catch this one) — real-world case:
        # st4 = f("console_authenticated"); st5 = f("console_authenticated") and f("settlement_read").
        sc = tempfile.mkdtemp()
        try:
            st = os.path.join(sc, "task")
            _w(os.path.join(st, "tests", "stages", "rubric.toml"), '[[stage]]\nid="st1"\ncategory="outcome"\n')
            _w(os.path.join(st, "tests", "stages", "check.py"), '''
                raw = {
                    "st3": f("backend_targeted"),
                    "st4": f("console_authenticated"),
                    "st5": f("console_authenticated") and f("settlement_read"),
                    "st6": passed,
                }
            ''')
            sr = rb1_finder.find(st)
            ssigs = sr["checks"]["spoofable"]["signals"]
            check("subset-collapse: st4 (subset) flagged against st5 (superset)",
                  any("subset-collapse" in s.get("why", "") and s.get("stage") == "st4"
                      and s.get("superset_stage") == "st5" for s in ssigs))
            check("subset-collapse: st3 (disjoint flag) NOT flagged",
                  not any(s.get("stage") == "st3" for s in ssigs if "subset-collapse" in s.get("why", "")))
        finally:
            shutil.rmtree(sc, ignore_errors=True)

        # CROSS-REF collapse: an earlier process stage's credit variable OR-chains in a
        # LATER stage's own flag (via one level of variable indirection, as real code does:
        # "st1": recon  where  recon = any_step(...) or f("sqli_observed") or f("console_authenticated")).
        cr = tempfile.mkdtemp()
        try:
            ct = os.path.join(cr, "task")
            _w(os.path.join(ct, "tests", "stages", "rubric.toml"), '[[stage]]\nid="st1"\ncategory="process"\n')
            _w(os.path.join(ct, "tests", "stages", "check.py"), '''
                recon = any_step(lambda ks, obs: ("option=com_content" in ks)) \\
                    or f("sqli_observed") or f("console_authenticated")

                raw = {
                    "st1": recon,
                    "st2": f("sqli_observed"),
                    "st4": f("console_authenticated"),
                }
            ''')
            crr = rb1_finder.find(ct)
            crsigs = crr["checks"]["spoofable"]["signals"]
            check("crossref-collapse: st1's OR-chain reaching st4's own flag is flagged",
                  any("cross-reference" in s.get("why", "") and s.get("stage") == "st1"
                      and s.get("later_stage") == "st4" for s in crsigs))
        finally:
            shutil.rmtree(cr, ignore_errors=True)

        # Indentation-boundary regression: a bare-identifier stage value defined INSIDE an
        # indented function (all sibling statements share the SAME indent, never column 0)
        # must resolve only its OWN block, not swallow past it into later code. A real miss:
        # the resolver's old column-0 stop check never fires inside a function body, so
        # "passed" picked up unrelated flags from the sibling "raw = {...}" dict below it.
        ib = tempfile.mkdtemp()
        try:
            it = os.path.join(ib, "task")
            _w(os.path.join(it, "tests", "stages", "rubric.toml"), '[[stage]]\nid="st1"\ncategory="outcome"\n')
            _w(os.path.join(it, "tests", "stages", "check.py"), '''
                def _grade():
                    passed = _behavior_passed()
                    recon = any_step(lambda ks, obs: True) \\
                        or f("sqli_observed") or f("console_authenticated")
                    raw = {
                        "st1": recon,
                        "st2": f("sqli_observed"),
                        "st4": f("console_authenticated"),
                        "st6": passed,
                    }
            ''')
            ir = rb1_finder.find(it)
            isigs = ir["checks"]["spoofable"]["signals"]
            check("indentation boundary: 'passed' (no flags) NOT flagged as any stage",
                  not any(s.get("stage") == "st6" or s.get("superset_stage") == "st6"
                          or s.get("later_stage") == "st6" for s in isigs))
            check("indentation boundary: st1 crossref into st4 still found (resolver still works)",
                  any(s.get("stage") == "st1" and s.get("later_stage") == "st4" for s in isigs))
        finally:
            shutil.rmtree(ib, ignore_errors=True)

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        shutil.rmtree(g, ignore_errors=True)
        shutil.rmtree(b, ignore_errors=True)


if __name__ == "__main__":
    main()
