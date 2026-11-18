#!/usr/bin/env python3
"""
TDD tests for vu2_finder.py — static FINDER layer of the VU2 eval
(Vulnerability: Decoy & Patch Coverage).

VU2 is reader-dominant, so the finder's job is COVERAGE: enumerate every route/handler
that touches the scored resource, GROUP siblings (so the reader checks the documented
fix closes ALL of them, not just the named one — [Fail - Survives Documented Fix]), and
LOCATE the documented fix / resisting-decoy description (for [Fail - Missing or Leaking
Decoy]). The reader then judges whether the fix covers every sibling and a genuine decoy
resists.

Run:  python3 -I test_vu2_finder.py
"""
import os, sys, tempfile, textwrap, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vu2_finder  # noqa: E402


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))


def build_fixture(root):
    t = os.path.join(root, "task")
    env = os.path.join(t, "environment")
    # Flask app: two sibling routes on /v1/records + an unrelated one
    _w(os.path.join(env, "ledger-service", "app.py"), '''
        @app.get('/health')
        def health(): return 'ok'

        @app.get('/v1/records')
        def records(): ...

        @app.get('/v1/records/<record_id>/disposition')
        def disposition(record_id): ...
    ''')
    # PHP endpoints on the fieldcalc resource (vulnerable + resisting siblings)
    _w(os.path.join(env, "dolibarr", "custom", "fieldcalc", "preview.php"), "<?php eval($c->expr); ?>")
    _w(os.path.join(env, "dolibarr", "custom", "fieldcalc", "export.php"), "<?php // enforces saved-configuration ownership ?>")
    _w(os.path.join(env, "dolibarr", "custom", "fieldcalc", "label_preview.php"), "<?php echo htmlspecialchars($label); ?>")
    # documented fix / resisting-decoy description in difficulty_explanation
    _w(os.path.join(t, "task.toml"), '''
        [task]
        name = "acme/fieldcalc"
        difficulty_explanation = """
        Export enforces saved-configuration ownership, label preview HTML escapes stored
        labels, and the numeric validator rejects the document payload. Only the document
        preview evaluates the stored expression.
        """
    ''')
    return t


PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def main():
    tmp = tempfile.mkdtemp()
    try:
        r = vu2_finder.find(build_fixture(tmp))
        inv = r["checks"]["route_inventory"]
        fix = r["checks"]["documented_fix"]
        routes = inv["routes"]
        groups = inv["resource_groups"]

        def has_path(p):
            return any(p in rt["path"] for rt in routes)

        # 1. Flask routes enumerated
        check("Flask /v1/records enumerated", has_path("/v1/records"))
        check("Flask disposition route enumerated", has_path("disposition"))

        # 2. PHP endpoints enumerated
        check("PHP preview.php endpoint enumerated", has_path("preview.php"))
        check("PHP export.php (resisting sibling) enumerated", has_path("export.php"))

        # 3. siblings grouped by resource (the two /v1/records* routes share a group)
        rec_groups = [g for g, items in groups.items() if any("/v1/records" in i["path"] for i in items)]
        check("sibling grouping: /v1/records* share a resource group",
              any(len(groups[g]) >= 2 for g in rec_groups))

        # 4. fieldcalc PHP siblings grouped together
        fc_group = [g for g, items in groups.items() if any("fieldcalc" in i["path"] for i in items)]
        check("fieldcalc siblings grouped (preview + export + label_preview)",
              any(len(groups[g]) >= 3 for g in fc_group))

        # 5. documented fix / resisting-decoy description located
        check("documented fix located from difficulty_explanation",
              len(fix["located"]) >= 1 and any("enforces" in x["text"].lower() or "escape" in x["text"].lower()
                                               or "rejects" in x["text"].lower() for x in fix["located"]))

        # 6. files_to_read includes the route files + task.toml
        check("files_to_read includes route files + task.toml",
              any("app.py" in f for f in inv["files_to_read"]) and
              any("task.toml" in f for f in fix["files_to_read"]))

        print(f"\n{PASS} passed, {FAIL} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
