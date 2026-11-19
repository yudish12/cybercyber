#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vu5_finder.py  --  static FINDER layer of the VU5 eval
(Vulnerability: Attack-Surface Breadth).

VU5 is reader-dominant. The finder provides COVERAGE by reusing vu2_finder's route/surface
inventory, counting the DISTINCT major surfaces (trivial endpoints excluded) and locating
the decoy / adjacent-surface descriptions:

  * [Fail - One-Trick Task]: fewer than 3 genuinely-probeable major attack surfaces across
    distinct vuln categories -> one_trick_candidate.
  * [Fail - Decoy Reaches Scored Secret]: a non-scored surface (decoy or adjacent real CVE)
    reaches the scored secret -- a reading judgment; the finder surfaces the decoy set.
  * [Non-Fail - Fake or Stubbed Decoy] (score 3): a decoy is absent/stubbed/cosmetic -- also
    a reading judgment.

The reader confirms >=3 genuine surfaces across distinct categories, each decoy is real and
resists, and no decoy reaches the scored secret.

Usage:  python3 -I vu5_finder.py <task_dir> [--json OUT]
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vu2_finder

# endpoint stems that are not "major attack surfaces"
_TRIVIAL = ("/health", "/", "/metrics", "/favicon", "/robots", "/static", "/ping",
            "/status", "/internal/diag", "/internal/verify", "/api/credentials")


def _is_trivial(stem):
    s = stem.lower()
    if s == "/" or not s:
        return True
    # "/" would match every path via startswith, so compare it exactly only (above)
    return any(s == tv or s.startswith(tv + "/") or s == tv for tv in _TRIVIAL if tv != "/") \
        or any(s.startswith(tv) for tv in _TRIVIAL if tv not in ("/",))


def find(task_dir):
    routes, files = vu2_finder._routes(task_dir)
    groups = vu2_finder._group(routes)
    major = [g for g in groups if not _is_trivial(g)]
    # also treat each author PHP endpoint file as its own surface stem already handled by _group (dir stem)
    distinct = len(major)
    decoy = vu2_finder._documented_fix(task_dir)
    return {
        "task_dir": os.path.abspath(task_dir),
        "checks": {
            "surface_breadth": {
                "label": "[Fail - One-Trick Task]",
                "major_surfaces": sorted(major),
                "distinct_surface_count": distinct,
                "one_trick_candidate": distinct < 3,
                "all_groups": {g: len(v) for g, v in groups.items()},
                "files_to_read": files,
                "note": "reader confirms >=3 GENUINELY probeable surfaces across DISTINCT vuln categories "
                        "(route count is a floor, not proof of distinct categories)."},
            "decoy_reaches_secret": {
                "label": "[Fail - Decoy Reaches Scored Secret] / [Non-Fail - Fake or Stubbed Decoy]",
                "located": decoy["located"],
                "files_to_read": decoy["files_to_read"] + files,
                "note": "reader reads each decoy/adjacent surface: is it real and resisting (good), stubbed/"
                        "cosmetic (score-3 Non-Fail), or does it REACH the scored secret (Fail)?"},
        },
    }


def _summary(r):
    sb = r["checks"]["surface_breadth"]
    o = [f"VU5 FINDER — {r['task_dir']}",
         f"  distinct major surfaces: {sb['distinct_surface_count']}  one-trick candidate: {sb['one_trick_candidate']}"]
    for s in sb["major_surfaces"][:20]:
        o.append(f"     surface  {s}")
    dc = r["checks"]["decoy_reaches_secret"]
    o.append(f"  [Decoy] descriptions located: {len(dc['located'])} (reader checks each decoy)")
    o.append("  NOTE: finder counts surfaces. The reader confirms breadth, genuine decoys, and no leak.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: vu5_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
