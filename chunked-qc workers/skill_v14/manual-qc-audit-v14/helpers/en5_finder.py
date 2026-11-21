#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
en5_finder.py  --  static FINDER layer of the OFFICIAL V19 EN5 eval
(Environment: {EN5} Provenance / Licensing).

*** NAMING COLLISION WARNING ***
The official V19 QC rubric (2026-11-19 doc) promotes "Provenance / Licensing" OUT
of EN4 into its own numbered dimension, reusing the short code "EN5". This is a
DIFFERENT dimension from:
  - cqc's (cyber_quality_check's) own CUSTOM "EN5" = "Leftover Harness/Seeder
    Endpoint Exposure" (checks/llm_checks.py) -- cqc still ships the older V11
    reference CSV, where licensing is folded into EN4 and "EN5" means Leftover
    Harness/Seeder Endpoint, NOT licensing. cqc has not been updated to V19.
  - this skill's own `custom_finder.py`/`custom_reader.py`, which implements
    THAT same Leftover-Harness concept and is UNCHANGED by this file.
When reconciling tool output against this skill (SKILL.md rule 7): a cqc row
printed "EN5" is ALWAYS Leftover Harness/Seeder Endpoint Exposure. THIS finder's
EN5 is the V19-official Provenance/Licensing dimension. Never conflate the two
rows -- they happen to share a code across incompatible rubric versions.

READ-ONLY. It POINTS; it does not render the EN5 verdict. The image/wheel
license-matching logic is reused verbatim from en4_finder.py (V11/V14 folded
licensing into EN4; V19 splits it out here), PLUS two things en4_finder never
covered:
  * OS-package attribution: every `apt-get install` / `apk add` package name in
    every Dockerfile, cross-referenced against NOTICE.md. The real miss that
    drove this file: 6afb975e9c3753a2c8232a77 installed curl/dnsutils/jq/tmux/
    default-mysql-client and attributed NONE of them anywhere.
  * V19's two-tier bar (the en4-era check was a flat fail):
      [Fail - Provenance / Licensing]     (score 2) -- not attributed ANYWHERE
                                            in the task files, OR cannot legally
                                            be used commercially (reader-only).
      [Non-Fail - Provenance / Licensing] (score 3) -- missing from NOTICE.md
                                            but credited ELSEWHERE in the task
                                            files.
      PASS (score 5) -- properly licensed within NOTICE.md.
A "credited elsewhere" hit is a coverage floor, not proof: the reader confirms
it is a real license line, not a coincidental name match, before downgrading a
candidate from FAIL to NON-FAIL.

Usage:  python3 -I en5_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import en4_finder as _en4  # reuse image/wheel collection + NOTICE license-matching infra

_LIC_RE = _en4._LIC_RE
_read = _en4._read

# apt-get/apk install package-name extraction. `\`-continued lines are joined first so a
# multi-line RUN ... install block reads as one logical line.
_INSTALL_RE = re.compile(r'\b(?:apt-get\s+install|apk\s+add)\b(.*)', re.I)
_FLAG_OR_NOISE = {
    "-y", "--yes", "-q", "-qq", "--no-install-recommends", "update", "&&", "||", ";",
    "install", "add", "apt-get", "apk", "rm", "-rf",
}


def _joined_dockerfile_text(path):
    return re.sub(r'\\\s*\n\s*', ' ', _read(path))


def collect_os_packages(task_dir):
    """Every apt-get/apk package name installed in any Dockerfile, with its source
    file:line. Flags, the command tokens themselves, and path-like cleanup args are
    filtered out; only plausible package-name tokens are kept."""
    env = os.path.join(task_dir, "environment")
    out = []
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if not (fn == "Dockerfile" or fn.startswith("Dockerfile")):
                continue
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, task_dir)
            text = _joined_dockerfile_text(full)
            for i, line in enumerate(text.splitlines(), 1):
                m = _INSTALL_RE.search(line)
                if not m:
                    continue
                for tok in m.group(1).split():
                    tok = tok.strip().rstrip('\\')
                    if not tok or tok in _FLAG_OR_NOISE or tok.startswith(("-", "/", "$")):
                        continue
                    if re.fullmatch(r'[A-Za-z][A-Za-z0-9+._-]*', tok):
                        out.append({"package": tok, "source": rel, "line": i})
    seen, dedup = set(), []
    for p in out:
        key = (p["package"], p["source"])
        if key not in seen:
            seen.add(key)
            dedup.append(p)
    return dedup


def _credited_elsewhere(task_dir, name, exclude_path):
    """V19's Non-Fail carve-out: search every OTHER text-ish task file for `name` near a
    license token. Returns 'relpath:line' of the first hit, or None. A finder-level floor
    -- the reader confirms the hit is a real license line, not a coincidental name match."""
    if not name:
        return None
    for dp, _d, fns in os.walk(task_dir):
        for fn in fns:
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, task_dir)
            if rel == exclude_path:
                continue
            # a NESTED notice.md must not rescue coverage -- only the top-level NOTICE.md
            # (already excluded above) is authoritative; any other file named NOTICE.md
            # anywhere in the tree is excluded from "elsewhere" too.
            if fn.upper() == "NOTICE.MD":
                continue
            if not (fn.endswith((".md", ".txt", ".toml", ".cfg", ".rst", ".yaml", ".yml"))
                    or fn.upper().startswith("LICENSE")):
                continue
            for i, line in enumerate(_read(full).splitlines(), 1):
                if name in line and _LIC_RE.search(line):
                    return f"{rel}:{i}"
    return None


def _provenance_v19(task_dir, images, wheels, os_pkgs, notice):
    fail, non_fail, review, files = [], [], [], {notice["path"]}
    ntext = notice["text"] if notice["present"] else ""
    if not notice["present"]:
        fail.append({"component": "environment/NOTICE.md",
                      "issue": "top-level NOTICE.md missing", "tier": "fail"})

    def _classify(component_label, name_keys, window, elsewhere_name):
        # Try each key (e.g. the full "python:3.12-slim" base, then the bare "python"
        # repo name); a key that is MENTIONED but yields no token ("") must not stop the
        # search early -- a later, bare key is what actually matches a shared "Licenses:"
        # summary paragraph that names the component generically, not by its full ref.
        lic, any_mentioned = None, False
        for key in name_keys:
            candidate = _en4._row_license(ntext, key, window=window) if notice["present"] else None
            if candidate:
                lic = candidate
                break
            if candidate == "":
                any_mentioned = True
        if lic:
            return
        elsewhere = _credited_elsewhere(task_dir, elsewhere_name, notice["path"])
        if elsewhere:
            non_fail.append({"component": component_label,
                              "issue": f"not attributed within NOTICE.md, but credited at {elsewhere}",
                              "tier": "non_fail"})
        else:
            reason = ("listed in NOTICE but no license token" if any_mentioned
                      else "not attributed anywhere in the task files")
            fail.append({"component": component_label, "issue": reason, "tier": "fail"})

    for im in images:
        files.add(im["source"])
        _classify(im["ref"], [im["base"], im["repo_short"]], 1, im["repo_short"])
    for wh in wheels:
        files.add(wh["rel"])
        nlic = _en4._row_license(ntext, wh["file"]) if notice["present"] else None
        if nlic:
            # attributed in NOTICE -- but is it the RIGHT license? Cross-check against the
            # wheel's own METADATA. A wrong attribution is worse than a missing one; it is
            # never downgradeable via the "credited elsewhere" carve-out.
            mlic = _en4._lic_token(wh["metadata_license"])
            rel = _en4._lic_rel(nlic, mlic)
            if rel == "fail":
                fail.append({"component": wh["file"],
                             "issue": f"license family MISMATCH: NOTICE={_en4._lic_token(nlic)!r} vs "
                                      f"wheel METADATA={mlic!r} -- wrong attribution, not a gap",
                             "tier": "fail"})
            elif rel == "review":
                review.append({"component": wh["file"],
                               "issue": f"license version differs: NOTICE={_en4._lic_token(nlic)!r} "
                                        f"vs METADATA={mlic!r}"})
        else:
            _classify(wh["file"], [wh["file"]], 0, wh["file"])
    for pk in os_pkgs:
        files.add(pk["source"])
        _classify(pk["package"], [pk["package"]], 1, pk["package"])

    return {"label": "[Fail - Provenance / Licensing] / [Non-Fail - Provenance / Licensing]",
            "fail_candidates": fail, "non_fail_candidates": non_fail, "review": review,
            "files_to_read": sorted(files),
            "note": "FAIL only if not attributed ANYWHERE in the task files (or legally unusable "
                    "commercially -- reader-only, not automatable), or if NOTICE attributes the WRONG "
                    "license (wheel METADATA family mismatch). NON-FAIL (score 3) if missing from "
                    "NOTICE.md but credited elsewhere -- reader confirms that citation is a real "
                    "license line, not a coincidental name match. `review`: same license family, "
                    "differing version only -- informational, not a fail."}


def find(task_dir):
    images = _en4.collect_images(task_dir)
    wheels = _en4.collect_wheels(task_dir)
    os_pkgs = collect_os_packages(task_dir)
    notice = _en4.find_notice(task_dir)
    return {
        "task_dir": os.path.abspath(task_dir),
        "notice": {"present": notice["present"], "path": notice["path"]},
        "images": images, "wheel_count": len(wheels), "os_package_count": len(os_pkgs),
        "checks": {"provenance_licensing": _provenance_v19(task_dir, images, wheels, os_pkgs, notice)},
    }


def _summary(r):
    pv = r["checks"]["provenance_licensing"]
    o = [f"EN5 FINDER (V19-official Provenance/Licensing — NOT cqc's custom "
         f"'Leftover Harness' EN5) — {r['task_dir']}",
         f"  NOTICE present: {r['notice']['present']}  images: {len(r['images'])}  "
         f"wheels: {r['wheel_count']}  OS packages: {r['os_package_count']}",
         f"  [Fail] candidates={len(pv['fail_candidates'])}  "
         f"[Non-Fail, score 3] candidates={len(pv['non_fail_candidates'])}"]
    for c in pv["fail_candidates"][:30]:
        o.append(f"     FAIL?      {c['component']}  — {c['issue']}")
    for c in pv["non_fail_candidates"][:30]:
        o.append(f"     NON-FAIL?  {c['component']}  — {c['issue']}")
    for c in pv.get("review", [])[:15]:
        o.append(f"     review     {c['component']}  — {c['issue']}")
    o.append("  NOTE: finder points. The reader opens NOTICE + Dockerfiles + the 'elsewhere' "
             "citation and decides FAIL vs NON-FAIL vs clean.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: en5_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
