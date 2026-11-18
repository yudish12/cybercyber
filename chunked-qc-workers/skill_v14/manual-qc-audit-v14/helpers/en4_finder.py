#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
en4_finder.py  --  static FINDER layer of the EN4 eval
(Environment: Operational & Reproducibility -- the #1 recurring fail).

READ-ONLY. It POINTS; it does not render the EN4 verdict. Coverage + recall:
enumerate every base image and vendored wheel, cross-reference the TOP-LEVEL
environment/NOTICE.md for a license + digest pin, read each wheel's own METADATA
license to catch blanket/mismatch claims, flag mutable (unpinned) tags, and
surface reproducibility signals for the reader / a boot.

Bias to flag (false fails > missed fails): a literal provenance gap or an
unpinned tag is a FAIL-candidate; runtime-only reproducibility is a LIVE item;
nothing is dropped. The reader opens NOTICE + the Dockerfiles + the wheels and
renders the certain verdict.

V14 EN4 fail labels covered:
  [Fail - Provenance / Licensing]  -> provenance_licensing
  [Fail - Unbounded or Unpinned]   -> unpinned_images
  [Fail - Reproducibility]         -> reproducibility (static signals; rest LIVE)

Usage:  python3 -I en4_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io, zipfile

_LIC = (r"(MIT|BSD-\d-Clause|BSD|Apache-2\.0|Apache|GPL-\d(\.\d)?(-or-later|-only)?|"
        r"LGPL[\w.\-]*|MPL-2\.0|MPL|PSF-2\.0|PSF|Python-2\.0|CNRI[\w.\-]*|ISC|"
        r"Unlicense|CC0[\w.\-]*|Zlib|HPND|0BSD)")
_LIC_RE = re.compile(_LIC)
_INTERNET_RE = re.compile(
    r"(curl\s|wget\s|apt-get\s+(?:update|install)|apk\s+add|pip\s+install(?!.*--no-index)"
    r"|https?://(?!localhost|127\.0\.0\.1|gateway|main|internal|host\.docker))",
    re.I)


def _read(path):
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# images                                                                       #
# --------------------------------------------------------------------------- #
def collect_images(task_dir):
    env = os.path.join(task_dir, "environment")
    imgs = []
    # FROM in every Dockerfile
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if fn == "Dockerfile" or fn.startswith("Dockerfile"):
                full = os.path.join(dp, fn)
                for i, line in enumerate(_read(full).splitlines(), 1):
                    m = re.match(r"\s*FROM\s+(\S+)", line, re.I)
                    if m:
                        imgs.append(_img_rec(m.group(1), os.path.relpath(full, task_dir), i))
    # image: in compose
    for name in ("docker-compose.yaml", "docker-compose.yml"):
        full = os.path.join(env, name)
        for i, line in enumerate(_read(full).splitlines(), 1):
            m = re.match(r"\s*image:\s*(\S+)", line)
            if m:
                imgs.append(_img_rec(m.group(1).strip('"\''), os.path.join("environment", name), i))
    # de-dup by ref
    seen, out = set(), []
    for r in imgs:
        if r["ref"] not in seen:
            seen.add(r["ref"]); out.append(r)
    return out


def _img_rec(ref, src, line):
    pinned = "@sha256:" in ref
    base = ref.split("@", 1)[0]
    repo = base.rsplit(":", 1)[0]
    repo_short = repo.rsplit("/", 1)[-1]
    return {"ref": ref, "base": base, "repo": repo, "repo_short": repo_short,
            "pinned": pinned, "source": src, "line": line}


# --------------------------------------------------------------------------- #
# NOTICE                                                                        #
# --------------------------------------------------------------------------- #
def find_notice(task_dir):
    p = os.path.join(task_dir, "environment", "NOTICE.md")
    if os.path.exists(p):
        return {"present": True, "path": "environment/NOTICE.md",
                "text": _read(p), "abs": p}
    return {"present": False, "path": "environment/NOTICE.md", "text": "", "abs": p}


def _row_license(notice_text, key):
    """Find the NOTICE line mentioning `key`; return the license token on it, if any."""
    for line in notice_text.splitlines():
        if key and key in line:
            m = _LIC_RE.search(line)
            if m:
                return m.group(0)
            return ""  # mentioned but no license token
    return None  # not mentioned at all


# --------------------------------------------------------------------------- #
# wheels                                                                        #
# --------------------------------------------------------------------------- #
def collect_wheels(task_dir):
    env = os.path.join(task_dir, "environment")
    out = []
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if fn.endswith(".whl"):
                full = os.path.join(dp, fn)
                out.append({"file": fn, "rel": os.path.relpath(full, task_dir),
                            "metadata_license": _wheel_license(full)})
    return out


def _wheel_license(whl_path):
    try:
        with zipfile.ZipFile(whl_path) as z:
            metas = [n for n in z.namelist() if n.endswith(".dist-info/METADATA") or n.endswith("/METADATA")]
            if not metas:
                return ""
            text = z.read(metas[0]).decode("utf-8", "replace")
    except Exception:
        return ""
    m = re.search(r"(?mi)^License-Expression:\s*(.+)$", text)
    if m:
        return m.group(1).strip()
    m = re.search(r"(?mi)^License:\s*(.+)$", text)
    if m and m.group(1).strip() and m.group(1).strip().upper() != "UNKNOWN":
        return m.group(1).strip()
    cls = re.findall(r"(?mi)^Classifier:\s*License\s*::\s*(.+)$", text)
    if cls:
        return "; ".join(c.strip() for c in cls)
    return ""


def _lic_token(s):
    m = _LIC_RE.search(s or "")
    return m.group(0) if m else ""


def _lic_family(tok):
    t = (tok or "").lower()
    for key in ("lgpl", "agpl", "gpl", "apache", "bsd", "mpl", "mit", "psf",
                "python", "cnri", "isc", "zlib", "hpnd", "unlicense", "cc0"):
        if key in t:
            return {"agpl": "GPL", "lgpl": "LGPL", "gpl": "GPL",
                    "python": "PSF", "psf": "PSF"}.get(key, key.upper())
    return t.upper()


def _lic_ver(tok):
    m = re.search(r"\d+(?:\.\d+)?", tok or "")
    return m.group(0) if m else ""


def _lic_rel(notice_tok, meta_tok):
    """match / review / fail. Family mismatch = fail; same family, differing
    explicit versions = review; a refinement (one side unversioned) = match."""
    nt, mt = _lic_token(notice_tok), _lic_token(meta_tok)
    if not nt or not mt:
        return "match"          # nothing comparable -> coverage check handles gaps
    if _lic_family(nt) != _lic_family(mt):
        return "fail"
    nv, mv = _lic_ver(nt), _lic_ver(mt)
    if nv and mv and nv != mv:
        return "review"
    return "match"


# --------------------------------------------------------------------------- #
# the three EN4 sub-finders                                                     #
# --------------------------------------------------------------------------- #
def _provenance(task_dir, images, wheels, notice):
    fail, review, files = [], [], {notice["path"]}
    if not notice["present"]:
        fail.append({"component": "environment/NOTICE.md", "issue": "top-level NOTICE.md missing"})
        return {"label": "[Fail - Provenance / Licensing]", "fail_candidates": fail,
                "review": review, "files_to_read": sorted(files)}
    ntext = notice["text"]

    # images: must be named in top-level NOTICE with a license
    for im in images:
        files.add(im["source"])
        lic = _row_license(ntext, im["base"])
        if lic is None:
            lic = _row_license(ntext, im["repo_short"])
        if lic is None:
            fail.append({"component": im["ref"], "issue": "image not listed in top-level NOTICE",
                         "source": f'{im["source"]}:{im["line"]}'})
        elif lic == "":
            fail.append({"component": im["ref"], "issue": "listed in NOTICE but no license token",
                         "source": im["source"]})

    # wheels: must be listed + NOTICE license must match the wheel's own METADATA
    for wh in wheels:
        files.add(wh["rel"])
        nlic = _row_license(ntext, wh["file"])
        mlic = _lic_token(wh["metadata_license"])
        if nlic is None:
            fail.append({"component": wh["file"], "issue": "wheel not listed in NOTICE",
                         "metadata_license": wh["metadata_license"]})
        elif nlic == "":
            fail.append({"component": wh["file"], "issue": "wheel listed but no license token"})
        else:
            rel = _lic_rel(nlic, mlic)
            if rel == "fail":
                fail.append({"component": wh["file"],
                             "issue": f"license family mismatch: NOTICE={_lic_token(nlic)} vs METADATA={mlic}",
                             "metadata_license": wh["metadata_license"]})
            elif rel == "review":
                review.append({"component": wh["file"],
                               "issue": f"license version differs: NOTICE={_lic_token(nlic)} vs METADATA={mlic}"})
    return {"label": "[Fail - Provenance / Licensing]", "fail_candidates": fail,
            "review": review, "files_to_read": sorted(files)}


def _unpinned(task_dir, images):
    fail = []
    for im in images:
        if not im["pinned"]:
            fail.append({"component": im["ref"], "issue": "mutable tag, no @sha256 digest pin",
                         "source": f'{im["source"]}:{im["line"]}'})
    return {"label": "[Fail - Unbounded or Unpinned]", "fail_candidates": fail,
            "files_to_read": sorted({im["source"] for im in images})}


def _reproducibility(task_dir):
    env = os.path.join(task_dir, "environment")
    cands, live, files = [], [], set()
    for dp, _d, fns in os.walk(env):
        for fn in fns:
            if not (fn.endswith(".sh") or fn.startswith("Dockerfile") or fn.endswith((".yaml", ".yml"))):
                continue
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, task_dir)
            for i, line in enumerate(_read(full).splitlines(), 1):
                if _INTERNET_RE.search(line):
                    cands.append({"file": rel, "line": i, "signal": "possible runtime/build internet",
                                  "text": line.strip()[:160]})
                    files.add(rel)
                if re.search(r"ALLOW(ED)?_?IP|NOT_ALLOWED_IP|client[_-]?ip|allowlist", line, re.I):
                    cands.append({"file": rel, "line": i, "signal": "IP allowlist (check vs Docker subnet)",
                                  "text": line.strip()[:160]})
                    files.add(rel)
    live = [
        "boot: run twice -- confirm no flaky boot / service-discovery drift",
        "boot: restart main -- confirm the scored marker does not desync",
        "config: verifier/solver timeout must be >= agent timeout (false infra_error)",
        "boot: confirm the runtime needs no public internet; report-judge host reachable offline",
    ]
    return {"label": "[Fail - Reproducibility]", "candidates": cands, "live_items": live,
            "files_to_read": sorted(files)}


# --------------------------------------------------------------------------- #
# entry                                                                        #
# --------------------------------------------------------------------------- #
def find(task_dir):
    images = collect_images(task_dir)
    wheels = collect_wheels(task_dir)
    notice = find_notice(task_dir)
    return {
        "task_dir": os.path.abspath(task_dir),
        "notice": {"present": notice["present"], "path": notice["path"]},
        "images": images,
        "wheel_count": len(wheels),
        "checks": {
            "provenance_licensing": _provenance(task_dir, images, wheels, notice),
            "unpinned_images": _unpinned(task_dir, images),
            "reproducibility": _reproducibility(task_dir),
        },
    }


def _summary(r):
    o = [f"EN4 FINDER — {r['task_dir']}",
         f"  NOTICE present: {r['notice']['present']}  images: {len(r['images'])}  wheels: {r['wheel_count']}"]
    pv = r["checks"]["provenance_licensing"]
    o.append(f"  [Provenance / Licensing] FAIL-candidates={len(pv['fail_candidates'])}")
    for c in pv["fail_candidates"][:30]:
        o.append(f"     FAIL?  {c['component']}  — {c['issue']}")
    up = r["checks"]["unpinned_images"]
    o.append(f"  [Unbounded or Unpinned] FAIL-candidates={len(up['fail_candidates'])}")
    for c in up["fail_candidates"]:
        o.append(f"     FAIL?  {c['component']}  — {c['issue']} ({c['source']})")
    rp = r["checks"]["reproducibility"]
    o.append(f"  [Reproducibility] static signals={len(rp['candidates'])}, LIVE checks={len(rp['live_items'])}")
    for c in rp["candidates"][:15]:
        o.append(f"     signal {c['file']}:{c['line']}  {c['signal']}  — {c['text']}")
    o.append("  NOTE: finder only points. The reader opens NOTICE + Dockerfiles + wheels and decides.")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: en4_finder.py <task_dir> [--json OUT]", file=sys.stderr)
        return 2
    r = find(argv[0])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as f:
            json.dump(r, f, indent=2)
    print(_summary(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
