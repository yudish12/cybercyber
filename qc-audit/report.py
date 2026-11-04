#!/usr/bin/env python3
"""
Assemble the final auditor-format QC report for one task.

Usage:
  report.py --pack pack.json [--verdicts workflow_out.json] [--label NAME] [--md]

Merges the deterministic verdicts from the evidence pack with the judgment
verdicts from the workflow and prints every rubric dimension in rubric order,
in the human auditor's format (Component / Answer / Score / Feedback).
"""
import json, os, re, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
# Derived from tiers.json so a rubric revision that renumbers dimensions cannot leave
# a stale id here. V6 inserted "Harness Integrity" at 23 and pushed Spam Check to 24.
_TIERS = {int(k): v for k, v in json.load(
    open(os.path.join(HERE, "tiers.json"))).items()}
_RUBRIC_TITLES = {r["_id"]: r["title"] for r in json.load(
    open(os.path.join(HERE, "rubric.json")))}
NOT_ASSESSABLE = {i: _RUBRIC_TITLES[i] for i, t in _TIERS.items() if t == "form-field"}
N_DIMS = len(_RUBRIC_TITLES)




def task_identity(pack, label):
    """Everything that names this task, so a report can never be mistaken for another.

    The Scale attempt id is not inside task.toml — it lives in the archive/folder name
    (`pass_6aa46932df3c3e50b8e623a0_task`). Scan path segments RIGHT TO LEFT: a
    left-to-right scan of the whole absolute path lets a hex-named scratch or extraction
    parent win over the bundle's own id.
    """
    ev = pack.get("evidence") or {}
    t = ev.get("task") if isinstance(ev.get("task"), dict) else {}
    root = str(pack.get("task_root") or "")
    v4i = ev.get("v4_identity")
    ident = (v4i.get("bundle_name") if isinstance(v4i, dict) else "") or ""

    GENERIC = {"task", "bundle", "tasks", ".", "", "tmp", "environment"}
    HEXID = re.compile(r"(?<![0-9a-zA-Z])([0-9a-fA-F]{24})(?![0-9a-zA-Z])")
    hexid = ""
    for seg in list(reversed(root.split(os.sep))) + [ident]:
        m = HEXID.search(seg or "")
        if m:
            hexid = m.group(1).lower()
            break

    if hexid:
        task_id = hexid
    else:
        # No attempt id: build something that cannot collide across bundles. The bare
        # basename is "task" for every extracted bundle, so two different bundles used
        # to report the same id.
        named = next((seg for seg in reversed(root.split(os.sep))
                      if seg and seg.lower() not in GENERIC), "")
        task_id = named or ident or label or "unknown"
        if task_id.lower() in GENERIC:
            task_id = f"{task_id}:{label}"
    return {
        "task_id": task_id,
        "attempt_id": hexid,
        "bundle": ident,
        "label": label,
        "name": t.get("name"),
        "cwe": t.get("cwe"),
        "vulnerability_kind": t.get("vulnerability_kind"),
        "task_root": root,
    }


def _open_questions(ev, depth=0):
    """Collect needs_judgment reasons, including one level of nesting.

    Deterministic verdicts wrap their analysis (D17/D18 use {"analysis": {...}}),
    so a top-level-only read silently dropped the open question.
    """
    out = []
    if not isinstance(ev, dict) or depth > 2:
        return out
    if ev.get("needs_judgment") and ev.get("_why_judgment"):
        out.append(str(ev["_why_judgment"]))
    for v in ev.values():
        if isinstance(v, dict):
            out.extend(_open_questions(v, depth + 1))
    return out[:3]


def _nested_problems(ev, depth=0):
    """Pull `problems` out of a nested analysis block so a failing deterministic
    check renders its reason instead of a raw JSON dump."""
    if not isinstance(ev, dict) or depth > 2:
        return []
    out = []
    for k, v in ev.items():
        if isinstance(v, dict):
            if v.get("status") == "FAIL":
                out.extend(v.get("problems") or ([v["detail"]] if v.get("detail") else []))
            out.extend(_nested_problems(v, depth + 1))
    return out[:4]




def feedback_for(v, mx):
    """The human-readable reason behind a verdict, for both the full report and relay."""
    fb = (v.get("why") or "").strip()
    if v.get("src") == "deterministic" and not fb:
        ev = v.get("evidence") or {}
        probs = (ev.get("problems") or ev.get("violations") or ev.get("leaky_prefixes")
                 or _nested_problems(ev) or [])
        if probs:
            fb = "; ".join(map(str, probs))[:600]
        elif v["score"] == mx:
            fb = "All mechanical checks passed."
        else:
            fb = f"check failed; evidence: {json.dumps(ev, default=str)[:400]}"
    return fb


def emit_relay(rubric, by_title, ident, have, adv, warnings=()):
    """The block to paste into the chat reply.

    Every one of the rubric's dimensions appears, with its score and its verbatim rubric
    answer. Reporting only the dimensions that failed leaves the reader with no answer
    for the other twenty, which is what the auditor form actually asks for.
    """
    print(f"**QC audit — task id `{ident['task_id']}`**")
    bits = [f"`{ident['name']}`" if ident.get("name") else None,
            ident.get("cwe"), str(ident.get("vulnerability_kind") or "")[:60] or None]
    print(" · ".join(b for b in bits if b))
    print()
    print("| # | Dimension | Score | Verdict | Answer |")
    print("|---|---|---|---|---|")
    fails, nonfails, unscored = [], [], []
    for r in rubric:
        v = by_title.get(r["title"])
        mx = max(o["score"] for o in r["options"])
        if v is None:
            na = r["_id"] in NOT_ASSESSABLE and not have.get(r["_id"])
            verdict = "NOT ASSESSABLE" if na else "NOT SCORED"
            answer = ("submission-form fields not supplied" if na
                      else "not run in this pass")
            unscored.append((r["_id"], r["title"], verdict))
            print(f"| {r['_id']} | {r['title']} | n/a | {verdict} | {answer} |")
            continue
        nf = bool(re.match(r"\s*\[Non-?Fail", str(v.get("option") or ""), re.I))
        verdict = "PASS" if v["score"] == mx else ("NON-FAIL" if nf else "**FAIL**")
        # NOT truncated: this cell is the answer the reviewer copies onto the auditor
        # form, so it has to be the rubric's verbatim option. The longest is ~330 chars.
        # `|` would break the markdown table, so escape it.
        ans = " ".join(str(v.get("option") or "").split()).replace("|", "\\|")
        if v["score"] < mx:
            (nonfails if nf else fails).append((r["_id"], r["title"], v))
        print(f"| {r['_id']} | {r['title']} | {v['score']}/{mx} | {verdict} | {ans} |")
    print()
    # A dimension that was never run is not a pass. Saying PASS while a third of the
    # rubric is unscored reads as "this bundle cleared QC", which it has not.
    unrun = [u for u in unscored if u[2] == "NOT SCORED"]
    if fails:
        overall = "FAIL"
        tail = ""
    elif unrun:
        overall = "INCOMPLETE"
        tail = (f" No dimension failed so far, but {len(unrun)} of {N_DIMS} were never scored — "
                "run them before treating this as a pass.")
    else:
        overall = "PASS"
        tail = ""
    print(f"**Overall: {overall}** for task id `{ident['task_id']}`.{tail}")
    if fails:
        print()
        print("Failing dimensions and why:")
        for i, t, v in fails:
            why = " ".join(feedback_for(v, 5).split())[:400] or "see the full report"
            print(f"- **{t}** — {v['score']}/5. {why}")
    if nonfails:
        print()
        print("Non-fail deductions (these do not fail the bundle):")
        for i, t, v in nonfails:
            why = " ".join(feedback_for(v, 5).split())[:300]
            print(f"- **{t}** — {v['score']}/5. {why}")
    disagreed = [(r["title"], by_title[r["title"]]) for r in rubric
                 if r["title"] in by_title and (by_title[r["title"]].get("confirm") or {})
                 and not by_title[r["title"]]["confirm"].get("agrees")]
    if disagreed:
        print()
        print("Mechanical check vs independent read — DISAGREEMENT (settle before reporting):")
        for t, v in disagreed:
            c = v["confirm"]
            print(f"- **{t}** — check says {v['score']}/5, independent read says {c.get('score')}/5. "
                  f"{' '.join(str(c.get('why') or '').split())[:240]}")
    contested = [(r["_id"], r["title"], by_title[r["title"]]) for r in rubric
                 if r["title"] in by_title
                 and (by_title[r["title"]].get("verification") or {}).get("contested")]
    if contested:
        print()
        print("Contested verdicts (the adversarial verifiers disagreed — settle on the merits):")
        for i, t, v in contested:
            ver = v.get("verification") or {}
            print(f"- **{t}** — {ver.get('found', 0)} of {ver.get('total')} hunters found a "
                  f"violation{', tiebroken' if ver.get('tiebroken') else ''}. Scored "
                  f"{v['score']}/5.")
    if unscored:
        print()
        print("Not scored in this pass — every one of these must be scored before the "
              "audit is complete:")
        for _i, _t, _v in unscored:
            print(f"- **{_t}** — {_v}")
    if warnings:
        print()
        print("Merge warnings (read before trusting the scores above):")
        for wmsg in list(warnings)[:10]:
            print(f"- {wmsg}")
    bad = [x for x in (adv or []) if isinstance(x, dict) and x.get("status") in ("FAIL", "WARN")]
    if bad:
        print()
        print("Harbor contract advisories (not rubric-scored, but they break real trials):")
        for x in bad:
            print(f"- [{x.get('status','?')}] {x.get('check','?')}: "
                  f"{' '.join(str(x.get('detail','')).split())[:180]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", required=True)
    ap.add_argument("--verdicts", default=None)
    ap.add_argument("--label", default=None)
    ap.add_argument("--md", action="store_true", help="markdown headings in the detail section")
    ap.add_argument("--relay", action="store_true",
                    help="print ONLY the markdown block to paste into the chat reply: "
                         "task id, every rubric dimension, and the reasons for every non-max score")
    a = ap.parse_args()

    rubric = json.load(open(os.path.join(HERE, "rubric.json")))
    by_id = {r["_id"]: r for r in rubric}
    title_to_id = {r["title"]: r["_id"] for r in rubric}
    try:
        pack = json.load(open(a.pack))
    except Exception as e:
        raise SystemExit(f"cannot read --pack {a.pack}: {e}")
    if not isinstance(pack, dict):
        raise SystemExit(f"--pack {a.pack} is not an evidence pack (expected a JSON object)")
    label = a.label or os.path.basename(a.pack).rsplit(".", 1)[0]
    warnings = []

    def snap(dim_id, score, text):
        """Force the answer back to the rubric's verbatim option.

        A judgment agent returns free text. Losing one bracket turns the rubric's
        explicit `[Non-Fail - ...]` into something that reads as a fail, and the
        paraphrase would be copied onto the auditor form as if it were the option.
        """
        r = by_id.get(dim_id)
        if not r:
            return text, None
        opts = [o for o in r["options"] if o["score"] == score]
        if not opts:
            return text, (f"{r['title']}: score {score} matches no rubric option "
                          f"(valid: {sorted({o['score'] for o in r['options']})})")
        if len(opts) == 1:
            return opts[0]["text"], None
        norm = lambda x: " ".join(str(x or "").lower().split())
        said = norm(text)
        for o in opts:
            m = re.match(r"\s*(\[[^\]]+\])", o["text"])
            if m and norm(m.group(1)) in said:
                return o["text"], None
        best, bestn = opts[0], -1
        for o in opts:
            words = set(norm(o["text"]).split()) - {"the", "a", "an", "and", "or", "of", "to"}
            n = sum(1 for w in words if w in said)
            if n > bestn:
                best, bestn = o, n
        lbl = re.match(r"\s*(\[[^\]]+\])", best["text"])
        return best["text"], (f"{r['title']}: the answer was paraphrased; snapped to "
                              f"{(lbl.group(1) if lbl else best['text'][:40])!r}")

    merged = {}          # dimension_id -> verdict
    for d in pack.get("deterministic", []) or []:
        if not isinstance(d, dict):
            continue
        did = d.get("dimension_id") or title_to_id.get(d.get("title"))
        # Approach A: every dimension is scored by the judgment tier. Legacy mechanical
        # verdicts from the extractor are keyed to the old numbering and are NOT consumed
        # as rubric verdicts here; only dims explicitly tiered "deterministic" would be.
        if _TIERS.get(did) != "deterministic":
            continue
        if did not in by_id:
            warnings.append(f"deterministic verdict for an unknown dimension: {d.get('title')!r}")
            continue
        merged[did] = {"score": d.get("score"), "option": d.get("option") or "",
                       "why": d.get("note") or "", "src": "deterministic",
                       "evidence": d.get("evidence")}

    n_judgment = 0
    if a.verdicts:
        if not os.path.exists(a.verdicts):
            raise SystemExit(f"--verdicts {a.verdicts} does not exist. A missing verdicts file "
                             "would silently produce a deterministic-only report that looks "
                             "like a finished audit.")
        try:
            wf = json.load(open(a.verdicts))
        except Exception as e:
            raise SystemExit(f"cannot read --verdicts {a.verdicts}: {e}")
        if isinstance(wf, dict):
            rows = wf.get("verdicts")
            if rows is None:
                rows = wf.get("result", {}).get("verdicts") if isinstance(wf.get("result"), dict) else None
            rows = rows or []
        elif isinstance(wf, list):
            rows = wf
        else:
            rows = []
        seen_tasks = set()
        for v in rows:
            if not isinstance(v, dict):
                warnings.append("skipped a verdict that is not an object")
                continue
            vt = v.get("task")
            if vt is not None:
                seen_tasks.add(vt)
                # A verdict belonging to another task must never be merged. Omitting
                # --label used to skip this check entirely and pull in every verdict
                # in the file, reporting one task's failures under another's id.
                if vt != label:
                    continue
            did = v.get("dimension_id") or title_to_id.get(v.get("title"))
            if did not in by_id:
                warnings.append(f"judgment verdict for an unknown dimension: "
                                f"{v.get('title') or v.get('dimension_id')!r} (title drift?)")
                continue
            if "final_score" not in v:
                warnings.append(f"{by_id[did]['title']}: judgment verdict has no final_score; skipped")
                continue
            if merged.get(did, {}).get("src") == "deterministic":
                warnings.append(f"{by_id[did]['title']}: a judgment verdict was ignored because "
                                "this dimension is scored mechanically")
                continue
            opt, note = snap(did, v.get("final_score"), v.get("final_option"))
            if note:
                warnings.append(note)
            merged[did] = {"score": v.get("final_score"), "option": opt,
                           "why": v.get("justification"), "src": "judgment",
                           "evidence": v.get("evidence"),
                           "verification": v.get("verification") or {},
                           "initial": v.get("initial_score")}
            n_judgment += 1
        # An independent read of a mechanically-scored dimension. Disagreement is
        # surfaced, never silently resolved: the whole point is that a regex which did
        # not fire must not be mistaken for a verified pass.
        for c in (wf.get("confirmations") or []) if isinstance(wf, dict) else []:
            if not isinstance(c, dict) or c.get("task") not in (None, label):
                continue
            did = c.get("dimension_id") or title_to_id.get(c.get("title"))
            if did not in merged:
                continue
            m = merged[did]
            m["confirm"] = {
                "score": c.get("confirm_score"),
                "option": c.get("confirm_option"),
                "established": c.get("established"),
                "why": c.get("justification"),
                "confidence": c.get("confidence"),
                "agrees": c.get("confirm_score") == m.get("score"),
            }
            if not m["confirm"]["agrees"]:
                warnings.append(
                    f"{by_id[did]['title']}: the mechanical check says "
                    f"{m.get('score')}/5 but an independent read says "
                    f"{c.get('confirm_score')}/5 — settle this before reporting")
        if not n_judgment:
            raise SystemExit(
                f"--verdicts {a.verdicts} produced no usable verdicts for label {label!r}. "
                f"Task labels found in that file: {sorted(seen_tasks) or 'none'}. "
                "Reporting would have printed a deterministic-only result that looks finished.")

    by_title = {by_id[i]["title"]: v for i, v in merged.items()}

    ident = task_identity(pack, label)
    _ff = (pack.get("evidence") or {}).get("form_fields") or {}
    _ff_err = _ff.get("_parse_error")
    # Presence, not truthiness. A submission with blank explanation boxes is exactly what
    # "Explanations - Spam Check" exists to fail; excusing it as NOT ASSESSABLE hid that.
    have = {22: "vulnerability_type" in _ff,
            24: any(k in _ff for k in ("vulnerability_explanation",
                                       "complexity_increase", "model_failure_reason"))}
    lines, fails, unassessed, nonfails = [], [], [], []
    H = "## " if a.md else ""
    for r in rubric:
        t = r["title"]; rid = r["_id"]
        v = by_title.get(t)
        if v is None:
            if rid in NOT_ASSESSABLE and not have.get(rid):
                unassessed.append(t)
                _why = (f"the --fields file could not be parsed ({_ff_err})" if _ff_err
                        else "submission-form fields not provided (they are not part of "
                             "task.tar.gz)")
                lines.append(f"\n{H}Component: {t}\n  Answer: NOT ASSESSABLE — {_why}.\n"
                             f"  Score:  n/a\n  Feedback: Re-run extract_evidence.py with "
                             f"--fields <form_fields.json> to score this.")
                continue
            lines.append(f"\n{H}Component: {t}\n  Answer: NOT SCORED\n  Score: n/a")
            continue
        mx = max(o["score"] for o in r["options"])
        # The rubric distinguishes [Fail - ...] from [Non-Fail - ...]. Dimension 8's
        # score-3 option is explicitly a NON-fail ("right family, imprecise CWE"), so
        # scoring below max must not by itself fail the bundle.
        nonfail = bool(re.match(r"\s*\[Non-?Fail", str(v.get("option") or ""), re.I))
        is_fail = v["score"] < mx and not nonfail
        if is_fail:
            fails.append((t, v))
        elif v["score"] < mx:
            nonfails.append((t, v))
        flag = "   <<< FAIL" if is_fail else ("   (non-fail)" if v["score"] < mx else "")
        lines.append(f"\n{H}Component: {t}{flag}")
        lines.append(f"  Answer: {v['option']}")
        lines.append(f"  Score:  {v['score']}/5   [{v['src']}]")
        # Every dimension's description ends "For all options except the last, apply
        # the error category." Give the reviewer the category they must apply.
        if v["score"] < mx and r.get("error_categories"):
            lines.append(f"  Error category to apply: {r['error_categories']}")
        _c = v.get("confirm")
        if _c:
            mark = "agrees" if _c.get("agrees") else "DISAGREES"
            lines.append(f"  Independent read: {mark} ({_c.get('score')}/5, "
                         f"confidence {_c.get('confidence')})")
            if _c.get("established"):
                lines.append(f"    established: {' '.join(str(_c['established']).split())[:400]}")
            if not _c.get("agrees"):
                lines.append(f"    their reasoning: {' '.join(str(_c.get('why') or '').split())[:300]}")
        for _why in _open_questions(v.get("evidence")):
            lines.append(f"  OPEN QUESTION: {_why[:400]}")
        if v.get("initial") is not None and v["initial"] != v["score"]:
            lines.append(f"  Note:   initial {v['initial']}/5, changed by adversarial verification")
        fb = feedback_for(v, mx)
        lines.append(f"  Feedback: {fb[:900] or 'No feedback.'}")
        if v.get("evidence") and v["src"] == "judgment":
            for e in (v["evidence"] or [])[:4]:
                lines.append(f"     - {str(e)[:200]}")
        if (v.get("verification") or {}).get("kind") not in (None, "none"):
            ver = v["verification"] or {}
            lines.append(f"  Verification: {ver['kind']} "
                         f"{ver.get('refutes', ver.get('found', 0))}/{ver.get('total')} "
                         f"flipped={ver.get('flipped')}"
                         + ("  TIEBROKEN" if ver.get("tiebroken") else ""))
            if ver.get("contested"):
                lines.append("  CONTESTED: the verifiers disagreed. Settle this on the merits "
                             "before reporting it; do not accept the majority by default.")

    ev = pack.get("evidence") or {}
    adv = [x for x in (ev.get("harbor_advisories") or []) if isinstance(x, dict)]
    if warnings:
        print("MERGE WARNINGS (read these before trusting the scores):")
        for wmsg in warnings[:10]:
            print(f"  ! {wmsg}")
        print()
    if a.relay:
        emit_relay(rubric, by_title, ident, have, adv, warnings)
        return

    print("=" * 96)
    print(f"QC AUDIT — task id: {ident['task_id']}")
    print(f"  attempt id : {ident['attempt_id'] or '(none in the path — bundle name used)'}")
    print(f"  bundle     : {ident['bundle']}")
    print(f"  task name  : {ident['name']}")
    print(f"  cwe / kind : {ident['cwe']}   {str(ident['vulnerability_kind'])[:55]}")
    print(f"  task root  : {ident['task_root']}")
    print("=" * 96)
    # A complete table, ALWAYS. The detail below can be long, and summarising it
    # to "the interesting dimensions" loses the answer for the rest.
    print(f"\nALL {N_DIMS} RUBRIC DIMENSIONS")
    print("-" * 96)
    print(f"  {'#':<3} {'SCORE':<6} {'VERDICT':<10} {'SRC':<14} DIMENSION")
    print("-" * 96)
    for r in rubric:
        v = by_title.get(r["title"])
        mx = max(o["score"] for o in r["options"])
        if v is None:
            na = r["_id"] in NOT_ASSESSABLE and not have.get(r["_id"])
            sc, vd, src = "n/a", "-", ("NOT ASSESSABLE" if na else "NOT SCORED")
        else:
            nf = bool(re.match(r"\s*\[Non-?Fail", str(v.get("option") or ""), re.I))
            vd = "PASS" if v["score"] == mx else ("NON-FAIL" if nf else "FAIL")
            sc, src = f"{v['score']}/{mx}", v["src"]
        print(f"  {r['_id']:<3} {sc:<6} {vd:<10} {src:<14} {r['title']}")
    print("-" * 96)

    print("\n".join(lines))
    print("\n" + "=" * 96)
    scored = [r for r in rubric if r["title"] in by_title]
    _na = sum(1 for r in rubric if r["_id"] in NOT_ASSESSABLE
              and r["title"] not in by_title and not have.get(r["_id"]))
    _unrun = len(rubric) - len(scored) - _na
    _overall = "FAIL" if fails else ("INCOMPLETE" if _unrun else "PASS")
    _atmax = sum(1 for r in rubric if r["title"] in by_title
                 and by_title[r["title"]]["score"] == max(o["score"] for o in r["options"]))
    print(f"OVERALL: {_overall}   for task id {ident['task_id']}   "
          f"({_atmax}/{len(scored)} scored dimensions at max score; "
          f"{_unrun} never scored, {_na} not assessable)")
    if _overall == "INCOMPLETE":
        print("  Nothing failed yet, but the audit is not finished — score the remaining "
              "dimensions before calling this a pass.")
    if fails:
        print("Failing dimensions:")
        for t, v in fails:
            print(f"  - {t}  ({v['score']}/5)")
    if nonfails:
        print("Non-fail deductions (do NOT fail the bundle):")
        for t, v in nonfails:
            print(f"  - {t}  ({v['score']}/5)")
    if unassessed:
        print(f"Not assessable without form fields: {', '.join(unassessed)}")
    print("=" * 96)
    if adv:
        bad = [x for x in adv if x.get("status") in ("FAIL", "WARN")]
        print("\nHARBOR CONTRACT ADVISORIES (not rubric-scored — these break real trials)")
        print("-" * 96)
        for row in adv:
            inf = f"  ({row['informs']})" if row.get("informs") else ""
            st = str(row.get("status", "?")); ck = str(row.get("check", "?"))
            print(f"  [{st:<6}] {ck:<24} {str(row.get('detail',''))[:100]}{inf}")
            if row.get("fix") and st in ("FAIL", "WARN", "REVIEW"):
                print(f"           fix: {str(row['fix'])[:150]}")
        print("-" * 96)
        print(f"  {len(bad)} advisory item(s) need attention. These do NOT change the QC score,")
        print("  but a FAIL here silently breaks every Harbor trial.")
        print("=" * 96)


if __name__ == "__main__":
    main()
