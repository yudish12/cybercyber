#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chain_finder.py  --  CROSS-DIMENSION discovery-chain trace (feeds VU3, VU4, EV4 together).

Root cause of repeated misses: dimensions were judged in isolation. This builds ONE ordered
hop map of the intended solve and, per hop, flags whether its locator is (a) discoverable via a
SERVED response somewhere, and (b) OVER-SERVED at L0 (robots.txt / unauth route / shipped tier).
The reader then traces the chain hop-by-hop:
  * a hop with NO served-in  -> VU4 [Undiscoverable]
  * a LATER hop served at L0  -> VU3 [Non-Monotonic] (pivot delivered as L0 service content)
  * whole chain short + every hop served/mechanical -> EV4 [Too Easy For Pass@k]

Usage:  python3 -I chain_finder.py <task_dir> [--json OUT]
"""
import os, re, sys, json, io
HERE = os.path.dirname(os.path.abspath(__file__))
_SRC_EXT = (".py", ".php", ".ts", ".js", ".go", ".rb")
_SERVED_RE = re.compile(r"\breturn\b|jsonify|\bprint\b|\becho\b|render|Response\(|\.write\(", re.I)
_REQ_RE = re.compile(r"https?://|\$\{?BASE\}?|\bcurl\b|post_json|get_json|\bwget\b|\bget\(|\bpost\(")
_NOISE = {"logs","verifier","tmp","api","dev","etc","work","opt","bin","var","www","health","index","json","php"}


def _read(p):
    try: return io.open(p,"r",encoding="utf-8",errors="replace").read()
    except Exception: return ""


def _hops(task_dir):
    solve=_read(os.path.join(task_dir,"solution","solve.sh"))+"\n"+_read(os.path.join(task_dir,"solution","solve.py"))
    hops=[]
    have=lambda v: v in [h["seg"] for h in hops]
    for ln in solve.splitlines():
        # /path endpoints only from request-shaped lines
        if _REQ_RE.search(ln):
            for m in re.finditer(r"(?:\$\{?BASE\}?|https?://[^/\s\"']+|[\"'])(/[A-Za-z0-9_\-/.]+)",ln):
                for seg in m.group(1).strip("/").split("/"):
                    if len(seg)>=3 and not seg.isdigit() and seg.lower() not in _NOISE and not have(seg):
                        hops.append({"seg":seg})
        # query-param / dict endpoints from ANY line (sink params live in dict literals: "option":"com_content", "filter_order":payload)
        for qm in re.finditer(r"[\"']?(option|view|task|filter_order|layout)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_.]+)",ln):
            v=qm.group(2)
            # skip SQLi payload tokens (not discovery hops): extractvalue, a.title, payload var, etc.
            if "." in v or re.fullmatch(r"(payload|extractvalue|updatexml|sleep|union|select|concat|if|hex|version)", v, re.I):
                continue
            if v.lower() not in _NOISE and not have(v):
                hops.append({"seg":v})
    return hops


def _served_and_L0(task_dir):
    """Return (served_segment_set, L0_segment_text). served = segments appearing inside a served
    response in app source; L0 = text of robots.txt + shipped tier + unauth-reachable bodies."""
    env=os.path.join(task_dir,"environment"); served=set(); l0=[]
    for n in ("instruction.md","instruction_L0.md"):
        l0.append(_read(os.path.join(task_dir,n)))
    for dp,_s,fns in os.walk(env):
        for fn in fns:
            if os.path.splitext(fn)[1].lower() not in _SRC_EXT: continue
            lines=_read(os.path.join(dp,fn)).splitlines()
            for i,line in enumerate(lines):
                if any(_SERVED_RE.search(w) for w in lines[max(0,i-5):i+1]):
                    for m in re.finditer(r"[A-Za-z0-9_\-]{3,}",line):
                        served.add(m.group(0))
                if "robots" in fn.lower() or "Disallow" in line:
                    l0.append(line)
    return served, "\n".join(l0)


def find(task_dir):
    hops=_hops(task_dir)
    served,l0=_served_and_L0(task_dir)
    entry=hops[0]["seg"] if hops else None
    rows=[]
    for idx,h in enumerate(hops):
        seg=h["seg"]
        served_in = seg in served
        over_l0 = bool(re.search(r"\b"+re.escape(seg)+r"\b", l0))
        rows.append({"hop":idx+1,"seg":seg,"served_in":served_in,"over_served_L0":over_l0,
                     "entry":idx==0})
    undiscoverable=[r["seg"] for r in rows if not r["entry"] and not r["served_in"] and not r["over_served_L0"]]
    over_served=[r["seg"] for r in rows if not r["entry"] and r["over_served_L0"]]
    return {"task_dir":os.path.abspath(task_dir),"entry":entry,"chain":rows,
            "vu4_undiscoverable_hops":undiscoverable,
            "vu3_overserved_at_L0_hops":over_served,
            "ev4_chain_len":len(hops),
            "note":"reader traces hop-by-hop: no served-in -> VU4; a later hop over-served at L0 -> VU3; "
                   "short all-served chain -> EV4. Query-param/filter_order endpoints included."}


def _summary(r):
    o=[f"CHAIN TRACE — {r['task_dir']}", f"  entry: {r['entry']}  hops: {r['ev4_chain_len']}"]
    for c in r["chain"]:
        tag="ENTRY" if c["entry"] else ("OVER-SERVED@L0" if c["over_served_L0"] else ("served" if c["served_in"] else "UNDISCOVERABLE"))
        o.append(f"    hop{c['hop']} {c['seg']:24} {tag}")
    o.append(f"  VU4 undiscoverable hops: {r['vu4_undiscoverable_hops']}")
    o.append(f"  VU3 over-served-at-L0 hops: {r['vu3_overserved_at_L0_hops']}")
    return "\n".join(o)


def main(argv):
    if not argv or not os.path.isdir(argv[0]):
        print("usage: chain_finder.py <task_dir> [--json OUT]",file=sys.stderr); return 2
    r=find(argv[0])
    if "--json" in argv: json.dump(r,open(argv[argv.index("--json")+1],"w"),indent=2)
    print(_summary(r)); return 0


if __name__=="__main__":
    sys.exit(main(sys.argv[1:]))
