#!/usr/bin/env python3
"""taskgooner preflight -- deterministic floor checks for the dual-gate QC rubric.

Catches the objective, mechanical fails fast so the LLM-judged qc-audit run can
focus on the judgment dimensions. NOT a verdict: it cannot judge realism,
discoverability, decoy strength or difficulty. Exit non-zero on any FAIL.

    python3 preflight.py <TASK_DIR | task.tar.gz | task.zip>
"""
from __future__ import annotations
import json, os, re, sys, tarfile, tempfile, zipfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # py<3.11
    tomllib = None

FAILS: list[str] = []
WARNS: list[str] = []
OKS: list[str] = []

def fail(dim, msg): FAILS.append(f"[FAIL] {dim}: {msg}")
def warn(dim, msg): WARNS.append(f"[WARN] {dim}: {msg}")
def ok(dim, msg): OKS.append(f"[ok]   {dim}: {msg}")

# vulnerability-class synonyms keyed by CWE, for the VU4 leak grep.
CWE_SYNONYMS = {
    "22": [r"path\s*traversal", r"directory\s*traversal", r"\.\./ escape"],
    "89": [r"sql\s*inject", r"\bsqli\b"],
    "918": [r"\bssrf\b", r"server-?side request forgery"],
    "639": [r"\bidor\b", r"\bbola\b", r"insecure direct object", r"broken object"],
    "915": [r"mass\s*assign"],
    "200": [r"\binformation (?:exposure|disclosure)\b", r"\benv(?:ironment)? leak\b"],
    "77": [r"command\s*inject"], "78": [r"os command inject", r"command\s*inject"],
    "79": [r"\bxss\b", r"cross-?site scripting"],
    "287": [r"auth(?:entication)? bypass"], "502": [r"insecure deserial", r"deserial"],
}
GENERIC_LEAK = [r"\bcwe-?\d{2,4}\b"]

def load_task(arg: str) -> Path:
    p = Path(arg)
    if p.is_dir():
        return (p / "task") if (p / "task" / "task.toml").exists() else p
    tmp = Path(tempfile.mkdtemp(prefix="tg-pre-"))
    if arg.endswith((".tar.gz", ".tgz")):
        tarfile.open(arg).extractall(tmp)
    elif arg.endswith(".zip"):
        zipfile.ZipFile(arg).extractall(tmp)
    else:
        sys.exit(f"unrecognized input: {arg}")
    cands = [d.parent for d in tmp.rglob("task.toml")]
    if not cands:
        sys.exit("no task.toml inside the archive")
    return sorted(cands, key=lambda d: len(d.parts))[0]

def read(p: Path) -> str:
    try: return p.read_text(errors="replace")
    except OSError: return ""

def grep(p: Path, pat: str, flags=re.I):
    out = []
    for i, line in enumerate(read(p).splitlines(), 1):
        if re.search(pat, line, flags):
            out.append((i, line.strip()))
    return out

def check_f1(t: Path):
    required = [
        "task.toml", "instruction.md", "instruction_L0.md", "instruction_L1.md",
        "instruction_L2.md", "fresh_state.json", "environment/docker-compose.yaml",
        "environment/NOTICE.md", "solution/solve.sh", "tests/test.sh",
        "tests/isolation_test.sh", "tests/agent_judge_prompt.md",
        "tests/run_report_rubric.sh", "tests/run_report_rubric.py",
        "operator/behavior-catalog.json", "operator/report-rubric.json",
    ]
    miss = [f for f in required if not (t / f).exists() or (t / f).stat().st_size == 0]
    if miss: fail("F1", "missing/empty required file(s): " + ", ".join(miss))
    else: ok("F1", "all required dual-gate files present and non-empty")
    if (t / "tests/judge_prompt_template.md").exists():
        fail("F1", "tests/judge_prompt_template.md must be renamed to tests/agent_judge_prompt.md")
    for forb in ["trajectories/pass@k/rubric.json", "trajectories/pass@k/trajectory_analysis_report.md"]:
        if (t / forb).exists():
            fail("F1", f"{forb} must NOT exist in the dual-gate format (operator/ holds the gate specs)")
    for s in ["solution/solve.sh", "tests/test.sh", "tests/isolation_test.sh"]:
        sp = t / s
        if sp.exists():
            exe = os.access(sp, os.X_OK) or read(sp).startswith("#!")
            if not exe: fail("F1", f"{s} has neither exec bit nor shebang")

def check_f2(t: Path):
    c = t / "environment/docker-compose.yaml"
    if not c.exists(): return
    txt = read(c)
    if not re.search(r"^\s{2}main:\s*$", txt, re.M) and not re.search(r"^\s*main:\s*$", txt, re.M):
        fail("F2", "no service named exactly `main` in docker-compose.yaml")
    else: ok("F2", "`main` service present")
    for i, line in enumerate(txt.splitlines(), 1):
        if re.search(r'"\s*\d+\.\d+\.\d+\.\d+\s*:\s*\d+\s*:\s*\d+', line) or re.search(r"-\s*\"?\d+:\d+\"?\s*$", line):
            if "ports" in txt.splitlines()[max(0, i-2)] or re.search(r"-\s*\"?\d+:\d+", line):
                warn("F2", f"docker-compose.yaml:{i}: possible static host port -> {line.strip()}")
        if "ipv4_address" in line or re.search(r"\bsubnet:", line):
            fail("F2", f"docker-compose.yaml:{i}: static IP/subnet -> {line.strip()}")

def check_reward(t: Path):
    ts = t / "tests/test.sh"
    if not ts.exists(): return
    txt = read(ts)
    for k in ("behavior", "report_rubric", "reward"):
        if k not in txt: fail("F5/EV3", f"test.sh never mentions `{k}` key")
    if '"reason"' in txt and "reward.json" in txt:
        # only flag if a reason key is written INTO reward.json
        for i, line in enumerate(txt.splitlines(), 1):
            if "reward.json" in line and '"reason"' in line:
                fail("F5", f"test.sh:{i}: reward.json carries a string `reason` key (breaks pass@k)")
    # The canonical EV3 bug: a real-trial reward that is a hardcoded 1 instead of
    # being gated on report_rubric. Only meaningful on a B/R task (has the SKIP
    # branch for oracle/noop). The reward is correctly ANDed only when a
    # conditional ties REWARD to RR_SCORE (e.g. `[ "$RR_SCORE" = "1.0" ]`).
    is_br = "SKIP_REPORT_RUBRIC" in txt and "RR_SCORE" in txt
    sets_reward_const = bool(re.search(r'REWARD\s*=\s*"?1(\.0)?"?', txt))
    gated = bool(re.search(r'RR_SCORE"?\s*=\s*"?1(\.0)?"?', txt)) or \
            bool(re.search(r'reward\s*=\s*behavior\s+AND\s+report', txt, re.I))
    if is_br and sets_reward_const and not gated:
        for i, line in enumerate(txt.splitlines(), 1):
            if re.search(r'REWARD\s*=\s*"?1(\.0)?"?', line):
                fail("F5/EV3", f"test.sh:{i}: real-trial REWARD hardcoded to 1, not gated on report_rubric "
                               f"(reward must equal behavior AND report_rubric) -> {line.strip()}")
                break
    elif gated:
        ok("F5/EV3", "test.sh derives reward from behavior AND report_rubric")
    # fail-safe on ungradable report
    if "SKIP_REPORT_RUBRIC" not in txt:
        warn("F5", "test.sh has no SKIP_REPORT_RUBRIC branch for oracle/noop reference runs")

def check_f6(t: Path):
    comp = read(t / "environment/docker-compose.yaml")
    imgs = re.findall(r"image:\s*(\S+)", comp)
    for im in imgs:
        if "@sha256:" not in im:
            fail("F6/EN4", f"compose image not digest-pinned: {im}")
    for df in t.rglob("Dockerfile"):
        for i, line in enumerate(read(df).splitlines(), 1):
            m = re.match(r"\s*FROM\s+(\S+)", line, re.I)
            if m and "@sha256:" not in m.group(1) and not m.group(1).startswith("$"):
                fail("F6/EN4", f"{df.relative_to(t)}:{i}: FROM not digest-pinned -> {m.group(1)}")
    if not imgs or all("@sha256:" in i for i in imgs):
        ok("F6", "compose images digest-pinned")
    # task.toml ceilings + non-root agent + no agent timeout
    tt = read(t / "task.toml")
    for key in ("cpus", "memory_mb", "storage_mb"):
        if key not in tt: warn("F6", f"task.toml: no `{key}` ceiling declared")
    if tomllib:
        try:
            d = tomllib.loads(tt)
            au = d.get("agent", {})
            if au.get("user", "root") == "root": fail("F6", "task.toml [agent] user is root (need non-root)")
            else: ok("F6", f"non-root agent user = {au.get('user')!r}")
            if "timeout_sec" in au:
                fail("convention", "task.toml [agent] has timeout_sec -- remove it (100-turn cap governs)")
            else: ok("convention", "no [agent] timeout_sec (100-turn cap)")
        except Exception as e:
            fail("F1", f"task.toml does not parse: {e}")
    fs = t / "fresh_state.json"
    if fs.exists():
        try: json.loads(read(fs)); ok("F6", "fresh_state.json valid JSON")
        except Exception as e: fail("F6/F1", f"fresh_state.json invalid: {e}")

def check_en3(t: Path):
    targets = [t / "environment/docker-compose.yaml"]
    targets += list((t / "environment").rglob("*.env")) + list((t / "environment").rglob(".env"))
    hit = False
    for f in targets:
        for i, line in grep(f, r"(ROOT_PASSWORD|_PASSWORD|_SECRET|_KEY)\s*[:=]\s*\S"):
            if re.search(r"\$\{|\$\(|urandom|token_hex|openssl|/dev/urandom|random_bytes", line): continue
            if re.search(r"(PASSWORD|SECRET|KEY)\s*[:=]\s*['\"]?[A-Za-z0-9_.-]{1,40}['\"]?\s*$", line):
                fail("EN3", f"{f.relative_to(t)}:{i}: literal privileged credential -> {line}")
                hit = True
    if not hit: ok("EN3", "no literal privileged credential in compose/.env")

def check_vu4(t: Path):
    cwe = ""
    m = re.search(r'cwe\s*=\s*"CWE-(\d+)"', read(t / "task.toml"), re.I)
    if m: cwe = m.group(1)
    pats = CWE_SYNONYMS.get(cwe, []) + GENERIC_LEAK
    forbidden = [t / "instruction_L0.md", t / "instruction_L1.md"]
    env = t / "environment"
    src = [p for p in env.rglob("*") if p.suffix in (".py", ".php", ".js", ".sh", ".conf", ".ini")
           and "vendor-wheels" not in str(p) and p.name != "NOTICE.md"]
    hit = False
    for f in forbidden + src:
        for pat in pats:
            for i, line in grep(f, pat):
                if ".tgz" in line or "glpi-10" in line: continue
                fail("VU4", f"{f.relative_to(t)}:{i}: class-name/CWE leak (/{pat}/) -> {line}")
                hit = True
    if not hit: ok("VU4", f"no class-name/CWE leak in L0/L1/app-source (cwe={cwe or '?'})")

def check_rb1(t: Path):
    f = t / "operator/behavior-catalog.json"
    if not f.exists(): return
    try: d = json.loads(read(f))
    except Exception as e: return fail("RB1", f"behavior-catalog.json invalid JSON: {e}")
    req = ["id", "severity", "semantic_effect", "stages", "behavior_oracle", "equivalent_paths", "primary_success"]
    for b in d.get("behaviors", []):
        miss = [k for k in req if k not in b]
        if miss: fail("RB1", f"behavior-catalog behavior missing fields: {miss}")
        if b.get("primary_success") != "B AND R":
            fail("RB1", f'primary_success is {b.get("primary_success")!r}, must be "B AND R"')
    if not FAILS or all("RB1" not in x for x in FAILS):
        ok("RB1", "behavior-catalog well-formed; primary_success = 'B AND R'")

def check_rb2(t: Path):
    f = t / "operator/report-rubric.json"
    if not f.exists(): return
    try: d = json.loads(read(f))
    except Exception as e: return fail("RB2", f"report-rubric.json invalid JSON: {e}")
    for sec in ["required_per_finding", "evidence_binding", "reject_when", "descriptions"]:
        if sec not in d: fail("RB2", f"report-rubric missing section `{sec}`")
    seven = {"title", "affected_workflow", "access_preconditions", "reproduction_steps",
             "observed_evidence", "impact", "remediation"}
    if seven - set(d.get("required_per_finding", [])):
        fail("RB2", f"required_per_finding missing: {sorted(seven - set(d.get('required_per_finding', [])))}")
    descs = d.get("descriptions", {})
    if "expected_finding" not in descs: fail("RB2", "descriptions lacks `expected_finding`")
    if all("RB2" not in x for x in FAILS): ok("RB2", "report-rubric well-formed; 7 finding fields + descriptions")

def check_ev5(t: Path):
    f = t / "tests/isolation_test.sh"
    if not f.exists(): return
    txt = read(f).lower()
    cover = {"application source": any(k in txt for k in ("app.py", "source", "/var/www", "document.send")),
             "tests/": "tests" in txt or "test.sh" in txt,
             "solution/": "solve.sh" in txt or "solution" in txt,
             "credentials": "verifier_token" in txt or "marker" in txt}
    missing = [k for k, v in cover.items() if not v]
    if missing: fail("EV5", f"isolation_test.sh does not cover: {missing}")
    else: ok("EV5", "isolation_test.sh covers source, tests, solution, credentials")

def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    t = load_task(sys.argv[1])
    print(f"# taskgooner preflight -- {t}\n")
    for fn in (check_f1, check_f2, check_reward, check_f6, check_en3,
               check_vu4, check_rb1, check_rb2, check_ev5):
        try: fn(t)
        except Exception as e: warn(fn.__name__, f"check raised {e!r}")
    for line in OKS: print(line)
    for line in WARNS: print(line)
    for line in FAILS: print(line)
    print(f"\n{len(OKS)} ok, {len(WARNS)} warn, {len(FAILS)} FAIL")
    print("Preflight is a floor, not the verdict -- run the qc-audit skill for the 30-dim judgment.")
    sys.exit(1 if FAILS else 0)

if __name__ == "__main__":
    main()
