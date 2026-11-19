from pathlib import Path

from .checks import DIR_CHECKS
from .checks.llm_checks import check_f4_llm
from .report import result

VERDICT_ORDER = {"FAIL": 0, "ERROR": 0, "PASS": 1}


def run(task_dir: Path, archive_name: str):
    results = []
    for fn in DIR_CHECKS:
        try:
            results.append(fn(task_dir))
        except Exception as e:
            results.append(result(fn.__name__, fn.__name__, "ERROR", str(e)))
    try:
        results.append(check_f4_llm(task_dir, archive_name))
    except Exception as e:
        results.append(result("F4", "Metadata Consistency", "ERROR", str(e)))

    results.sort(key=lambda r: VERDICT_ORDER.get(r["verdict"], 2))
    return results


def summarize(results):
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return counts
