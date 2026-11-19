import argparse
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from .runner import run, summarize


def main():
    ap = argparse.ArgumentParser(prog="cyber_quality_check")
    ap.add_argument("target", help="task directory or .zip")
    ap.add_argument("--json", help="write full JSON report to this path")
    args = ap.parse_args()

    target = Path(args.target)
    cleanup = None
    if target.suffix == ".zip":
        tmp = Path(tempfile.mkdtemp(prefix="cyber_quality_check_"))
        with zipfile.ZipFile(target) as zf:
            zf.extractall(tmp)
        entries = list(tmp.iterdir())
        task_dir = entries[0] if len(entries) == 1 and entries[0].is_dir() else tmp
        cleanup = tmp
        archive_name = target.name
    else:
        task_dir = target
        archive_name = target.name

    results = run(task_dir, archive_name)

    for r in results:
        print(f"[{r['verdict']:6}] {r['id']:6} {r['title']}")
        print(f"         {r['detail']}")
        for e in r["evidence"][:5]:
            print(f"         - {e}")
        print()

    print("Summary:", summarize(results))

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))

    if cleanup:
        shutil.rmtree(cleanup, ignore_errors=True)


if __name__ == "__main__":
    main()
