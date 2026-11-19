import csv
import re
from pathlib import Path

REFERENCE_CSV = Path(__file__).parent / "reference" / "QC_rubric_V11.csv"

_ID_RE = re.compile(r"\{([A-Za-z0-9]+)\}")


def load_rubric(path: Path = REFERENCE_CSV):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    dimensions = {}
    cur = None
    for row in rows:
        title = row.get("title", "").strip()
        if title:
            m = _ID_RE.search(title)
            dim_id = m.group(1) if m else title.split(" - ")[-1].strip()
            cur = {
                "id": dim_id,
                "title": title,
                "questionText": row.get("questionText", "").strip(),
                "questionDescription": row.get("questionDescription", "").strip(),
                "options": [],
            }
            dimensions[dim_id] = cur
        if cur is not None and row.get("answerOptionText", "").strip():
            score_raw = row.get("answerOptionScore", "").strip()
            cur["options"].append({
                "text": row["answerOptionText"].strip(),
                "score": int(score_raw) if score_raw.isdigit() else 0,
            })
    return dimensions
