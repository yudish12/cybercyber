from pathlib import Path


def read(p: Path) -> str:
    try:
        return p.read_text(errors="ignore")
    except Exception:
        return ""


def result(id_, title, verdict, detail, evidence=None):
    return {"id": id_, "title": title, "verdict": verdict, "detail": detail, "evidence": evidence or []}
