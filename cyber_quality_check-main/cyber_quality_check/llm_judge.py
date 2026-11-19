from .llm_client import LLMNotConfigured, call_llm_verdict
from .report import result
from .rubric_loader import load_rubric

JUDGE_SYSTEM = (
    "You are a strict QC reviewer for Harbor cybersecurity task packages. "
    "You are given one rubric dimension (question, description, and the exact scored answer "
    "options) plus evidence gathered from the task's own files. "
    "First, read every line of the evidence shown carefully, not just the first screenful -- "
    "evidence relevant to the verdict is often buried past the first few lines. When a rubric "
    "option asks whether a term, class name, or format string appears somewhere, treat a "
    "misspelling or near-miss variant of the term (e.g. 'transversal' for 'traversal') as a match "
    "if a human reader would recognize it as the same word; do not rely on an exact literal "
    "substring match alone for this kind of question. "
    "Then pick exactly one answer option from the list and quote its bracketed fail-category label "
    "verbatim if it has one (e.g. '[Fail - Required Structure]'), or quote the passing option's "
    "text if nothing failed. "
    "Ground your justification only in the evidence shown, citing specific files or lines. "
    "If the evidence shown is insufficient to fully confirm a dimension that normally needs a "
    "live boot or a human-navigated walkthrough, do not guess a pass: pick the closest fail "
    "option and say plainly in the justification that this could not be confirmed from static "
    "evidence alone, same as this rubric's own fail-closed default for unconfirmed state. "
    "Keep the justification short, plain prose, no em dashes. "
    "You must always finish by calling the submit_verdict tool exactly once with your answer -- "
    "never end your turn with only plain text."
)

_RUBRIC = None


def _rubric():
    global _RUBRIC
    if _RUBRIC is None:
        _RUBRIC = load_rubric()
    return _RUBRIC


def judge_dimension(dim_id: str, evidence: dict, dim_override: dict = None):
    """dim_override lets a custom (non-V11) dimension reuse the same LLM-judge call and
    pass/fail scoring logic without needing a row in the bundled rubric CSV -- the override
    dict must have the same shape load_rubric() produces (title, questionText,
    questionDescription, options)."""
    dim = dim_override if dim_override is not None else _rubric().get(dim_id)
    if dim is None:
        return result(dim_id, dim_id, "ERROR", f"dimension {dim_id!r} not found in bundled rubric")

    options_text = "\n\n".join(f"- (score {o['score']}) {o['text']}" for o in dim["options"])
    evidence_text = "\n\n".join(f"=== {name} ===\n{content}" for name, content in evidence.items()) or "(no evidence files found)"
    user = (
        f"Dimension: {dim_id} -- {dim['title']}\n\n"
        f"Question: {dim['questionText']}\n\n"
        f"Description:\n{dim['questionDescription']}\n\n"
        f"Answer options:\n{options_text}\n\n"
        f"Evidence from the task:\n{evidence_text}\n"
    )

    try:
        parsed = call_llm_verdict(JUDGE_SYSTEM, user)
    except LLMNotConfigured as e:
        return result(dim_id, dim["title"], "ERROR", f"LLM not configured: {e}")
    except Exception as e:
        return result(dim_id, dim["title"], "ERROR", f"LLM call failed: {e}")

    score = parsed.get("score")
    max_score = max((o["score"] for o in dim["options"]), default=5)
    verdict = "PASS" if score == max_score else "FAIL"
    detail = parsed.get("option", "(no option returned)")
    return result(dim_id, dim["title"], verdict, detail, [parsed.get("justification", "")])
