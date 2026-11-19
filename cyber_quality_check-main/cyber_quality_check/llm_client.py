import json
import os
import socket
import urllib.error
import urllib.request


class LLMNotConfigured(RuntimeError):
    pass


class LLMRefusal(RuntimeError):
    pass


PRIMARY_MODEL = "mistral/deepseek-v4-1-flash-1017"
FALLBACK_MODEL = "anthropic/claude-sonnet-5"


VERDICT_TOOL = {
    "type": "function",
    "function": {
        "name": "submit_verdict",
        "description": "Submit the chosen rubric answer option, its score, and a justification.",
        "parameters": {
            "type": "object",
            "properties": {
                "option": {"type": "string", "description": "The verbatim option text or fail-category label"},
                "score": {"type": "integer"},
                "justification": {"type": "string"},
            },
            "required": ["option", "score", "justification"],
        },
    },
}


# Errors that mean "this attempt didn't get a usable answer" (as opposed to
# LLMNotConfigured, which means retrying/falling back can't possibly help).
_RETRYABLE_ERRORS = (ValueError, urllib.error.URLError, socket.timeout, TimeoutError)


def _call_once(system: str, user: str, max_tokens: int, api_key: str, base_url: str, model: str, timeout: int) -> dict:
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "tools": [VERDICT_TOOL],
        "tool_choice": "auto",
    }
    req = urllib.request.Request(
        base_url + "/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "authorization": "Bearer " + api_key,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    if (data.get("stop_details") or {}).get("type") == "refusal":
        raise LLMRefusal(f"model {model!r} refused: {json.dumps(data)[:300]!r}")
    choices = data.get("choices") or [{}]
    message = choices[0].get("message") or {}
    for call in message.get("tool_calls") or []:
        fn = call.get("function") or {}
        if fn.get("name") == "submit_verdict":
            try:
                return json.loads(fn.get("arguments", "{}"))
            except json.JSONDecodeError as e:
                raise ValueError(f"submit_verdict arguments not valid JSON: {fn.get('arguments')!r}") from e
    raise ValueError(f"no submit_verdict tool call in LLM response: {json.dumps(data)[:300]!r}")


def _try_model(system: str, user: str, max_tokens: int, api_key: str, base_url: str, model: str,
               retries: int, timeout: int) -> dict:
    last_err = None
    for attempt in range(retries + 1):
        try:
            return _call_once(system, user, max_tokens, api_key, base_url, model, timeout)
        except LLMRefusal:
            raise  # a content-policy refusal is deterministic -- retrying the same model won't help
        except _RETRYABLE_ERRORS as e:
            last_err = e
    raise last_err


def call_llm_verdict(system: str, user: str, max_tokens: int = 20000, retries: int = 1, timeout: int = 60) -> dict:
    """Any primary-model failure (timeout, network/HTTP error, malformed response, or
    refusal) falls through to the fallback model -- a slow/unresponsive primary is
    exactly the case the fallback exists for, not just explicit refusals. `timeout`
    and `retries` are kept small because this runs 8-16 at a time inside a single
    serverless invocation with a fixed wall-clock budget (vercel.json maxDuration):
    a per-model retry loop that eats minutes compounds across every concurrent check
    and was blowing that budget, producing an upstream 504 instead of a result."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise LLMNotConfigured("ANTHROPIC_API_KEY is not set in the environment")

    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    if base_url.endswith("/v1"):
        base_url = base_url[: -len("/v1")]
    model = os.environ.get("CYBER_QC_MODEL", PRIMARY_MODEL)
    fallback_model = os.environ.get("CYBER_QC_FALLBACK_MODEL", FALLBACK_MODEL)

    try:
        return _try_model(system, user, max_tokens, api_key, base_url, model, retries, timeout)
    except Exception as primary_err:
        if not fallback_model:
            raise
        try:
            return _try_model(system, user, max_tokens, api_key, base_url, fallback_model, retries, timeout)
        except Exception as fallback_err:
            raise fallback_err from primary_err
