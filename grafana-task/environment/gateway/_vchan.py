"""Verifier-token channel helper — FROZEN building block. Import it; never copy
its logic into a task.

The verifier token is the per-boot, unforgeable secret the grader uses to trust
the gateway's audit. It is written to /vchan/verifier_token chmod 600 (root-only),
on a Docker volume shared with the verifier (which runs as root). The non-root
agent cannot read it, so it cannot forge the audit. See
skills/scale_dev/verifier_channel.md.
"""
import os
import secrets

VCHAN_DIR = os.environ.get("VCHAN_DIR", "/vchan")
_TOKEN_PATH = os.path.join(VCHAN_DIR, "verifier_token")


def mint_verifier_token() -> str:
    """Mint (or reuse VERIFIER_TOKEN) the per-boot token and write it root-only
    to /vchan/verifier_token. Call once per boot, from the gateway setup.py."""
    tok = os.environ.get("VERIFIER_TOKEN") or secrets.token_hex(32)
    try:
        os.makedirs(VCHAN_DIR, exist_ok=True)
        with open(_TOKEN_PATH, "w") as f:
            f.write(tok)
        os.chmod(_TOKEN_PATH, 0o600)
    except OSError as e:
        print(f"[vchan] WARNING: could not write {_TOKEN_PATH}: {e}")
    return tok


def read_token() -> str:
    """Read the token minted this boot (same value the grader reads). Returns ''
    if absent so callers can fall back to mint_verifier_token()."""
    try:
        with open(_TOKEN_PATH) as f:
            return f.read().strip()
    except OSError:
        return ""
