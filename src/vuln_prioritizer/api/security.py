"""Security helpers shared by Workbench API middleware and routes."""

from __future__ import annotations

import hashlib

API_TOKEN_HASH_ITERATIONS = 210_000
API_TOKEN_HASH_SALT = b"vuln-prioritizer-workbench-api-token-v1"


def api_token_digest(token_value: str) -> str:
    """Return the deterministic stored digest for a high-entropy API token."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        token_value.encode("utf-8"),
        API_TOKEN_HASH_SALT,
        API_TOKEN_HASH_ITERATIONS,
    ).hex()
