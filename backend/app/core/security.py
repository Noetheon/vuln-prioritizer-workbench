"""Template-style JWT helpers for the active backend runtime."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import settings

ALGORITHM = "HS256"


class TokenDecodeError(ValueError):
    """Raised when an active-runtime JWT cannot be validated."""


def _base64url_encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _base64url_decode(payload: str) -> bytes:
    padding = "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(f"{payload}{padding}")


def access_token_expires_at(expires_delta: timedelta | None = None) -> datetime:
    """Return the expiry timestamp used for a new access token."""
    return datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )


def new_token_jti() -> str:
    """Return a random JWT ID suitable for revocable session tracking."""
    return secrets.token_urlsafe(32)


def token_jti_digest(jti: str) -> str:
    """Return a stable digest for storing JWT IDs without token material."""
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


def create_access_token(
    subject: str | Any,
    expires_delta: timedelta | None = None,
    *,
    jti: str | None = None,
    expires_at: datetime | None = None,
) -> str:
    """Create a signed JWT for the configured active-runtime subject."""
    expire = expires_at or access_token_expires_at(expires_delta)
    header = {"alg": ALGORITHM, "typ": "JWT"}
    claims = {"exp": int(expire.timestamp()), "sub": str(subject)}
    if jti is not None:
        claims["jti"] = jti
    signing_input = ".".join(
        [
            _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            _base64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8")),
        ]
    )
    signature = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{signing_input}.{_base64url_encode(signature)}"


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a HS256 JWT created by the active runtime."""
    try:
        header_segment, claims_segment, signature_segment = token.split(".")
        signing_input = f"{header_segment}.{claims_segment}"
        expected_signature = hmac.new(
            settings.SECRET_KEY.encode("utf-8"),
            signing_input.encode("ascii"),
            hashlib.sha256,
        ).digest()
        actual_signature = _base64url_decode(signature_segment)
        if not hmac.compare_digest(actual_signature, expected_signature):
            raise TokenDecodeError("Invalid token signature")

        header = json.loads(_base64url_decode(header_segment))
        if header.get("alg") != ALGORITHM:
            raise TokenDecodeError("Unsupported token algorithm")

        claims = json.loads(_base64url_decode(claims_segment))
        expires_at = claims.get("exp")
        if not isinstance(expires_at, int):
            raise TokenDecodeError("Missing token expiration")
        if datetime.now(UTC).timestamp() >= expires_at:
            raise TokenDecodeError("Expired token")
        return dict(claims)
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenDecodeError("Could not decode token") from exc
