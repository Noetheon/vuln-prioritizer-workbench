"""Template-style JWT helpers for the active backend runtime."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import settings

ALGORITHM = "HS256"
PASSWORD_HASH_ALGORITHM = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 600_000
PASSWORD_SALT_BYTES = 16
LEGACY_CONFIGURED_PASSWORD_PLACEHOLDERS = frozenset(
    {
        "configured-superuser",
        "configured-superuser-password-placeholder",
    }
)
SESSION_COOKIE_NAME = "vpw_session"
CSRF_COOKIE_NAME = "vpw_csrf"
CSRF_HEADER_NAME = "x-csrf-token"


class TokenDecodeError(ValueError):
    """Raised when an active-runtime JWT cannot be validated."""


def _base64url_encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _base64url_decode(payload: str) -> bytes:
    padding = "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(f"{payload}{padding}")


def get_password_hash(password: str) -> str:
    """Hash a password with stdlib PBKDF2-HMAC-SHA256."""
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return "$".join(
        [
            PASSWORD_HASH_ALGORITHM,
            str(PASSWORD_HASH_ITERATIONS),
            _base64url_encode(salt),
            _base64url_encode(digest),
        ]
    )


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against the persisted stdlib PBKDF2 hash."""
    try:
        algorithm, iterations_raw, salt_raw, digest_raw = hashed_password.split("$", 3)
        if algorithm != PASSWORD_HASH_ALGORITHM:
            return False
        iterations = int(iterations_raw)
        if iterations <= 0:
            return False
        expected_digest = _base64url_decode(digest_raw)
        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            _base64url_decode(salt_raw),
            iterations,
        )
    except (ValueError, binascii.Error):
        return False
    return hmac.compare_digest(actual_digest, expected_digest)


def password_hash_needs_bootstrap(hashed_password: str) -> bool:
    """Return whether a configured user's placeholder hash should be replaced."""
    return hashed_password in LEGACY_CONFIGURED_PASSWORD_PLACEHOLDERS


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


def create_csrf_token(jti: str) -> str:
    """Create a signed CSRF token bound to one JWT ID."""
    nonce = secrets.token_urlsafe(32)
    signature = _csrf_signature(jti, nonce)
    return f"{nonce}.{_base64url_encode(signature)}"


def verify_csrf_token(jti: str, token: str) -> bool:
    """Validate a signed CSRF token for one JWT ID."""
    try:
        nonce, signature_raw = token.split(".", 1)
    except ValueError:
        return False
    if not nonce or not signature_raw:
        return False
    try:
        actual_signature = _base64url_decode(signature_raw)
    except (ValueError, binascii.Error):
        return False
    expected_signature = _csrf_signature(jti, nonce)
    return hmac.compare_digest(actual_signature, expected_signature)


def _csrf_signature(jti: str, nonce: str) -> bytes:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        f"csrf:{jti}:{nonce}".encode(),
        hashlib.sha256,
    ).digest()


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
    except (ValueError, json.JSONDecodeError, binascii.Error) as exc:
        raise TokenDecodeError("Could not decode token") from exc
