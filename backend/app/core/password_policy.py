"""Shared password policy for Workbench account bootstrap and lifecycle paths."""

from __future__ import annotations

from dataclasses import dataclass

MIN_WORKBENCH_PASSWORD_LENGTH = 16
DEFAULT_WORKBENCH_SECRET = "changethis"
LOCAL_WORKBENCH_SECRET_PLACEHOLDER = "local-workbench-dev-secret"
LOCAL_WORKBENCH_PASSWORD_PLACEHOLDER = "local-workbench-dev-password"
INSECURE_WORKBENCH_PASSWORD_VALUES = frozenset(
    {
        "",
        DEFAULT_WORKBENCH_SECRET,
        LOCAL_WORKBENCH_SECRET_PLACEHOLDER,
        LOCAL_WORKBENCH_PASSWORD_PLACEHOLDER,
    }
)
PASSWORD_POLICY_ERROR = "Password does not meet Workbench password policy."


@dataclass(frozen=True)
class PasswordPolicyInput:
    """Context needed to validate a password without importing settings."""

    password: str
    username: str | None = None
    secret_key: str | None = None
    allow_local_bootstrap_default: bool = False


def password_policy_violations(policy_input: PasswordPolicyInput) -> tuple[str, ...]:
    """Return stable policy violation codes for a candidate Workbench password."""
    password = policy_input.password.strip()
    normalized = password.lower()
    violations: list[str] = []
    local_bootstrap_placeholder_allowed = (
        normalized in INSECURE_WORKBENCH_PASSWORD_VALUES
        and policy_input.allow_local_bootstrap_default
    )

    if normalized in INSECURE_WORKBENCH_PASSWORD_VALUES and not local_bootstrap_placeholder_allowed:
        violations.append("insecure-placeholder")
    if not local_bootstrap_placeholder_allowed and len(password) < MIN_WORKBENCH_PASSWORD_LENGTH:
        violations.append("too-short")
    if policy_input.username and normalized == policy_input.username.strip().lower():
        violations.append("matches-username")
    if policy_input.secret_key and password == policy_input.secret_key:
        violations.append("matches-secret-key")

    return tuple(dict.fromkeys(violations))


def validate_password_policy(policy_input: PasswordPolicyInput) -> None:
    """Raise ValueError when a candidate password violates the Workbench policy."""
    if password_policy_violations(policy_input):
        raise ValueError(PASSWORD_POLICY_ERROR)
