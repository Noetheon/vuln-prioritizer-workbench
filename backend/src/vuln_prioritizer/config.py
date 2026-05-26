"""Application constants and lightweight configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from re import Pattern, compile
from typing import Final

APP_NAME: Final = "vuln-prioritizer"
DEFAULT_OUTPUT_FORMAT: Final = "markdown"
DEFAULT_NVD_API_KEY_ENV: Final = "NVD_API_KEY"
DEFAULT_CACHE_DIR: Final = Path(".cache") / APP_NAME
DEFAULT_CACHE_TTL_HOURS: Final = 24
ENV_VAR_NAME_PATTERN: Final = r"^[A-Z_][A-Z0-9_]*$"
ENV_VAR_NAME_RE: Final[Pattern[str]] = compile(ENV_VAR_NAME_PATTERN)

NVD_API_URL: Final = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL: Final = "https://api.first.org/data/v1/epss"
KEV_FEED_URL: Final = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
KEV_MIRROR_URL: Final = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

HTTP_TIMEOUT_SECONDS: Final = 15
HTTP_MAX_RETRIES: Final = 3
EPSS_QUERY_CHAR_LIMIT: Final = 1900

PRIORITY_RANKS: Final = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Accepted": 80,
    "Suppressed": 90,
    "Fixed": 100,
}

PRIORITY_RECOMMENDATIONS: Final = {
    "Critical": (
        "Patch or mitigate immediately, validate exposure, strengthen detection "
        "coverage, and escalate potential business impact."
    ),
    "High": (
        "Patch quickly, assess available mitigations or workarounds, and confirm "
        "which products and assets are affected."
    ),
    "Medium": (
        "Prioritize in the regular remediation cycle and verify whether the "
        "affected software supports critical systems or privileged workflows."
    ),
    "Low": (
        "Document the finding, monitor for changes in exploitability or exposure, "
        "and address it during the normal patch cycle."
    ),
    "Accepted": (
        "Keep the accepted risk visible, monitor the waiver owner and expiry date, "
        "and reassess before the next review."
    ),
    "Suppressed": (
        "Keep the suppressed evidence available for audit and re-open if source context changes."
    ),
    "Fixed": (
        "Keep the fixed evidence available for audit and verify the scanner no longer "
        "reports the affected occurrence."
    ),
}

DATA_SOURCES: Final = [
    "NVD CVE API 2.0",
    "FIRST EPSS API",
    "CISA Known Exploited Vulnerabilities Catalog",
]


@dataclass(slots=True, frozen=True)
class ProviderConfig:
    """Minimal provider configuration container."""

    nvd_api_key_env: str = DEFAULT_NVD_API_KEY_ENV
    timeout_seconds: int = HTTP_TIMEOUT_SECONDS
    max_retries: int = HTTP_MAX_RETRIES

    def __post_init__(self) -> None:
        """Post init   method for ProviderConfig."""
        validate_env_var_name(
            self.nvd_api_key_env,
            label="NVD API key environment variable name",
        )


def validate_env_var_name(
    value: str,
    *,
    label: str = "environment variable name",
) -> str:
    """Validate an environment variable name used to resolve secret values."""
    if not ENV_VAR_NAME_RE.fullmatch(value):
        raise ValueError(f"{label} must match {ENV_VAR_NAME_PATTERN}.")
    return value
