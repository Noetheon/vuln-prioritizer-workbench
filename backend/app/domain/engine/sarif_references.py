"""SARIF reference filtering helpers for defensive reports."""

from __future__ import annotations

import re
from urllib.parse import urlparse

_CVE_REPOSITORY_RE = re.compile(r"\bcve-\d{4}-\d{4,}\b", re.IGNORECASE)
_EXPLOIT_REPOSITORY_NAMES = {
    "exploit-db",
    "exploitdb",
    "metasploit-framework",
}
_EXPLOIT_REFERENCE_HOSTS = {
    "exploit-db.com",
    "www.exploit-db.com",
    "packetstormsecurity.com",
    "www.packetstormsecurity.com",
}


def dedupe_defensive_http_urls(values: list[str]) -> list[str]:
    """Return unique HTTP(S) URLs while excluding direct exploit/PoC references."""
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if (
            not normalized.startswith(("http://", "https://"))
            or normalized in seen
            or not is_defensive_reference_url(normalized)
        ):
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def is_defensive_reference_url(value: str) -> bool:
    """Return whether a SARIF reference URL fits defensive evidence exports."""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return False
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False
    if hostname in _EXPLOIT_REFERENCE_HOSTS:
        return False

    if hostname == "github.com":
        parts = [part for part in parsed.path.lower().split("/") if part]
        if len(parts) < 2:
            return True
        repository = parts[1]
        repository_path = "/".join(parts[2:])
        if repository_path.startswith("security/advisories/"):
            return True
        if repository in _EXPLOIT_REPOSITORY_NAMES:
            return False
        if _CVE_REPOSITORY_RE.search(repository):
            return False

    return True
