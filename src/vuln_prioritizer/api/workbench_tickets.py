"""Jira and ServiceNow ticket sync helpers for Workbench routes."""

from __future__ import annotations

import os
import re
import socket
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse, urlunparse

import requests
from fastapi import HTTPException

from vuln_prioritizer.api.schemas import TicketSyncPreviewRequest

ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
SERVICENOW_TABLE_RE = re.compile(r"^[A-Za-z0-9_]+$")
JIRA_PROJECT_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,20}$")
TICKET_BASE_URL_ALLOWLIST_ENV = "VULN_PRIORITIZER_TICKET_BASE_URL_ALLOWLIST"
BLOCKED_TICKET_HOST_SUFFIXES = (".localhost", ".local", ".internal")


def _ticket_sync_token(token_env: str | None) -> str:
    env_name = (token_env or "").strip()
    if not env_name or not ENV_NAME_RE.fullmatch(env_name):
        raise HTTPException(
            status_code=422,
            detail="token_env must be an explicit environment variable name.",
        )
    token = os.getenv(env_name)
    if not token:
        raise HTTPException(status_code=422, detail=f"{env_name} is not configured.")
    return token


def _ticket_base_url(base_url: str | None) -> str:
    normalized_url = _normalized_https_base_url(base_url)
    if normalized_url in _configured_ticket_base_urls():
        return normalized_url
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname
    if hostname is None:
        raise HTTPException(
            status_code=422,
            detail="base_url host is required.",
        )
    _ensure_public_ticket_host(hostname)
    return normalized_url


def _normalized_https_base_url(base_url: str | None) -> str:
    raw_url = (base_url or "").strip().rstrip("/")
    parsed = urlparse(raw_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="base_url port is invalid.") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise HTTPException(
            status_code=422,
            detail="base_url must be an HTTPS URL without embedded credentials.",
        )
    if port is not None and port != 443:
        raise HTTPException(status_code=422, detail="base_url must use the default HTTPS port.")
    hostname = parsed.hostname
    if hostname is None:
        raise HTTPException(status_code=422, detail="base_url host is required.")
    normalized_host = _normalized_ticket_hostname(hostname)
    netloc = normalized_host if port is None else f"{normalized_host}:{port}"
    return urlunparse(("https", netloc, parsed.path.rstrip("/"), "", "", "")).rstrip("/")


def _configured_ticket_base_urls() -> set[str]:
    raw_values = os.getenv(TICKET_BASE_URL_ALLOWLIST_ENV, "")
    configured_urls: set[str] = set()
    for raw_value in re.split(r"[\s,]+", raw_values):
        if raw_value:
            configured_urls.add(_normalized_https_base_url(raw_value))
    return configured_urls


def _normalized_ticket_hostname(hostname: str) -> str:
    try:
        return hostname.rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise HTTPException(status_code=422, detail="base_url host is invalid.") from exc


def _ensure_public_ticket_host(hostname: str) -> None:
    normalized_host = _normalized_ticket_hostname(hostname)
    if normalized_host == "localhost" or normalized_host.endswith(BLOCKED_TICKET_HOST_SUFFIXES):
        raise HTTPException(
            status_code=422,
            detail=(
                "base_url host must resolve to a public address or be explicitly "
                f"allowlisted via {TICKET_BASE_URL_ALLOWLIST_ENV}."
            ),
        )
    try:
        _ensure_public_ticket_address(normalized_host)
        return
    except ValueError:
        pass
    try:
        resolved = socket.getaddrinfo(normalized_host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                "base_url host must resolve to a public address or be explicitly "
                f"allowlisted via {TICKET_BASE_URL_ALLOWLIST_ENV}."
            ),
        ) from exc
    addresses = {entry[4][0] for entry in resolved if isinstance(entry[4][0], str)}
    if not addresses:
        raise HTTPException(status_code=422, detail="base_url host did not resolve.")
    for address in addresses:
        _ensure_public_ticket_address(address)


def _ensure_public_ticket_address(address: str) -> None:
    parsed_address = ip_address(address)
    if not parsed_address.is_global:
        raise HTTPException(
            status_code=422,
            detail=(
                "base_url host must resolve to a public address or be explicitly "
                f"allowlisted via {TICKET_BASE_URL_ALLOWLIST_ENV}."
            ),
        )


def _ticket_endpoint_url(base_url: str, path: str) -> str:
    return f"{base_url}/{path.lstrip('/')}"


def _jira_project_key(project_key: str | None) -> str:
    key = (project_key or "").strip().upper()
    if not JIRA_PROJECT_RE.fullmatch(key):
        raise HTTPException(status_code=422, detail="jira_project_key is required.")
    return key


def _servicenow_table(table: str) -> str:
    normalized = table.strip()
    if not SERVICENOW_TABLE_RE.fullmatch(normalized):
        raise HTTPException(status_code=422, detail="servicenow_table is invalid.")
    return normalized


def _ticket_preview_payload(finding: Any, *, payload: TicketSyncPreviewRequest) -> dict[str, Any]:
    duplicate_key = (
        f"{finding.project_id}:{payload.provider}:{finding.cve_id}:{finding.asset_id or 'no-asset'}"
    )
    idempotency_key = f"{payload.idempotency_prefix}:{duplicate_key}"
    labels = [
        "vuln-prioritizer",
        f"priority-{finding.priority.lower()}",
        "security",
    ]
    if finding.in_kev:
        labels.append("kev")
    title = f"{finding.cve_id}: {finding.priority} priority remediation"
    body = "\n".join(
        [
            f"CVE: {finding.cve_id}",
            f"Priority: {finding.priority}",
            f"Operational rank: {finding.operational_rank}",
            f"Component: {finding.component.name if finding.component else 'N.A.'}",
            f"Asset: {finding.asset.asset_id if finding.asset else 'N.A.'}",
            f"Owner: {finding.asset.owner if finding.asset else 'N.A.'}",
            "",
            "Why now:",
            finding.rationale or "No rationale captured.",
            "",
            "Recommended action:",
            finding.recommended_action or "Review and remediate according to policy.",
            "",
            f"vuln-prioritizer duplicate_key: {duplicate_key}",
        ]
    )
    return {
        "provider": payload.provider,
        "finding_id": finding.id,
        "title": title,
        "body": body,
        "labels": labels,
        "duplicate_key": duplicate_key,
        "idempotency_key": idempotency_key,
    }


def _create_jira_issue(
    *,
    base_url: str,
    token: str,
    project_key: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    jira_payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": item["title"],
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": item["body"]}],
                    }
                ],
            },
            "issuetype": {"name": "Task"},
            "labels": item["labels"],
        }
    }
    try:
        request_url = _ticket_endpoint_url(base_url, "rest/api/3/issue")

        # _ticket_base_url restricts destinations to HTTPS allowlisted or public hosts.
        # codeql[py/full-ssrf]
        response = requests.post(
            request_url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Idempotency-Key": item["idempotency_key"],
                "User-Agent": "vuln-prioritizer-workbench",
            },
            json=jira_payload,
            timeout=10,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="Jira issue creation failed.") from exc
    if response.status_code not in {200, 201}:
        raise HTTPException(
            status_code=502,
            detail=f"Jira issue creation failed with status {response.status_code}.",
        )
    payload = response.json()
    external_id = str(payload.get("key") or payload.get("id") or "")
    return {
        "external_id": external_id,
        "ticket_url": f"{base_url}/browse/{external_id}" if external_id else None,
    }


def _create_servicenow_ticket(
    *,
    base_url: str,
    token: str,
    table: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    servicenow_payload = {
        "short_description": item["title"],
        "description": item["body"],
        "correlation_id": item["idempotency_key"],
        "category": "security",
    }
    try:
        request_url = _ticket_endpoint_url(base_url, f"api/now/table/{table}")

        # _ticket_base_url restricts destinations to HTTPS allowlisted or public hosts.
        # codeql[py/full-ssrf]
        response = requests.post(
            request_url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Idempotency-Key": item["idempotency_key"],
                "User-Agent": "vuln-prioritizer-workbench",
            },
            json=servicenow_payload,
            timeout=10,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="ServiceNow ticket creation failed.") from exc
    if response.status_code not in {200, 201}:
        raise HTTPException(
            status_code=502,
            detail=f"ServiceNow ticket creation failed with status {response.status_code}.",
        )
    payload = response.json()
    result = payload.get("result") if isinstance(payload, dict) else {}
    result = result if isinstance(result, dict) else {}
    external_id = str(result.get("number") or result.get("sys_id") or "")
    ticket_url = result.get("link")
    return {
        "external_id": external_id,
        "ticket_url": str(ticket_url) if ticket_url else None,
    }


__all__ = [
    "_create_jira_issue",
    "_create_servicenow_ticket",
    "_jira_project_key",
    "_servicenow_table",
    "_ticket_base_url",
    "_ticket_preview_payload",
    "_ticket_sync_token",
]
