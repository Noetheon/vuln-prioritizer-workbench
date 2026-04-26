"""Jira and ServiceNow ticket sync helpers for Workbench routes."""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from fastapi import HTTPException

from vuln_prioritizer.api.schemas import TicketSyncPreviewRequest

ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
SERVICENOW_TABLE_RE = re.compile(r"^[A-Za-z0-9_]+$")
JIRA_PROJECT_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,20}$")


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
    raw_url = (base_url or "").strip().rstrip("/")
    parsed = urlparse(raw_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise HTTPException(
            status_code=422,
            detail="base_url must be an HTTPS URL without embedded credentials.",
        )
    return raw_url


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
        response = requests.post(
            urljoin(base_url + "/", "rest/api/3/issue"),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Idempotency-Key": item["idempotency_key"],
                "User-Agent": "vuln-prioritizer-workbench",
            },
            json=jira_payload,
            timeout=10,
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
        response = requests.post(
            urljoin(base_url + "/", f"api/now/table/{table}"),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Idempotency-Key": item["idempotency_key"],
                "User-Agent": "vuln-prioritizer-workbench",
            },
            json=servicenow_payload,
            timeout=10,
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
