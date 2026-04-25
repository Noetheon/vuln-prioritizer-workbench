"""GitHub issue export helpers for Workbench routes."""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote

import requests
from fastapi import HTTPException

from vuln_prioritizer.api.schemas import GitHubIssuePreviewRequest

GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _github_export_token(token_env: str) -> str:
    env_name = token_env.strip()
    if not ENV_NAME_RE.fullmatch(env_name):
        raise HTTPException(
            status_code=422,
            detail="token_env must be an environment variable name.",
        )
    token = os.getenv(env_name)
    if not token:
        raise HTTPException(status_code=422, detail=f"{env_name} is not configured.")
    return token


def _github_repository_path(repository: str) -> str:
    if not GITHUB_REPOSITORY_RE.fullmatch(repository):
        raise HTTPException(status_code=422, detail="repository must use owner/name format.")
    owner, name = repository.split("/", 1)
    return f"{quote(owner, safe='')}/{quote(name, safe='')}"


def _create_github_issue(
    *,
    repository_path: str,
    token: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    issue_payload: dict[str, Any] = {
        "title": item["title"],
        "body": (
            item["body"]
            + "\n\n"
            + f"<!-- vuln-prioritizer duplicate_key: {item['duplicate_key']} -->"
        ),
        "labels": item["labels"],
    }
    milestone = item.get("milestone")
    if isinstance(milestone, str) and milestone.isdigit():
        issue_payload["milestone"] = int(milestone)
    try:
        response = requests.post(
            f"https://api.github.com/repos/{repository_path}/issues",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "vuln-prioritizer-workbench",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json=issue_payload,
            timeout=10,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="GitHub issue creation failed.") from exc
    if response.status_code != 201:
        raise HTTPException(
            status_code=502,
            detail=f"GitHub issue creation failed with status {response.status_code}.",
        )
    response_payload = response.json()
    return {
        "html_url": str(response_payload.get("html_url") or ""),
        "number": int(response_payload.get("number") or 0),
    }


def _github_issue_preview_payload(
    finding: Any, *, payload: GitHubIssuePreviewRequest
) -> dict[str, Any]:
    labels = [
        payload.label_prefix,
        f"{payload.label_prefix}:priority-{finding.priority.lower()}",
        "security",
    ]
    if finding.in_kev:
        labels.append(f"{payload.label_prefix}:kev")
    title = f"{finding.cve_id}: {finding.priority} priority remediation"
    body = "\n".join(
        [
            "## Finding",
            f"- CVE: `{finding.cve_id}`",
            f"- Priority: `{finding.priority}`",
            f"- Operational rank: `{finding.operational_rank}`",
            f"- Component: `{finding.component.name if finding.component else 'N.A.'}`",
            f"- Asset: `{finding.asset.asset_id if finding.asset else 'N.A.'}`",
            f"- Owner: `{finding.asset.owner if finding.asset else 'N.A.'}`",
            "",
            "## Why now",
            finding.rationale or "No rationale captured.",
            "",
            "## Recommended action",
            finding.recommended_action or "Review and remediate according to policy.",
            "",
            "Generated as a dry-run Workbench issue preview. Review before creating issues.",
        ]
    )
    return {
        "title": title,
        "body": body,
        "labels": labels,
        "milestone": payload.milestone,
        "duplicate_key": f"{finding.project_id}:{finding.cve_id}:{finding.asset_id or 'no-asset'}",
    }
