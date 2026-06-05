"""GitHub issue markdown and export helpers for Workbench findings."""

from __future__ import annotations

import os
import re
import uuid
from typing import Any, Literal
from urllib.parse import quote

import requests
from fastapi import HTTPException
from sqlmodel import Session

from app.domain.engine.security_redaction import redact_text, redact_value
from app.models.findings import Finding
from app.models.github_issues import (
    ENV_NAME_RE,
    GITHUB_REPOSITORY_RE,
    GitHubIssuePreviewCreate,
    GitHubIssuePreviewRecord,
)
from app.repositories import FindingPageQuery, FindingRepository
from app.services.decision_projection import DecisionFindingView, project_finding_decision_views

GITHUB_SECRET_PATTERN = re.compile(
    r"(?i)\b("
    r"ghp_[A-Za-z0-9_]{8,}|"
    r"github_pat_[A-Za-z0-9_]+|"
    r"xox[baprs]-[A-Za-z0-9-]{8,}|"
    r"sk-[A-Za-z0-9]{8,}|"
    r"AKIA[0-9A-Z]{16}"
    r")\b"
)

GitHubIssueFailureKind = Literal["network_error", "upstream_status"]


class GitHubIssueCreationError(HTTPException):
    """HTTP-facing GitHub create failure with audit-safe classification."""

    def __init__(
        self,
        *,
        failure_kind: GitHubIssueFailureKind,
        upstream_status_code: int | None = None,
        detail: str,
    ) -> None:
        """Initialize a new instance of GitHubIssueCreationError."""
        super().__init__(status_code=502, detail=detail)
        self.failure_kind = failure_kind
        self.upstream_status_code = upstream_status_code


def build_github_issue_preview_items(
    session: Session,
    *,
    project_id: uuid.UUID,
    payload: GitHubIssuePreviewCreate,
) -> list[GitHubIssuePreviewRecord]:
    """Return GitHub issue markdown for selected or top-ranked findings."""
    findings = _selected_findings(session, project_id=project_id, payload=payload)
    finding_views = project_finding_decision_views(session, findings)
    return [_preview_item(view, payload=payload) for view in finding_views]


def github_export_token(token_env: str | None) -> str:
    """Read a GitHub token from an explicit environment variable name."""
    if token_env is None or not token_env.strip():
        raise HTTPException(
            status_code=422,
            detail="token_env is required when dry_run is false.",
        )
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


def github_repository_path(repository: str) -> str:
    """Return a URL-safe GitHub repository path after owner/name validation."""
    if not GITHUB_REPOSITORY_RE.fullmatch(repository):
        raise HTTPException(status_code=422, detail="repository must use owner/name format.")
    owner, name = repository.split("/", 1)
    return f"{quote(owner, safe='')}/{quote(name, safe='')}"


def create_github_issue(
    *,
    repository_path: str,
    token: str,
    item: GitHubIssuePreviewRecord,
) -> dict[str, Any]:
    """Create one GitHub issue through the public GitHub REST API."""
    issue_payload: dict[str, Any] = {
        "title": item.title,
        "body": item.body,
        "labels": item.labels,
    }
    if item.milestone is not None:
        issue_payload["milestone"] = item.milestone
    try:
        # repository_path is validated as owner/name and the host is fixed.
        # codeql[py/full-ssrf]
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
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise GitHubIssueCreationError(
            failure_kind="network_error",
            detail="GitHub issue creation failed.",
        ) from exc
    if response.status_code != 201:
        raise GitHubIssueCreationError(
            failure_kind="upstream_status",
            upstream_status_code=response.status_code,
            detail=f"GitHub issue creation failed with status {response.status_code}.",
        )
    response_payload = response.json()
    return {
        "issue_url": str(response_payload.get("html_url") or ""),
        "issue_number": int(response_payload.get("number") or 0),
    }


def _selected_findings(
    session: Session,
    *,
    project_id: uuid.UUID,
    payload: GitHubIssuePreviewCreate,
) -> list[Finding]:
    """Selected findings function."""
    repo = FindingRepository(session)
    if payload.finding_ids:
        findings: list[Finding] = []
        for finding_id in payload.finding_ids:
            finding = repo.get_finding(finding_id)
            if finding is None or finding.project_id != project_id:
                raise HTTPException(status_code=404, detail="Finding not found in project.")
            findings.append(finding)
        return findings

    findings, _count = repo.list_project_findings_query(
        FindingPageQuery(
            project_id=project_id,
            limit=payload.limit,
            offset=0,
            sort="operational",
            direction="asc",
            priority=payload.priority,
            status=None,
        )
    )
    return findings


def _preview_item(
    view: DecisionFindingView,
    *,
    payload: GitHubIssuePreviewCreate,
) -> GitHubIssuePreviewRecord:
    """Preview item function."""
    finding = view.finding
    priority = _safe_text(view.priority_label)
    title = f"{_safe_text(view.cve_id)}: {priority} priority remediation"
    labels = [
        payload.label_prefix,
        f"{payload.label_prefix}:priority-{str(view.priority).lower()}",
        "security",
    ]
    if view.in_kev:
        labels.append(f"{payload.label_prefix}:kev")
    evidence_refs = _evidence_refs(view) if payload.include_evidence_refs else []
    duplicate_key = (
        f"{finding.project_id}:{finding.id}:{view.cve_id}:"
        f"{finding.asset_id or 'no-asset'}:{finding.component_id or 'no-component'}"
    )
    body = _issue_body(
        view,
        evidence_refs=evidence_refs,
        duplicate_key=duplicate_key,
    )
    return GitHubIssuePreviewRecord(
        finding_id=finding.id,
        cve_id=view.cve_id,
        title=title,
        body=body,
        labels=labels,
        milestone=payload.milestone,
        duplicate_key=duplicate_key,
        evidence_refs=evidence_refs,
    )


def _issue_body(
    view: DecisionFindingView,
    *,
    evidence_refs: list[str],
    duplicate_key: str,
) -> str:
    """Issue body function."""
    finding = view.finding
    finding_url = f"/api/v1/findings/{finding.id}"
    evidence_lines = [f"- {_safe_text(ref)}" for ref in evidence_refs] or [
        "- No additional evidence references captured."
    ]
    body = "\n".join(
        [
            "## Workbench Finding",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| CVE | `{_table_cell(view.cve_id)}` |",
            f"| Priority | {_table_cell(view.priority_label)} |",
            f"| Status | {_table_cell(str(view.status))} |",
            f"| Operational rank | {_table_cell(str(view.operational_rank))} |",
            f"| Risk score | {_table_cell(_number_label(view.risk_score))} |",
            f"| CVSS | {_table_cell(_number_label(view.cvss_base_score))} |",
            f"| EPSS | {_table_cell(_epss_label(view.epss))} |",
            f"| KEV | {_table_cell('yes' if view.in_kev else 'no')} |",
            f"| Component | {_table_cell(_component_label(finding))} |",
            f"| Asset | {_table_cell(_asset_label(finding))} |",
            f"| Owner | {_table_cell(finding.asset.owner if finding.asset else None)} |",
            (
                "| Service | "
                f"{_table_cell(finding.asset.business_service if finding.asset else None)} |"
            ),
            "",
            "## Why This Should Be Prioritized",
            "",
            _safe_block(view.rationale, fallback="No rationale captured."),
            "",
            "## Recommended Remediation",
            "",
            _safe_block(
                view.recommended_action,
                fallback=(
                    "Review the affected component or asset and remediate according to policy."
                ),
            ),
            "",
            "## Evidence References",
            "",
            *evidence_lines,
            "",
            "## Workbench Reference",
            "",
            f"- Finding API: `{finding_url}`",
            "",
            "Generated by Vuln Prioritizer Workbench as operator-reviewed GitHub issue markdown.",
            "",
            f"<!-- vuln-prioritizer-workbench duplicate_key: {_safe_text(duplicate_key)} -->",
        ]
    )
    return body


def _evidence_refs(view: DecisionFindingView) -> list[str]:
    """Evidence refs function."""
    finding = view.finding
    refs = [
        f"/api/v1/findings/{finding.id}",
        f"https://nvd.nist.gov/vuln/detail/{view.cve_id}",
    ]
    refs.extend(_extract_evidence_refs(view.evidence_payload))
    seen: set[str] = set()
    deduped: list[str] = []
    for ref in refs:
        safe_ref = _safe_text(ref).strip()
        if safe_ref and safe_ref not in seen:
            deduped.append(safe_ref)
            seen.add(safe_ref)
    return deduped[:10]


def _extract_evidence_refs(value: Any) -> list[str]:
    """Extract evidence refs function."""
    redacted, _paths = redact_value(value)
    refs: list[str] = []

    def walk(candidate: Any, key_hint: str = "") -> None:
        """Walk function."""
        if isinstance(candidate, dict):
            for key, child in candidate.items():
                walk(child, str(key).lower())
        elif isinstance(candidate, list):
            for child in candidate:
                walk(child, key_hint)
        elif isinstance(candidate, str) and _looks_like_evidence_ref(candidate, key_hint):
            refs.append(candidate)

    walk(redacted)
    return refs


def _looks_like_evidence_ref(value: str, key_hint: str) -> bool:
    """Looks like evidence ref function."""
    lower = value.lower()
    if value == "[REDACTED]":
        return False
    if lower.startswith(("http://", "https://")):
        return True
    if any(token in key_hint for token in ("ref", "url", "report", "artifact", "evidence")):
        return len(value.strip()) <= 500
    return False


def _safe_block(value: Any, *, fallback: str) -> str:
    """Safe block function."""
    text = _safe_text(value).strip()
    return text or fallback


def _safe_text(value: Any) -> str:
    """Safe text function."""
    if value is None:
        return ""
    redacted = redact_text(str(value))
    return GITHUB_SECRET_PATTERN.sub("<redacted>", redacted)


def _table_cell(value: Any) -> str:
    """Table cell function."""
    text = _safe_text(value).strip() or "Not recorded"
    return text.replace("|", "\\|").replace("\n", " ")


def _number_label(value: float | None) -> str:
    """Number label function."""
    if value is None:
        return "Not recorded"
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _epss_label(value: float | None) -> str:
    """Epss label function."""
    if value is None:
        return "Not recorded"
    return f"{value:.4f}".rstrip("0").rstrip(".")


def _component_label(finding: Finding) -> str:
    """Component label function."""
    if finding.component is None:
        return "Not recorded"
    if finding.component.version:
        return f"{finding.component.name} {finding.component.version}"
    return finding.component.name


def _asset_label(finding: Finding) -> str:
    """Asset label function."""
    if finding.asset is None:
        return "Not recorded"
    return finding.asset.name or finding.asset.asset_key
