"""Governance rollups for the Workbench."""

from __future__ import annotations

import uuid

from app.decision_core.readmodels import project_finding_decision_views
from app.models import ProjectGovernanceRollupsPublic
from app.repositories.findings import FindingRepository
from app.repositories.waivers import WaiverRepository
from app.services.governance_rollups import build_project_governance_rollups_payload


def build_project_governance_rollups_payload_from_repositories(
    *,
    project_id: uuid.UUID,
    finding_repository: FindingRepository,
    waiver_repository: WaiverRepository,
    limit: int = 5,
) -> ProjectGovernanceRollupsPublic:
    """Build governance rollups from bounded SQL-backed repository queries."""
    bounded_limit = max(1, min(limit, 50))
    findings = finding_repository.list_project_findings(project_id)
    finding_views = project_finding_decision_views(finding_repository.session, findings)
    return build_project_governance_rollups_payload(
        project_id=project_id,
        findings=finding_views,
        waivers=waiver_repository.list_project_waivers(project_id),
        waiver_repository=waiver_repository,
        limit=bounded_limit,
    )
