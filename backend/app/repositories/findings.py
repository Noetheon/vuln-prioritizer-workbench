"""Finding repository for template Workbench persistence."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session, col, select

from app.models import (
    Component,
    Finding,
    FindingPriority,
    FindingStatus,
    Vulnerability,
)
from app.models.base import get_datetime_utc


class FindingRepository:
    """Finding, component, and vulnerability persistence helpers."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert_component(
        self,
        *,
        name: str,
        version: str | None = None,
        purl: str | None = None,
        ecosystem: str | None = None,
        package_type: str | None = None,
    ) -> Component:
        """Create or update a shared component identity."""
        if purl:
            statement = select(Component).where(Component.purl == purl)
        else:
            statement = select(Component).where(
                Component.name == name,
                Component.version == version,
                Component.ecosystem == ecosystem,
            )
        component = self.session.exec(statement).first()
        if component is None:
            component = Component(name=name, version=version, purl=purl, ecosystem=ecosystem)
            self.session.add(component)
        else:
            component.name = name
            component.version = version
            component.purl = purl
            component.ecosystem = ecosystem

        component.package_type = package_type
        self.session.flush()
        return component

    def upsert_vulnerability(
        self,
        *,
        cve_id: str,
        source_id: str | None = None,
        title: str | None = None,
        description: str | None = None,
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        severity: str | None = None,
        cwe: str | None = None,
        published_at: str | None = None,
        modified_at: str | None = None,
        provider_json: dict[str, Any] | None = None,
    ) -> Vulnerability:
        """Create or update a CVE/provider record by CVE id."""
        statement = select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        vulnerability = self.session.exec(statement).first()
        if vulnerability is None:
            vulnerability = Vulnerability(cve_id=cve_id)
            self.session.add(vulnerability)

        vulnerability.source_id = source_id
        vulnerability.title = title
        vulnerability.description = description
        vulnerability.cvss_score = cvss_score
        vulnerability.cvss_vector = cvss_vector
        vulnerability.severity = severity
        vulnerability.cwe = cwe
        vulnerability.published_at = published_at
        vulnerability.modified_at = modified_at
        vulnerability.provider_json = provider_json or {}
        self.session.flush()
        return vulnerability

    def create_or_update_finding(
        self,
        *,
        project_id: uuid.UUID,
        vulnerability_id: uuid.UUID,
        cve_id: str,
        priority: FindingPriority | str,
        component_id: uuid.UUID | None = None,
        asset_id: uuid.UUID | None = None,
        status: FindingStatus | str = FindingStatus.OPEN,
        priority_rank: int = 99,
        risk_score: float | None = None,
        operational_rank: int = 0,
        in_kev: bool = False,
        epss: float | None = None,
        cvss_base_score: float | None = None,
        explanation_json: dict[str, Any] | None = None,
        data_quality_json: dict[str, Any] | None = None,
        evidence_json: dict[str, Any] | None = None,
    ) -> Finding:
        """Create or update a finding by project/vulnerability/component/asset identity."""
        filters: list[Any] = [
            Finding.project_id == project_id,
            Finding.vulnerability_id == vulnerability_id,
        ]
        filters.append(
            col(Finding.component_id).is_(None)
            if component_id is None
            else Finding.component_id == component_id
        )
        filters.append(
            col(Finding.asset_id).is_(None) if asset_id is None else Finding.asset_id == asset_id
        )
        finding = self.session.exec(select(Finding).where(*filters)).first()
        if finding is None:
            finding = Finding(
                project_id=project_id,
                vulnerability_id=vulnerability_id,
                component_id=component_id,
                asset_id=asset_id,
                cve_id=cve_id,
                status=FindingStatus(status),
                priority=FindingPriority(priority),
                priority_rank=priority_rank,
            )
            self.session.add(finding)

        finding.cve_id = cve_id
        finding.priority = FindingPriority(priority)
        finding.priority_rank = priority_rank
        finding.status = FindingStatus(status)
        finding.risk_score = risk_score
        finding.operational_rank = operational_rank
        finding.in_kev = in_kev
        finding.epss = epss
        finding.cvss_base_score = cvss_base_score
        finding.explanation_json = explanation_json or {}
        finding.data_quality_json = data_quality_json or {}
        finding.evidence_json = evidence_json or {}
        finding.last_seen_at = get_datetime_utc()
        self.session.flush()
        return finding

    def get_finding(self, finding_id: uuid.UUID) -> Finding | None:
        """Return a finding by primary key."""
        return self.session.get(Finding, finding_id)

    def list_project_findings(self, project_id: uuid.UUID) -> list[Finding]:
        """Return project findings ordered by operational priority."""
        statement = (
            select(Finding)
            .where(Finding.project_id == project_id)
            .order_by(col(Finding.operational_rank), col(Finding.priority_rank), Finding.cve_id)
        )
        return list(self.session.exec(statement).all())
