"""Finding repository for Workbench persistence."""

from __future__ import annotations

import uuid
from typing import Any, cast

from sqlalchemy.orm import QueryableAttribute, selectinload
from sqlmodel import Session, col, select

from app.models import (
    Component,
    Finding,
    FindingAttackContext,
    FindingStatus,
    Vulnerability,
)
from app.models.base import get_datetime_utc
from app.repositories.finding_attack_query import (
    list_project_attack_contexts as _list_project_attack_contexts,
)

_MANUAL_WORKFLOW_STATUSES = {
    FindingStatus.IN_REVIEW,
    FindingStatus.REMEDIATING,
}


class FindingRepository:
    """Finding, component, and vulnerability persistence helpers."""

    def __init__(self, session: Session) -> None:
        """Initialize a new instance of FindingRepository."""
        self.session = session

    def upsert_component(
        self,
        *,
        name: str,
        version: str | None = None,
        purl: str | None = None,
        ecosystem: str | None = None,
        package_type: str | None = None,
        flush: bool = True,
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
        if flush:
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
        flush: bool = True,
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
        if flush:
            self.session.flush()
        return vulnerability

    def create_or_update_finding(
        self,
        *,
        project_id: uuid.UUID,
        vulnerability_id: uuid.UUID,
        cve_id: str,
        dedup_key: str | None = None,
        component_id: uuid.UUID | None = None,
        asset_id: uuid.UUID | None = None,
        status: FindingStatus | str = FindingStatus.OPEN,
        existing_finding: Finding | None = None,
        lookup_existing: bool = True,
        flush: bool = True,
    ) -> Finding:
        """Create or update a finding by project/vulnerability/component/asset identity."""
        finding = existing_finding
        if finding is None and lookup_existing and dedup_key is not None:
            finding = self.get_project_finding_by_dedup_key(
                project_id=project_id,
                dedup_key=dedup_key,
            )
        if finding is None and lookup_existing:
            finding = self.get_project_finding_by_identity(
                project_id=project_id,
                vulnerability_id=vulnerability_id,
                component_id=component_id,
                asset_id=asset_id,
            )
        if finding is None:
            finding = Finding(
                project_id=project_id,
                vulnerability_id=vulnerability_id,
                component_id=component_id,
                asset_id=asset_id,
                cve_id=cve_id,
                dedup_key=dedup_key or str(uuid.uuid4()),
                status=FindingStatus(status),
            )
            self.session.add(finding)

        if dedup_key is not None:
            finding.dedup_key = dedup_key
        finding.cve_id = cve_id
        finding.status = _import_status_for_finding(
            current=FindingStatus(finding.status),
            imported=FindingStatus(status),
        )
        finding.last_seen_at = get_datetime_utc()
        if flush:
            self.session.flush()
        return finding

    def get_project_finding_by_dedup_key(
        self,
        *,
        project_id: uuid.UUID,
        dedup_key: str,
    ) -> Finding | None:
        """Return a project finding by its stable import dedup key."""
        statement = select(Finding).where(
            Finding.project_id == project_id,
            Finding.dedup_key == dedup_key,
        )
        return self.session.exec(statement).first()

    def get_project_finding_by_identity(
        self,
        *,
        project_id: uuid.UUID,
        vulnerability_id: uuid.UUID,
        component_id: uuid.UUID | None = None,
        asset_id: uuid.UUID | None = None,
    ) -> Finding | None:
        """Return a finding by project/vulnerability/component/asset identity."""
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
        return self.session.exec(select(Finding).where(*filters)).first()

    def get_finding(self, finding_id: uuid.UUID) -> Finding | None:
        """Return a finding by primary key."""
        return self.session.get(Finding, finding_id)

    def list_project_findings(self, project_id: uuid.UUID) -> list[Finding]:
        """Return project findings ordered by operational priority."""
        asset_relationship = cast(QueryableAttribute[Any], Finding.asset)
        component_relationship = cast(QueryableAttribute[Any], Finding.component)
        statement = (
            select(Finding)
            .where(Finding.project_id == project_id)
            .options(
                selectinload(asset_relationship),
                selectinload(component_relationship),
            )
            .order_by(Finding.cve_id, col(Finding.id))
        )
        return list(self.session.exec(statement).all())

    def count_project_findings(self, project_id: uuid.UUID) -> int:
        """Return the project finding count without materializing finding rows."""
        statement = select(Finding).where(Finding.project_id == project_id)
        return len(list(self.session.exec(statement).all()))

    def _count_project_findings_where(self, project_id: uuid.UUID, *criteria: Any) -> int:
        """Count project findings matching additional SQL identity criteria."""
        statement = select(Finding).where(Finding.project_id == project_id, *criteria)
        return len(list(self.session.exec(statement).all()))

    def list_project_attack_contexts(self, project_id: uuid.UUID) -> list[FindingAttackContext]:
        """Return ATT&CK contexts for findings in one project, newest rows first."""
        return _list_project_attack_contexts(self.session, project_id)


def _import_status_for_finding(
    *,
    current: FindingStatus,
    imported: FindingStatus,
) -> FindingStatus:
    """Keep analyst workflow status unless import evidence moves the finding elsewhere."""
    if imported == FindingStatus.OPEN and current in _MANUAL_WORKFLOW_STATUSES:
        return current
    return imported
