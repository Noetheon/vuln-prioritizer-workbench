"""Finding, component, and vulnerability persistence helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session, selectinload

from vuln_prioritizer.db.models import (
    Asset,
    Component,
    Finding,
    FindingOccurrence,
    FindingStatusHistory,
    Vulnerability,
    utc_now,
)

FINDING_SORT_FIELDS = {"operational", "priority", "epss", "cvss", "cve", "status"}


class FindingRepositoryMixin:
    """Finding repository methods."""

    session: Session

    def upsert_component(
        self,
        *,
        name: str,
        version: str | None = None,
        purl: str | None = None,
        ecosystem: str | None = None,
        package_type: str | None = None,
    ) -> Component:
        component = self.session.scalar(
            select(Component).where(
                Component.name == name,
                Component.version == version,
                Component.purl == purl,
            )
        )
        if component is None:
            component = Component(name=name, version=version, purl=purl)
            self.session.add(component)
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
        provider_json: dict | None = None,
    ) -> Vulnerability:
        vulnerability = self.session.scalar(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        )
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

    def get_vulnerability_by_cve(self, cve_id: str) -> Vulnerability | None:
        return self.session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))

    def list_findings_for_cve(self, project_id: str, cve_id: str) -> list[Finding]:
        statement = (
            select(Finding)
            .where(Finding.project_id == project_id, Finding.cve_id == cve_id)
            .options(
                selectinload(Finding.vulnerability),
                selectinload(Finding.component),
                selectinload(Finding.asset),
                selectinload(Finding.occurrences),
            )
            .order_by(Finding.operational_rank, Finding.last_seen_at.desc())
        )
        return list(self.session.scalars(statement))

    def create_or_update_finding(
        self,
        *,
        project_id: str,
        vulnerability_id: str,
        cve_id: str,
        priority: str,
        component_id: str | None = None,
        asset_id: str | None = None,
        analysis_run_id: str | None = None,
        status: str = "open",
        risk_score: float | None = None,
        priority_rank: int = 99,
        operational_rank: int = 0,
        in_kev: bool = False,
        epss: float | None = None,
        cvss_base_score: float | None = None,
        attack_mapped: bool = False,
        suppressed_by_vex: bool = False,
        under_investigation: bool = False,
        waiver_status: str | None = None,
        waiver_reason: str | None = None,
        waiver_owner: str | None = None,
        waiver_expires_on: str | None = None,
        waiver_review_on: str | None = None,
        waiver_days_remaining: int | None = None,
        waiver_scope: str | None = None,
        waiver_id: str | None = None,
        waiver_matched_scope: str | None = None,
        waiver_approval_ref: str | None = None,
        waiver_ticket_url: str | None = None,
        recommended_action: str | None = None,
        rationale: str | None = None,
        explanation_json: dict | None = None,
        finding_json: dict | None = None,
        waived: bool = False,
    ) -> Finding:
        statement: Select[tuple[Finding]] = select(Finding).where(
            Finding.project_id == project_id,
            Finding.vulnerability_id == vulnerability_id,
            Finding.component_id == component_id,
            Finding.asset_id == asset_id,
        )
        finding = self.session.scalar(statement)
        is_new = finding is None
        if finding is None:
            finding = Finding(
                project_id=project_id,
                vulnerability_id=vulnerability_id,
                component_id=component_id,
                asset_id=asset_id,
                cve_id=cve_id,
                priority=priority,
            )
            self.session.add(finding)
        finding.analysis_run_id = analysis_run_id
        finding.cve_id = cve_id
        if is_new:
            finding.status = status
        finding.priority = priority
        finding.priority_rank = priority_rank
        finding.risk_score = risk_score
        finding.operational_rank = operational_rank
        finding.in_kev = in_kev
        finding.epss = epss
        finding.cvss_base_score = cvss_base_score
        finding.attack_mapped = attack_mapped
        finding.suppressed_by_vex = suppressed_by_vex
        finding.under_investigation = under_investigation
        finding.waiver_status = waiver_status
        finding.waiver_reason = waiver_reason
        finding.waiver_owner = waiver_owner
        finding.waiver_expires_on = waiver_expires_on
        finding.waiver_review_on = waiver_review_on
        finding.waiver_days_remaining = waiver_days_remaining
        finding.waiver_scope = waiver_scope
        finding.waiver_id = waiver_id
        finding.waiver_matched_scope = waiver_matched_scope
        finding.waiver_approval_ref = waiver_approval_ref
        finding.waiver_ticket_url = waiver_ticket_url
        finding.recommended_action = recommended_action
        finding.rationale = rationale
        finding.explanation_json = explanation_json or {}
        finding.finding_json = finding_json or {}
        finding.waived = waived
        finding.last_seen_at = utc_now()
        self.session.flush()
        return finding

    def add_finding_occurrence(
        self,
        *,
        finding_id: str,
        analysis_run_id: str,
        scanner: str | None = None,
        raw_reference: str | None = None,
        fix_version: str | None = None,
        evidence_json: dict | None = None,
    ) -> FindingOccurrence:
        occurrence = FindingOccurrence(
            finding_id=finding_id,
            analysis_run_id=analysis_run_id,
            scanner=scanner,
            raw_reference=raw_reference,
            fix_version=fix_version,
            evidence_json=evidence_json or {},
        )
        self.session.add(occurrence)
        self.session.flush()
        return occurrence

    def list_project_findings(self, project_id: str) -> list[Finding]:
        statement = (
            select(Finding)
            .where(Finding.project_id == project_id)
            .options(
                selectinload(Finding.vulnerability),
                selectinload(Finding.component),
                selectinload(Finding.asset),
                selectinload(Finding.occurrences),
                selectinload(Finding.attack_contexts),
                selectinload(Finding.status_history),
            )
            .order_by(Finding.operational_rank, Vulnerability.cve_id)
            .join(Finding.vulnerability)
        )
        return list(self.session.scalars(statement))

    def list_project_findings_page(
        self,
        project_id: str,
        *,
        priority: str | None = None,
        status: str | None = None,
        q: str | None = None,
        kev: bool | None = None,
        owner: str | None = None,
        service: str | None = None,
        min_epss: float | None = None,
        min_cvss: float | None = None,
        sort: str = "operational",
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Finding], int]:
        """Return a server-side filtered and paginated findings page."""
        if sort not in FINDING_SORT_FIELDS:
            raise ValueError(f"Unsupported findings sort field: {sort}.")

        filters = [Finding.project_id == project_id]
        if priority:
            filters.append(Finding.priority == priority)
        if status:
            filters.append(Finding.status == status)
        if kev is not None:
            filters.append(Finding.in_kev.is_(kev))
        if owner:
            filters.append(Asset.owner == owner)
        if service:
            filters.append(Asset.business_service == service)
        if min_epss is not None:
            filters.append(Finding.epss.is_not(None))
            filters.append(Finding.epss >= min_epss)
        if min_cvss is not None:
            filters.append(Finding.cvss_base_score.is_not(None))
            filters.append(Finding.cvss_base_score >= min_cvss)
        if q:
            pattern = f"%{q.strip()}%"
            filters.append(
                or_(
                    Finding.cve_id.ilike(pattern),
                    Vulnerability.description.ilike(pattern),
                    Component.name.ilike(pattern),
                    Asset.asset_id.ilike(pattern),
                    Asset.owner.ilike(pattern),
                    Asset.business_service.ilike(pattern),
                )
            )

        base = (
            select(Finding)
            .join(Finding.vulnerability)
            .outerjoin(Finding.component)
            .outerjoin(Finding.asset)
            .where(*filters)
        )
        total = self.session.scalar(select(func.count()).select_from(base.subquery())) or 0
        statement = (
            base.options(
                selectinload(Finding.vulnerability),
                selectinload(Finding.component),
                selectinload(Finding.asset),
                selectinload(Finding.occurrences),
                selectinload(Finding.attack_contexts),
            )
            .order_by(*_finding_order_by(sort))
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(statement)), int(total)

    def get_finding(self, finding_id: str) -> Finding | None:
        statement = (
            select(Finding)
            .where(Finding.id == finding_id)
            .options(
                selectinload(Finding.vulnerability),
                selectinload(Finding.component),
                selectinload(Finding.asset),
                selectinload(Finding.occurrences),
                selectinload(Finding.attack_contexts),
                selectinload(Finding.status_history),
            )
        )
        return self.session.scalar(statement)

    def update_finding_status(
        self,
        finding: Finding,
        *,
        status: str,
        actor: str | None = None,
        reason: str | None = None,
    ) -> FindingStatusHistory:
        previous_status = finding.status
        finding.status = status
        finding.last_seen_at = utc_now()
        history = FindingStatusHistory(
            project_id=finding.project_id,
            finding_id=finding.id,
            previous_status=previous_status,
            new_status=status,
            actor=actor,
            reason=reason,
        )
        finding.status_history.append(history)
        self.session.add(history)
        self.session.flush()
        return history

    def list_finding_status_history(self, finding_id: str) -> list[FindingStatusHistory]:
        statement = (
            select(FindingStatusHistory)
            .where(FindingStatusHistory.finding_id == finding_id)
            .order_by(FindingStatusHistory.created_at)
        )
        return list(self.session.scalars(statement))


def _finding_order_by(sort: str) -> tuple[Any, ...]:
    if sort == "priority":
        return (Finding.priority_rank, Finding.operational_rank, Finding.cve_id)
    if sort == "epss":
        return (
            Finding.epss.desc().nullslast(),
            Finding.priority_rank,
            Finding.operational_rank,
            Finding.cve_id,
        )
    if sort == "cvss":
        return (
            Finding.cvss_base_score.desc().nullslast(),
            Finding.priority_rank,
            Finding.operational_rank,
            Finding.cve_id,
        )
    if sort == "cve":
        return (Finding.cve_id, Finding.operational_rank)
    if sort == "status":
        return (Finding.status, Finding.operational_rank, Finding.cve_id)
    return (Finding.operational_rank, Finding.priority_rank, Finding.cve_id)
