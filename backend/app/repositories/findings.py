"""Finding repository for Workbench persistence."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy.orm import QueryableAttribute, selectinload
from sqlmodel import Session, col, select

from app.models import (
    Asset,
    AttackSummaryContextRow,
    AttackSummaryFindingRow,
    Component,
    Finding,
    FindingAttackContext,
    FindingPriority,
    FindingStatus,
    GovernanceRollupPublic,
    Vulnerability,
)
from app.models.base import get_datetime_utc
from app.repositories.finding_attack_query import (
    list_project_attack_contexts as _list_project_attack_contexts,
)
from app.repositories.finding_attack_query import (
    list_project_attack_summary_contexts as _list_project_attack_summary_contexts,
)
from app.repositories.finding_page_query import (
    FindingPageQuery,
)

if TYPE_CHECKING:
    from app.services.decision_projection import DecisionFindingView


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
        finding.status = FindingStatus(status)
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

    def project_finding_summary_counts(self, project_id: uuid.UUID) -> dict[str, Any]:
        """Return dashboard summary counts from evidence-backed decision views."""
        from app.services.decision_projection import project_finding_decision_views  # noqa: PLC0415

        findings = self.list_project_findings(project_id)
        views = project_finding_decision_views(self.session, findings)
        open_statuses = {
            FindingStatus.OPEN,
            FindingStatus.IN_REVIEW,
            FindingStatus.REMEDIATING,
        }
        priority_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        for view in views:
            priority_counts[view.priority.value] = priority_counts.get(view.priority.value, 0) + 1
            status_counts[view.status.value] = status_counts.get(view.status.value, 0) + 1
        return {
            "finding_count": len(views),
            "open_finding_count": sum(1 for view in views if view.status in open_statuses),
            "counts_by_priority": priority_counts,
            "counts_by_status": status_counts,
            "kev_hits": sum(1 for view in views if view.in_kev),
            "epss_hits": sum(1 for view in views if view.epss is not None),
            "cvss_known_count": sum(1 for view in views if view.cvss_base_score is not None),
        }

    def _count_project_findings_where(self, project_id: uuid.UUID, *criteria: Any) -> int:
        """Count project findings matching additional SQL identity criteria."""
        statement = select(Finding).where(Finding.project_id == project_id, *criteria)
        return len(list(self.session.exec(statement).all()))

    def project_dashboard_signal_counts(self, project_id: uuid.UUID) -> dict[str, Any]:
        """Return dashboard signal counts from evidence-backed decision views."""
        from app.services.dashboard_counts import dashboard_signal_counts  # noqa: PLC0415
        from app.services.decision_projection import project_finding_decision_views  # noqa: PLC0415

        counts = dashboard_signal_counts(
            project_finding_decision_views(self.session, self.list_project_findings(project_id))
        )
        return counts.model_dump()

    def project_governance_rollups(
        self,
        project_id: uuid.UUID,
        *,
        dimension: str,
        limit: int,
    ) -> list[GovernanceRollupPublic]:
        """Return evidence-backed governance rollups for one project dimension."""
        from app.services.decision_projection import project_finding_decision_views  # noqa: PLC0415
        from app.services.governance_rollups import (
            build_project_governance_rollups_payload,  # noqa: PLC0415
        )

        rollups = build_project_governance_rollups_payload(
            project_id=project_id,
            findings=project_finding_decision_views(
                self.session,
                self.list_project_findings(project_id),
            ),
            limit=limit,
        )
        return {
            "owner": rollups.owners,
            "service": rollups.services,
            "asset": rollups.assets,
            "environment": rollups.environments,
        }[dimension]

    def project_waiver_finding_counts(self, project_id: uuid.UUID) -> dict[str, int]:
        """Return accepted-risk finding counts for governance debt."""
        from app.services.decision_projection import project_finding_decision_views  # noqa: PLC0415

        views = project_finding_decision_views(self.session, self.list_project_findings(project_id))
        return {
            "accepted_finding_count": sum(
                1 for view in views if view.status == FindingStatus.ACCEPTED or view.waived
            ),
            "expired_finding_count": 0,
            "review_due_finding_count": 0,
        }

    def _top_cves_for_governance_label(
        self,
        project_id: uuid.UUID,
        *,
        dimension: str,
        label: str,
    ) -> list[str]:
        return [
            rollup_cve
            for rollup in self.project_governance_rollups(
                project_id,
                dimension=dimension,
                limit=500,
            )
            if rollup.label == label
            for rollup_cve in rollup.top_cves
        ][:5]

    def list_project_attack_contexts(self, project_id: uuid.UUID) -> list[FindingAttackContext]:
        """Return ATT&CK contexts for findings in one project, newest rows first."""
        return _list_project_attack_contexts(self.session, project_id)

    def list_project_attack_summary_inputs(
        self,
        project_id: uuid.UUID,
    ) -> tuple[list[AttackSummaryFindingRow], list[AttackSummaryContextRow]]:
        """Return evidence-backed rows needed for the ATT&CK dashboard summary."""
        from app.services.decision_projection import project_finding_decision_views  # noqa: PLC0415

        finding_rows = [
            AttackSummaryFindingRow(id=view.finding.id, risk_score=view.risk_score)
            for view in project_finding_decision_views(
                self.session,
                self.list_project_findings(project_id),
            )
        ]
        context_rows = _list_project_attack_summary_contexts(self.session, project_id)
        return finding_rows, context_rows

    def list_project_findings_page(
        self,
        project_id: uuid.UUID,
        *,
        limit: int = 100,
        offset: int = 0,
        sort: str = "operational",
        direction: str = "asc",
        priority: FindingPriority | str | None = None,
        status: FindingStatus | str | None = None,
        kev: bool | None = None,
        owner: str | None = None,
        service: str | None = None,
        owner_service: str | None = None,
        query: str | None = None,
        asset_id: uuid.UUID | None = None,
        exposure: str | None = None,
        epss_min: float | None = None,
        epss_max: float | None = None,
        cvss_min: float | None = None,
        cvss_max: float | None = None,
    ) -> tuple[list[Finding], int]:
        """Return a filtered, sorted, paginated project finding page."""
        return self.list_project_findings_query(
            FindingPageQuery(
                project_id=project_id,
                limit=limit,
                offset=offset,
                sort=sort,
                direction=direction,
                priority=priority,
                status=status,
                kev=kev,
                owner=owner,
                service=service,
                owner_service=owner_service,
                query=query,
                asset_id=asset_id,
                exposure=exposure,
                epss_min=epss_min,
                epss_max=epss_max,
                cvss_min=cvss_min,
                cvss_max=cvss_max,
            )
        )

    def list_project_findings_query(
        self,
        query: FindingPageQuery,
    ) -> tuple[list[Finding], int]:
        """Return a filtered, sorted, paginated project finding page."""
        asset_relationship = cast(QueryableAttribute[Any], Finding.asset)
        component_relationship = cast(QueryableAttribute[Any], Finding.component)
        statement = (
            select(Finding)
            .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
            .outerjoin(Component, col(Finding.component_id) == col(Component.id))
            .options(
                selectinload(asset_relationship),
                selectinload(component_relationship),
            )
            .where(Finding.project_id == query.project_id)
            .order_by(Finding.cve_id, col(Finding.id))
        )
        findings = list(self.session.exec(statement).all())
        from app.services.decision_projection import (  # noqa: PLC0415
            project_finding_decision_views,
        )

        views = [
            view
            for view in project_finding_decision_views(self.session, findings)
            if _matches_finding_page_query(view, query)
        ]
        views.sort(key=lambda view: _finding_page_sort_key(view, query))
        if query.direction == "desc":
            views.reverse()
        count = len(views)
        page = views[query.offset : query.offset + query.limit]
        return [view.finding for view in page], count


def _matches_finding_page_query(
    view: DecisionFindingView,
    query: FindingPageQuery,
) -> bool:
    finding = view.finding
    asset = finding.asset
    component = finding.component
    if query.priority is not None and view.priority != FindingPriority(query.priority):
        return False
    if query.status is not None and view.status != FindingStatus(query.status):
        return False
    if query.kev is not None and view.in_kev != query.kev:
        return False
    if query.asset_id is not None and finding.asset_id != query.asset_id:
        return False
    if query.exposure is not None and (asset is None or asset.exposure != query.exposure):
        return False
    if query.epss_min is not None and (view.epss is None or view.epss < query.epss_min):
        return False
    if query.epss_max is not None and (view.epss is None or view.epss > query.epss_max):
        return False
    if query.cvss_min is not None and (
        view.cvss_base_score is None or view.cvss_base_score < query.cvss_min
    ):
        return False
    if query.cvss_max is not None and (
        view.cvss_base_score is None or view.cvss_base_score > query.cvss_max
    ):
        return False
    if not _contains(asset.owner if asset else None, query.owner):
        return False
    if not _contains(asset.business_service if asset else None, query.service):
        return False
    if query.owner_service and not (
        _contains(asset.owner if asset else None, query.owner_service)
        or _contains(asset.business_service if asset else None, query.owner_service)
    ):
        return False
    if query.query and not any(
        _contains(value, query.query)
        for value in (
            view.cve_id,
            view.recommended_action,
            view.rationale,
            component.name if component else None,
            component.version if component else None,
            component.purl if component else None,
            component.ecosystem if component else None,
            asset.asset_key if asset else None,
            asset.name if asset else None,
            asset.target_ref if asset else None,
            asset.owner if asset else None,
            asset.business_service if asset else None,
        )
    ):
        return False
    return True


def _contains(value: object, needle: str | None) -> bool:
    if not needle or not needle.strip():
        return True
    return needle.strip().casefold() in str(value or "").casefold()


def _finding_page_sort_key(view: DecisionFindingView, query: FindingPageQuery) -> tuple[Any, ...]:
    finding = view.finding
    asset = finding.asset
    component = finding.component
    if query.sort == "operational":
        return (view.operational_rank or 999_999, view.priority_rank, view.cve_id, str(finding.id))
    if query.sort == "priority":
        return (view.priority_rank, view.cve_id, str(finding.id))
    if query.sort == "score":
        return (_none_last_number(view.risk_score), view.priority_rank, view.cve_id)
    if query.sort == "cve":
        return (view.cve_id, str(finding.id))
    if query.sort == "status":
        return (view.status.value, view.cve_id, str(finding.id))
    if query.sort == "epss":
        return (_none_last_number(view.epss), view.priority_rank, view.cve_id)
    if query.sort == "cvss":
        return (_none_last_number(view.cvss_base_score), view.priority_rank, view.cve_id)
    if query.sort == "kev":
        return (1 if view.in_kev else 0, view.priority_rank, view.cve_id)
    if query.sort == "last_seen":
        return (finding.last_seen_at, view.priority_rank, view.cve_id)
    if query.sort == "component":
        return (
            str(component.name if component else ""),
            str(component.version if component else ""),
            str(asset.business_service if asset else ""),
            str(asset.asset_key if asset else ""),
            view.cve_id,
        )
    if query.sort == "owner":
        return (
            str(asset.owner if asset else ""),
            str(asset.business_service if asset else ""),
            str(asset.asset_key if asset else ""),
            view.cve_id,
        )
    raise ValueError(f"Unsupported findings sort field: {query.sort}.")


def _none_last_number(value: float | int | None) -> tuple[int, float]:
    return (1, 0.0) if value is None else (0, float(value))
