"""Finding repository for Workbench persistence."""

from __future__ import annotations

import uuid
from typing import Any, cast

from sqlalchemy import case, or_
from sqlalchemy.orm import QueryableAttribute, selectinload
from sqlmodel import Session, col, func, select

from app.models import (
    Asset,
    AssetExposure,
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
from app.repositories.finding_page_query import (
    FindingPageQuery,
    finding_page_filters,
    finding_page_order_by,
)

PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
STATUS_LABELS = tuple(status.value for status in FindingStatus)
OPEN_WORK_STATUSES = (
    FindingStatus.OPEN,
    FindingStatus.IN_REVIEW,
    FindingStatus.REMEDIATING,
)
UNKNOWN_LABEL = "Unassigned"


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
        attack_mapped: bool = False,
        suppressed_by_vex: bool = False,
        under_investigation: bool = False,
        waived: bool = False,
        recommended_action: str | None = None,
        rationale: str | None = None,
        explanation_json: dict[str, Any] | None = None,
        data_quality_json: dict[str, Any] | None = None,
        evidence_json: dict[str, Any] | None = None,
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
                priority=FindingPriority(priority),
                priority_rank=priority_rank,
            )
            self.session.add(finding)

        if dedup_key is not None:
            finding.dedup_key = dedup_key
        finding.cve_id = cve_id
        finding.priority = FindingPriority(priority)
        finding.priority_rank = priority_rank
        finding.status = FindingStatus(status)
        finding.risk_score = risk_score
        finding.operational_rank = operational_rank
        finding.in_kev = in_kev
        finding.epss = epss
        finding.cvss_base_score = cvss_base_score
        finding.attack_mapped = attack_mapped
        finding.suppressed_by_vex = suppressed_by_vex
        finding.under_investigation = under_investigation
        finding.waived = waived
        finding.recommended_action = recommended_action
        finding.rationale = rationale
        finding.explanation_json = explanation_json or {}
        finding.data_quality_json = data_quality_json or {}
        finding.evidence_json = evidence_json or {}
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
            .order_by(col(Finding.operational_rank), col(Finding.priority_rank), Finding.cve_id)
        )
        return list(self.session.exec(statement).all())

    def count_project_findings(self, project_id: uuid.UUID) -> int:
        """Return the project finding count without materializing finding rows."""
        statement = (
            select(func.count()).select_from(Finding).where(Finding.project_id == project_id)
        )
        return int(self.session.exec(statement).one())

    def project_finding_summary_counts(self, project_id: uuid.UUID) -> dict[str, Any]:
        """Return dashboard summary counts with bounded aggregate queries."""
        open_statuses = [
            FindingStatus.OPEN,
            FindingStatus.IN_REVIEW,
            FindingStatus.REMEDIATING,
        ]
        priority_counts = {
            str(priority): int(count)
            for priority, count in self.session.exec(
                select(Finding.priority, func.count())
                .where(Finding.project_id == project_id)
                .group_by(Finding.priority)
            ).all()
        }
        status_counts = {
            str(status): int(count)
            for status, count in self.session.exec(
                select(Finding.status, func.count())
                .where(Finding.project_id == project_id)
                .group_by(Finding.status)
            ).all()
        }
        return {
            "finding_count": self.count_project_findings(project_id),
            "open_finding_count": self._count_project_findings_where(
                project_id,
                col(Finding.status).in_(open_statuses),
            ),
            "counts_by_priority": priority_counts,
            "counts_by_status": status_counts,
            "kev_hits": self._count_project_findings_where(
                project_id,
                col(Finding.in_kev).is_(True),
            ),
            "epss_hits": self._count_project_findings_where(
                project_id,
                col(Finding.epss).is_not(None),
            ),
            "cvss_known_count": self._count_project_findings_where(
                project_id,
                col(Finding.cvss_base_score).is_not(None),
            ),
        }

    def _count_project_findings_where(self, project_id: uuid.UUID, *criteria: Any) -> int:
        """Count project findings where method for FindingRepository."""
        statement = (
            select(func.count())
            .select_from(Finding)
            .where(Finding.project_id == project_id, *criteria)
        )
        return int(self.session.exec(statement).one())

    def project_dashboard_signal_counts(self, project_id: uuid.UUID) -> dict[str, Any]:
        """Return dashboard signal counts without materializing project findings."""
        epss = col(Finding.epss)
        priority = col(Finding.priority)
        exposure = col(Asset.exposure)
        columns: list[Any] = [
            func.sum(_case_int(epss >= 0.7)),
            func.sum(_case_int((epss >= 0) & (epss <= 0.25))),
            func.sum(_case_int((epss >= 0.25) & (epss <= 0.5))),
            func.sum(_case_int((epss >= 0.5) & (epss <= 0.7))),
            func.sum(
                _case_int(
                    (priority == FindingPriority.CRITICAL)
                    & (exposure == AssetExposure.INTERNET_FACING)
                )
            ),
        ]
        epss_bucket_rows = self.session.exec(
            select(*columns)
            .select_from(Finding)
            .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
            .where(Finding.project_id == project_id)
        ).one()
        high_epss, low, medium, high, internet_facing_criticals = epss_bucket_rows
        return {
            "high_epss": int(high_epss or 0),
            "internet_facing_criticals": int(internet_facing_criticals or 0),
            "epss_buckets": {
                "low": int(low or 0),
                "medium": int(medium or 0),
                "high": int(high or 0),
                "critical": int(high_epss or 0),
            },
        }

    def project_governance_rollups(
        self,
        project_id: uuid.UUID,
        *,
        dimension: str,
        limit: int,
    ) -> list[GovernanceRollupPublic]:
        """Return SQL-backed governance rollups for one project dimension."""
        label_expr = _governance_label_expression(dimension)
        waiver_status = Finding.explanation_json["waiver_status"].as_string()
        status = col(Finding.status)
        priority = col(Finding.priority)
        waived = col(Finding.waived)
        in_kev = col(Finding.in_kev)
        attack_mapped = col(Finding.attack_mapped)
        suppressed_by_vex = col(Finding.suppressed_by_vex)
        under_investigation = col(Finding.under_investigation)
        risk_score = col(Finding.risk_score)
        columns: list[Any] = [
            label_expr,
            func.count(),
            func.sum(_case_int(status.in_(OPEN_WORK_STATUSES))),
            func.sum(
                _case_int(
                    or_(
                        status == FindingStatus.ACCEPTED,
                        waived.is_(True),
                    )
                )
            ),
            func.sum(_case_int(status == FindingStatus.FIXED)),
            func.sum(_case_int(status == FindingStatus.SUPPRESSED)),
            func.sum(_case_int(priority == FindingPriority.CRITICAL)),
            func.sum(_case_int(priority == FindingPriority.HIGH)),
            func.sum(_case_int(in_kev.is_(True))),
            func.sum(_case_int(attack_mapped.is_(True))),
            func.sum(_case_int(suppressed_by_vex.is_(True))),
            func.sum(_case_int(under_investigation.is_(True))),
            func.sum(_case_int(waived.is_(True))),
            func.sum(_case_int(waiver_status == "expired")),
            func.sum(_case_int(waiver_status == "review_due")),
            func.coalesce(func.sum(risk_score), 0.0),
            func.max(risk_score),
            *[
                func.sum(_case_int(priority == finding_priority))
                for finding_priority in (
                    FindingPriority.CRITICAL,
                    FindingPriority.HIGH,
                    FindingPriority.MEDIUM,
                    FindingPriority.LOW,
                )
            ],
            *[func.sum(_case_int(status == finding_status)) for finding_status in FindingStatus],
        ]
        statement = (
            select(*columns)
            .select_from(Finding)
            .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
            .where(Finding.project_id == project_id)
            .group_by(label_expr)
        )
        rollups = [
            _governance_rollup_from_row(
                row,
                dimension=dimension,
                top_cves=self._top_cves_for_governance_label(
                    project_id,
                    dimension=dimension,
                    label=str(row[0]),
                ),
            )
            for row in self.session.exec(statement).all()
        ]
        rollups.sort(
            key=lambda item: (
                -item.risk_score_total,
                -item.critical_count,
                -item.high_count,
                -item.finding_count,
                item.label.casefold(),
            )
        )
        return rollups[:limit]

    def project_waiver_finding_counts(self, project_id: uuid.UUID) -> dict[str, int]:
        """Return accepted-risk finding counts for governance debt."""
        waiver_status = Finding.explanation_json["waiver_status"].as_string()
        status = col(Finding.status)
        waived = col(Finding.waived)
        columns: list[Any] = [
            func.sum(
                _case_int(
                    or_(
                        status == FindingStatus.ACCEPTED,
                        waived.is_(True),
                    )
                )
            ),
            func.sum(_case_int(waiver_status == "expired")),
            func.sum(_case_int(waiver_status == "review_due")),
        ]
        accepted, expired, review_due = self.session.exec(
            select(*columns).select_from(Finding).where(Finding.project_id == project_id)
        ).one()
        return {
            "accepted_finding_count": int(accepted or 0),
            "expired_finding_count": int(expired or 0),
            "review_due_finding_count": int(review_due or 0),
        }

    def _top_cves_for_governance_label(
        self,
        project_id: uuid.UUID,
        *,
        dimension: str,
        label: str,
    ) -> list[str]:
        label_expr = _governance_label_expression(dimension)
        statement = (
            select(Finding.cve_id)
            .select_from(Finding)
            .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
            .where(Finding.project_id == project_id, label_expr == label)
            .order_by(col(Finding.operational_rank), col(Finding.priority_rank), Finding.cve_id)
            .limit(5)
        )
        return list(self.session.exec(statement).all())

    def list_project_attack_contexts(self, project_id: uuid.UUID) -> list[FindingAttackContext]:
        """Return ATT&CK contexts for findings in one project, newest rows first."""
        statement = (
            select(FindingAttackContext)
            .join(Finding, col(FindingAttackContext.finding_id) == col(Finding.id))
            .where(Finding.project_id == project_id)
            .order_by(col(FindingAttackContext.created_at).desc())
        )
        return list(self.session.exec(statement).all())

    def list_project_attack_summary_inputs(
        self,
        project_id: uuid.UUID,
    ) -> tuple[list[AttackSummaryFindingRow], list[AttackSummaryContextRow]]:
        """Return lightweight rows needed for the ATT&CK dashboard summary."""
        finding_columns: list[Any] = [Finding.id, Finding.risk_score]
        finding_rows = [
            AttackSummaryFindingRow(id=finding_id, risk_score=risk_score)
            for finding_id, risk_score in self.session.exec(
                select(*finding_columns).where(Finding.project_id == project_id)
            ).all()
        ]
        context_columns: list[Any] = [
            FindingAttackContext.finding_id,
            FindingAttackContext.mapped,
            FindingAttackContext.technique_ids_json,
            FindingAttackContext.tactic_ids_json,
            FindingAttackContext.mappings_json,
            FindingAttackContext.review_status,
            FindingAttackContext.source,
            FindingAttackContext.created_at,
        ]
        context_rows = [
            AttackSummaryContextRow(
                finding_id=finding_id,
                mapped=bool(mapped),
                technique_ids_json=list(technique_ids_json or []),
                tactic_ids_json=list(tactic_ids_json or []),
                mappings_json=list(mappings_json or []),
                review_status=str(review_status),
                source=source,
                created_at=created_at,
            )
            for (
                finding_id,
                mapped,
                technique_ids_json,
                tactic_ids_json,
                mappings_json,
                review_status,
                source,
                created_at,
            ) in self.session.exec(
                select(*context_columns)
                .join(Finding, col(FindingAttackContext.finding_id) == col(Finding.id))
                .where(Finding.project_id == project_id)
                .order_by(col(FindingAttackContext.created_at).desc())
            ).all()
        ]
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
        filters = finding_page_filters(query)

        count_statement = (
            select(func.count())
            .select_from(Finding)
            .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
            .outerjoin(Component, col(Finding.component_id) == col(Component.id))
            .where(*filters)
        )
        order_by = finding_page_order_by(query)
        statement = (
            select(Finding)
            .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
            .outerjoin(Component, col(Finding.component_id) == col(Component.id))
            .options(
                selectinload(asset_relationship),
                selectinload(component_relationship),
            )
            .where(*filters)
            .order_by(*order_by)
            .offset(query.offset)
            .limit(query.limit)
        )
        count = self.session.exec(count_statement).one()
        findings = self.session.exec(statement).all()
        return list(findings), count


def _case_int(condition: Any) -> Any:
    return case((condition, 1), else_=0)


def _governance_label_expression(dimension: str) -> Any:
    if dimension == "owner":
        return func.coalesce(func.nullif(Asset.owner, ""), UNKNOWN_LABEL)
    if dimension == "service":
        return func.coalesce(func.nullif(Asset.business_service, ""), UNKNOWN_LABEL)
    if dimension == "asset":
        return func.coalesce(
            func.nullif(Asset.asset_key, ""),
            func.nullif(Asset.name, ""),
            UNKNOWN_LABEL,
        )
    if dimension == "environment":
        return func.coalesce(func.nullif(Asset.environment, ""), "unknown")
    raise ValueError(f"Unknown governance dimension: {dimension}")


def _governance_rollup_from_row(
    row: Any,
    *,
    dimension: str,
    top_cves: list[str],
) -> GovernanceRollupPublic:
    priority_start = 17
    status_start = priority_start + len(PRIORITY_LABELS)
    priority_counts = {
        label: _row_int(row, priority_start + index) for index, label in enumerate(PRIORITY_LABELS)
    }
    status_counts = {
        status: _row_int(row, status_start + index) for index, status in enumerate(STATUS_LABELS)
    }
    return GovernanceRollupPublic(
        dimension=dimension,
        label=str(row[0]),
        finding_count=_row_int(row, 1),
        open_count=_row_int(row, 2),
        accepted_count=_row_int(row, 3),
        fixed_count=_row_int(row, 4),
        suppressed_count=_row_int(row, 5),
        critical_count=_row_int(row, 6),
        high_count=_row_int(row, 7),
        kev_count=_row_int(row, 8),
        attack_mapped_count=_row_int(row, 9),
        suppressed_by_vex_count=_row_int(row, 10),
        under_investigation_count=_row_int(row, 11),
        waived_count=_row_int(row, 12),
        expired_waiver_count=_row_int(row, 13),
        review_due_waiver_count=_row_int(row, 14),
        risk_score_total=round(float(row[15] or 0.0), 3),
        risk_score_max=round(float(row[16]), 3) if row[16] is not None else None,
        highest_priority=_highest_priority(priority_counts),
        priority_counts=priority_counts,
        status_counts=status_counts,
        top_cves=top_cves,
    )


def _row_int(row: Any, index: int) -> int:
    return int(row[index] or 0)


def _highest_priority(priority_counts: dict[str, int]) -> str | None:
    for priority in PRIORITY_LABELS:
        if priority_counts.get(priority, 0):
            return priority
    return None
