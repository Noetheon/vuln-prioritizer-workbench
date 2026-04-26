"""Repository helpers for common Workbench database operations."""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypeVar

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session, selectinload

from vuln_prioritizer.db.models import (
    AnalysisRun,
    ApiToken,
    Asset,
    AttackMappingRecord,
    AuditEvent,
    Component,
    DetectionControl,
    DetectionControlAttachment,
    DetectionControlHistory,
    Finding,
    FindingAttackContext,
    FindingOccurrence,
    FindingStatusHistory,
    GitHubIssueExport,
    Project,
    ProjectArtifactRetention,
    ProjectConfigSnapshot,
    Vulnerability,
    WorkbenchJob,
    utc_now,
)
from vuln_prioritizer.db.repository_artifacts import ArtifactRepositoryMixin
from vuln_prioritizer.db.repository_assets import AssetWaiverRepositoryMixin
from vuln_prioritizer.db.repository_providers import ProviderSnapshotRepositoryMixin

T = TypeVar("T")

FINDING_SORT_FIELDS = {"operational", "priority", "epss", "cvss", "cve", "status"}


class WorkbenchRepository(
    ProviderSnapshotRepositoryMixin,
    AssetWaiverRepositoryMixin,
    ArtifactRepositoryMixin,
):
    """Small repository facade for the Workbench MVP persistence flow."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_project(self, name: str, description: str | None = None) -> Project:
        project = Project(name=name, description=description)
        self.session.add(project)
        self.session.flush()
        return project

    def get_project(self, project_id: str) -> Project | None:
        return self.session.get(Project, project_id)

    def get_project_by_name(self, name: str) -> Project | None:
        return self.session.scalar(select(Project).where(Project.name == name))

    def list_projects(self) -> list[Project]:
        statement = select(Project).order_by(Project.created_at, Project.name)
        return list(self.session.scalars(statement))

    def create_analysis_run(
        self,
        *,
        project_id: str,
        input_type: str,
        input_filename: str | None = None,
        input_path: str | None = None,
        status: str = "pending",
        provider_snapshot_id: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        attack_summary_json: dict[str, Any] | None = None,
        summary_json: dict | None = None,
    ) -> AnalysisRun:
        run = AnalysisRun(
            project_id=project_id,
            input_type=input_type,
            input_filename=input_filename,
            input_path=input_path,
            status=status,
            provider_snapshot_id=provider_snapshot_id,
            metadata_json=metadata_json or {},
            attack_summary_json=attack_summary_json or {},
            summary_json=summary_json or {},
        )
        self.session.add(run)
        self.session.flush()
        return run

    def finish_analysis_run(
        self,
        run_id: str,
        *,
        status: str = "completed",
        finished_at: datetime | None = None,
        error_message: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        attack_summary_json: dict[str, Any] | None = None,
        summary_json: dict | None = None,
    ) -> AnalysisRun:
        run = self._required(AnalysisRun, run_id)
        run.status = status
        run.finished_at = finished_at or utc_now()
        run.error_message = error_message
        if metadata_json is not None:
            run.metadata_json = metadata_json
        if attack_summary_json is not None:
            run.attack_summary_json = attack_summary_json
        if summary_json is not None:
            run.summary_json = summary_json
        self.session.flush()
        return run

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

    def upsert_attack_mapping(
        self,
        *,
        vulnerability_id: str,
        cve_id: str,
        attack_object_id: str,
        source: str,
        attack_object_name: str | None = None,
        mapping_type: str | None = None,
        source_version: str | None = None,
        source_hash: str | None = None,
        source_path: str | None = None,
        attack_version: str | None = None,
        domain: str | None = None,
        metadata_hash: str | None = None,
        metadata_path: str | None = None,
        confidence: float | None = None,
        review_status: str = "unreviewed",
        rationale: str | None = None,
        references_json: list[str] | None = None,
        mapping_json: dict | None = None,
    ) -> AttackMappingRecord:
        statement = select(AttackMappingRecord).where(
            AttackMappingRecord.source == source,
            AttackMappingRecord.cve_id == cve_id,
            AttackMappingRecord.attack_object_id == attack_object_id,
            AttackMappingRecord.mapping_type == mapping_type,
        )
        mapping = self.session.scalar(statement)
        if mapping is None:
            mapping = AttackMappingRecord(
                vulnerability_id=vulnerability_id,
                cve_id=cve_id,
                attack_object_id=attack_object_id,
                source=source,
            )
            self.session.add(mapping)
        mapping.vulnerability_id = vulnerability_id
        mapping.attack_object_name = attack_object_name
        mapping.mapping_type = mapping_type
        mapping.source_version = source_version
        mapping.source_hash = source_hash
        mapping.source_path = source_path
        mapping.attack_version = attack_version
        mapping.domain = domain
        mapping.metadata_hash = metadata_hash
        mapping.metadata_path = metadata_path
        mapping.confidence = confidence
        mapping.review_status = review_status
        mapping.rationale = rationale
        mapping.references_json = references_json or []
        mapping.mapping_json = mapping_json or {}
        self.session.flush()
        return mapping

    def create_or_update_finding_attack_context(
        self,
        *,
        finding_id: str,
        analysis_run_id: str,
        cve_id: str,
        mapped: bool,
        source: str,
        attack_relevance: str,
        threat_context_rank: int,
        source_version: str | None = None,
        source_hash: str | None = None,
        source_path: str | None = None,
        attack_version: str | None = None,
        domain: str | None = None,
        metadata_hash: str | None = None,
        metadata_path: str | None = None,
        rationale: str | None = None,
        review_status: str = "unreviewed",
        techniques_json: list[dict[str, Any]] | None = None,
        tactics_json: list[str] | None = None,
        mappings_json: list[dict[str, Any]] | None = None,
    ) -> FindingAttackContext:
        statement = select(FindingAttackContext).where(
            FindingAttackContext.finding_id == finding_id,
            FindingAttackContext.analysis_run_id == analysis_run_id,
        )
        context = self.session.scalar(statement)
        if context is None:
            context = FindingAttackContext(
                finding_id=finding_id,
                analysis_run_id=analysis_run_id,
                cve_id=cve_id,
            )
            self.session.add(context)
        context.cve_id = cve_id
        context.mapped = mapped
        context.source = source
        context.source_version = source_version
        context.source_hash = source_hash
        context.source_path = source_path
        context.attack_version = attack_version
        context.domain = domain
        context.metadata_hash = metadata_hash
        context.metadata_path = metadata_path
        context.attack_relevance = attack_relevance
        context.threat_context_rank = threat_context_rank
        context.rationale = rationale
        context.review_status = review_status
        context.techniques_json = techniques_json or []
        context.tactics_json = tactics_json or []
        context.mappings_json = mappings_json or []
        self.session.flush()
        return context

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

    def list_analysis_runs(self, project_id: str) -> list[AnalysisRun]:
        statement = (
            select(AnalysisRun)
            .where(AnalysisRun.project_id == project_id)
            .order_by(AnalysisRun.started_at.desc())
        )
        return list(self.session.scalars(statement))

    def get_analysis_run(self, run_id: str) -> AnalysisRun | None:
        return self.session.get(AnalysisRun, run_id)

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

    def list_finding_attack_contexts(self, finding_id: str) -> list[FindingAttackContext]:
        statement = (
            select(FindingAttackContext)
            .where(FindingAttackContext.finding_id == finding_id)
            .order_by(FindingAttackContext.threat_context_rank, FindingAttackContext.created_at)
        )
        return list(self.session.scalars(statement))

    def list_run_attack_contexts(self, analysis_run_id: str) -> list[FindingAttackContext]:
        statement = (
            select(FindingAttackContext)
            .where(FindingAttackContext.analysis_run_id == analysis_run_id)
            .order_by(FindingAttackContext.threat_context_rank, FindingAttackContext.cve_id)
        )
        return list(self.session.scalars(statement))

    def list_project_attack_contexts(self, project_id: str) -> list[FindingAttackContext]:
        statement = (
            select(FindingAttackContext)
            .join(Finding, Finding.id == FindingAttackContext.finding_id)
            .where(Finding.project_id == project_id)
            .order_by(FindingAttackContext.threat_context_rank, FindingAttackContext.cve_id)
        )
        return list(self.session.scalars(statement))

    def list_project_attack_review_contexts(
        self,
        project_id: str,
        *,
        review_status: str | None = None,
        source: str | None = None,
        mapped: bool | None = None,
        priority: str | None = None,
        technique_id: str | None = None,
        limit: int = 100,
    ) -> list[FindingAttackContext]:
        statement = (
            select(FindingAttackContext)
            .join(Finding, Finding.id == FindingAttackContext.finding_id)
            .where(Finding.project_id == project_id)
            .options(selectinload(FindingAttackContext.finding))
        )
        if review_status is not None:
            statement = statement.where(FindingAttackContext.review_status == review_status)
        if source is not None:
            statement = statement.where(FindingAttackContext.source == source)
        if mapped is not None:
            statement = statement.where(FindingAttackContext.mapped == mapped)
        if priority is not None:
            statement = statement.where(Finding.priority == priority)
        statement = statement.order_by(
            FindingAttackContext.review_status,
            FindingAttackContext.threat_context_rank,
            FindingAttackContext.cve_id,
        )
        contexts = list(self.session.scalars(statement))
        if technique_id is not None:
            contexts = [
                context
                for context in contexts
                if _attack_context_has_technique(context, technique_id)
            ]
        return contexts[:limit]

    def update_finding_attack_review_status(
        self,
        finding_id: str,
        *,
        review_status: str,
    ) -> list[FindingAttackContext]:
        contexts = self.list_finding_attack_contexts(finding_id)
        for context in contexts:
            context.review_status = review_status
        self.session.flush()
        return contexts

    def upsert_detection_control(
        self,
        *,
        project_id: str,
        name: str,
        technique_id: str,
        control_id: str | None = None,
        technique_name: str | None = None,
        source_type: str | None = None,
        coverage_level: str = "unknown",
        environment: str | None = None,
        owner: str | None = None,
        evidence_ref: str | None = None,
        evidence_refs_json: list[str] | None = None,
        review_status: str = "unreviewed",
        notes: str | None = None,
        last_verified_at: str | None = None,
        history_actor: str | None = None,
        history_reason: str | None = None,
    ) -> DetectionControl:
        statement = select(DetectionControl).where(
            DetectionControl.project_id == project_id,
            DetectionControl.technique_id == technique_id,
        )
        if control_id is not None:
            statement = statement.where(DetectionControl.control_id == control_id)
        else:
            statement = statement.where(DetectionControl.control_id.is_(None))
        control = self.session.scalar(statement)
        if control is None:
            control = DetectionControl(
                project_id=project_id,
                name=name,
                technique_id=technique_id,
                control_id=control_id,
            )
            self.session.add(control)
            previous: dict[str, Any] = {}
            event_type = "created"
        else:
            previous = _detection_control_history_snapshot(control)
            event_type = "updated"
        control.name = name
        control.technique_name = technique_name
        control.source_type = source_type
        control.coverage_level = coverage_level
        control.environment = environment
        control.owner = owner
        control.evidence_ref = evidence_ref
        control.evidence_refs_json = evidence_refs_json or []
        control.review_status = review_status
        control.notes = notes
        control.last_verified_at = last_verified_at
        self.session.flush()
        current = _detection_control_history_snapshot(control)
        if previous != current:
            self.add_detection_control_history(
                control=control,
                event_type=event_type,
                actor=history_actor,
                reason=history_reason,
                previous_json=previous,
                current_json=current,
            )
        return control

    def update_detection_control(
        self,
        control: DetectionControl,
        *,
        name: str,
        technique_id: str,
        control_id: str | None = None,
        technique_name: str | None = None,
        source_type: str | None = None,
        coverage_level: str = "unknown",
        environment: str | None = None,
        owner: str | None = None,
        evidence_ref: str | None = None,
        evidence_refs_json: list[str] | None = None,
        review_status: str = "unreviewed",
        notes: str | None = None,
        last_verified_at: str | None = None,
        history_actor: str | None = None,
        history_reason: str | None = None,
    ) -> DetectionControl:
        existing = self.session.scalar(
            select(DetectionControl).where(
                DetectionControl.project_id == control.project_id,
                DetectionControl.technique_id == technique_id,
                DetectionControl.control_id == control_id,
                DetectionControl.id != control.id,
            )
        )
        if existing is not None:
            raise ValueError("Detection control identity already exists.")
        previous = _detection_control_history_snapshot(control)
        control.name = name
        control.technique_id = technique_id
        control.control_id = control_id
        control.technique_name = technique_name
        control.source_type = source_type
        control.coverage_level = coverage_level
        control.environment = environment
        control.owner = owner
        control.evidence_ref = evidence_ref
        control.evidence_refs_json = evidence_refs_json or []
        control.review_status = review_status
        control.notes = notes
        control.last_verified_at = last_verified_at
        self.session.flush()
        current = _detection_control_history_snapshot(control)
        if previous != current:
            self.add_detection_control_history(
                control=control,
                event_type="updated",
                actor=history_actor,
                reason=history_reason,
                previous_json=previous,
                current_json=current,
            )
        return control

    def list_project_detection_controls(self, project_id: str) -> list[DetectionControl]:
        statement = (
            select(DetectionControl)
            .where(DetectionControl.project_id == project_id)
            .options(
                selectinload(DetectionControl.history),
                selectinload(DetectionControl.attachments),
            )
            .order_by(DetectionControl.technique_id, DetectionControl.name)
        )
        return list(self.session.scalars(statement))

    def list_detection_controls_for_technique(
        self, project_id: str, technique_id: str
    ) -> list[DetectionControl]:
        statement = (
            select(DetectionControl)
            .where(
                DetectionControl.project_id == project_id,
                DetectionControl.technique_id == technique_id,
            )
            .options(
                selectinload(DetectionControl.history),
                selectinload(DetectionControl.attachments),
            )
            .order_by(DetectionControl.coverage_level, DetectionControl.name)
        )
        return list(self.session.scalars(statement))

    def get_detection_control(self, control_id: str) -> DetectionControl | None:
        statement = (
            select(DetectionControl)
            .where(DetectionControl.id == control_id)
            .options(
                selectinload(DetectionControl.history),
                selectinload(DetectionControl.attachments),
            )
        )
        return self.session.scalar(statement)

    def delete_detection_control(self, control: DetectionControl) -> None:
        self.session.delete(control)
        self.session.flush()

    def add_detection_control_history(
        self,
        *,
        control: DetectionControl,
        event_type: str,
        actor: str | None = None,
        reason: str | None = None,
        previous_json: dict[str, Any] | None = None,
        current_json: dict[str, Any] | None = None,
    ) -> DetectionControlHistory:
        history = DetectionControlHistory(
            project_id=control.project_id,
            control_id=control.id,
            event_type=event_type,
            actor=actor,
            reason=reason,
            previous_json=previous_json or {},
            current_json=current_json or _detection_control_history_snapshot(control),
        )
        self.session.add(history)
        self.session.flush()
        if "history" in control.__dict__:
            control.history.append(history)
        return history

    def list_detection_control_history(self, control_id: str) -> list[DetectionControlHistory]:
        statement = (
            select(DetectionControlHistory)
            .where(DetectionControlHistory.control_id == control_id)
            .order_by(DetectionControlHistory.created_at.desc())
        )
        return list(self.session.scalars(statement))

    def add_detection_control_attachment(
        self,
        *,
        control_id: str,
        project_id: str,
        filename: str,
        path: str,
        sha256: str,
        size_bytes: int,
        content_type: str | None = None,
    ) -> DetectionControlAttachment:
        attachment = DetectionControlAttachment(
            control_id=control_id,
            project_id=project_id,
            filename=filename,
            content_type=content_type,
            path=path,
            sha256=sha256,
            size_bytes=size_bytes,
        )
        self.session.add(attachment)
        self.session.flush()
        return attachment

    def get_detection_control_attachment(
        self, attachment_id: str
    ) -> DetectionControlAttachment | None:
        return self.session.get(DetectionControlAttachment, attachment_id)

    def list_detection_control_attachments(
        self, control_id: str
    ) -> list[DetectionControlAttachment]:
        statement = (
            select(DetectionControlAttachment)
            .where(DetectionControlAttachment.control_id == control_id)
            .order_by(DetectionControlAttachment.created_at.desc())
        )
        return list(self.session.scalars(statement))

    def delete_detection_control_attachment(self, attachment: DetectionControlAttachment) -> None:
        self.session.delete(attachment)
        self.session.flush()

    def create_api_token(self, *, name: str, token_hash: str) -> ApiToken:
        token = ApiToken(name=name, token_hash=token_hash)
        self.session.add(token)
        self.session.flush()
        return token

    def get_active_api_token_by_hash(self, token_hash: str) -> ApiToken | None:
        return self.session.scalar(
            select(ApiToken).where(ApiToken.token_hash == token_hash, ApiToken.revoked_at.is_(None))
        )

    def has_active_api_tokens(self) -> bool:
        return (
            self.session.scalar(select(ApiToken.id).where(ApiToken.revoked_at.is_(None)).limit(1))
            is not None
        )

    def mark_api_token_used(self, token: ApiToken) -> None:
        token.last_used_at = utc_now()
        self.session.flush()

    def list_api_tokens(self) -> list[ApiToken]:
        statement = select(ApiToken).order_by(ApiToken.created_at.desc(), ApiToken.name)
        return list(self.session.scalars(statement))

    def get_api_token(self, token_id: str) -> ApiToken | None:
        return self.session.get(ApiToken, token_id)

    def revoke_api_token(self, token: ApiToken) -> ApiToken:
        token.revoked_at = utc_now()
        self.session.flush()
        return token

    def github_issue_export_exists(self, project_id: str, duplicate_key: str) -> bool:
        statement = select(GitHubIssueExport.id).where(
            GitHubIssueExport.project_id == project_id,
            GitHubIssueExport.duplicate_key == duplicate_key,
        )
        return self.session.scalar(statement) is not None

    def create_github_issue_export(
        self,
        *,
        project_id: str,
        finding_id: str | None,
        duplicate_key: str,
        title: str,
        html_url: str | None,
        issue_number: int | None,
    ) -> GitHubIssueExport:
        export = GitHubIssueExport(
            project_id=project_id,
            finding_id=finding_id,
            duplicate_key=duplicate_key,
            title=title,
            html_url=html_url,
            issue_number=issue_number,
        )
        self.session.add(export)
        self.session.flush()
        return export

    def save_project_config_snapshot(
        self,
        *,
        project_id: str,
        source: str,
        config_json: dict[str, Any],
    ) -> ProjectConfigSnapshot:
        snapshot = ProjectConfigSnapshot(
            project_id=project_id,
            source=source,
            config_json=config_json,
        )
        self.session.add(snapshot)
        self.session.flush()
        return snapshot

    def get_latest_project_config_snapshot(self, project_id: str) -> ProjectConfigSnapshot | None:
        statement = (
            select(ProjectConfigSnapshot)
            .where(ProjectConfigSnapshot.project_id == project_id)
            .order_by(ProjectConfigSnapshot.created_at.desc())
            .limit(1)
        )
        return self.session.scalar(statement)

    def get_project_config_snapshot(self, snapshot_id: str) -> ProjectConfigSnapshot | None:
        return self.session.get(ProjectConfigSnapshot, snapshot_id)

    def list_project_config_snapshots(
        self,
        project_id: str,
        *,
        limit: int = 50,
    ) -> list[ProjectConfigSnapshot]:
        statement = (
            select(ProjectConfigSnapshot)
            .where(ProjectConfigSnapshot.project_id == project_id)
            .order_by(ProjectConfigSnapshot.created_at.desc())
            .limit(limit)
        )
        return list(self.session.scalars(statement))

    def create_audit_event(
        self,
        *,
        event_type: str,
        project_id: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        actor: str | None = None,
        message: str | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            project_id=project_id,
            event_type=event_type,
            target_type=target_type,
            target_id=target_id,
            actor=actor,
            message=message,
            metadata_json=metadata_json or {},
        )
        self.session.add(event)
        self.session.flush()
        return event

    def list_project_audit_events(self, project_id: str, *, limit: int = 100) -> list[AuditEvent]:
        statement = (
            select(AuditEvent)
            .where(AuditEvent.project_id == project_id)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
        )
        return list(self.session.scalars(statement))

    def enqueue_workbench_job(
        self,
        *,
        kind: str,
        project_id: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        payload_json: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        priority: int = 100,
        max_attempts: int = 3,
    ) -> WorkbenchJob:
        if idempotency_key:
            existing = self.session.scalar(
                select(WorkbenchJob).where(WorkbenchJob.idempotency_key == idempotency_key)
            )
            if existing is not None:
                return existing
        job = WorkbenchJob(
            kind=kind,
            project_id=project_id,
            target_type=target_type,
            target_id=target_id,
            payload_json=payload_json or {},
            idempotency_key=idempotency_key,
            priority=priority,
            max_attempts=max_attempts,
            logs_json=[],
            result_json={},
        )
        self.session.add(job)
        self.session.flush()
        return job

    def get_workbench_job(self, job_id: str) -> WorkbenchJob | None:
        return self.session.get(WorkbenchJob, job_id)

    def list_workbench_jobs(
        self,
        *,
        project_id: str | None = None,
        status: str | None = None,
        kind: str | None = None,
        limit: int = 100,
    ) -> list[WorkbenchJob]:
        statement = select(WorkbenchJob)
        if project_id is not None:
            statement = statement.where(WorkbenchJob.project_id == project_id)
        if status is not None:
            statement = statement.where(WorkbenchJob.status == status)
        if kind is not None:
            statement = statement.where(WorkbenchJob.kind == kind)
        statement = statement.order_by(WorkbenchJob.created_at.desc()).limit(limit)
        return list(self.session.scalars(statement))

    def start_workbench_job(self, job: WorkbenchJob, *, worker_id: str = "sync") -> WorkbenchJob:
        job.status = "running"
        job.attempts += 1
        job.started_at = utc_now()
        job.heartbeat_at = job.started_at
        job.lease_owner = worker_id
        job.error_message = None
        job.logs_json = [*_job_logs(job), _job_log_entry("started", progress=job.progress)]
        self.session.flush()
        return job

    def update_workbench_job_progress(
        self,
        job: WorkbenchJob,
        *,
        progress: int,
        message: str | None = None,
    ) -> WorkbenchJob:
        job.progress = max(0, min(100, progress))
        job.heartbeat_at = utc_now()
        logs = _job_logs(job)
        if message:
            logs.append(_job_log_entry(message, progress=job.progress))
        job.logs_json = logs
        self.session.flush()
        return job

    def complete_workbench_job(
        self,
        job: WorkbenchJob,
        *,
        result_json: dict[str, Any] | None = None,
        message: str = "completed",
    ) -> WorkbenchJob:
        job.status = "completed"
        job.progress = 100
        job.result_json = result_json or {}
        job.finished_at = utc_now()
        job.heartbeat_at = job.finished_at
        job.lease_owner = None
        job.lease_expires_at = None
        job.logs_json = [*_job_logs(job), _job_log_entry(message, progress=100)]
        self.session.flush()
        return job

    def fail_workbench_job(
        self,
        job: WorkbenchJob,
        *,
        error_message: str,
        retryable: bool = True,
    ) -> WorkbenchJob:
        job.status = "queued" if retryable and job.attempts < job.max_attempts else "failed"
        job.error_message = error_message
        job.finished_at = utc_now() if job.status == "failed" else None
        job.heartbeat_at = utc_now()
        job.lease_owner = None
        job.lease_expires_at = None
        job.logs_json = [*_job_logs(job), _job_log_entry(error_message, progress=job.progress)]
        self.session.flush()
        return job

    def retry_workbench_job(self, job: WorkbenchJob) -> WorkbenchJob:
        if job.status not in {"failed", "completed"}:
            return job
        job.status = "queued"
        job.progress = 0
        job.error_message = None
        job.finished_at = None
        job.queued_at = utc_now()
        job.logs_json = [*_job_logs(job), _job_log_entry("retry queued", progress=0)]
        self.session.flush()
        return job

    def get_project_artifact_retention(self, project_id: str) -> ProjectArtifactRetention | None:
        return self.session.scalar(
            select(ProjectArtifactRetention).where(
                ProjectArtifactRetention.project_id == project_id
            )
        )

    def upsert_project_artifact_retention(
        self,
        *,
        project_id: str,
        report_retention_days: int | None = None,
        evidence_retention_days: int | None = None,
        max_disk_usage_mb: int | None = None,
    ) -> ProjectArtifactRetention:
        retention = self.get_project_artifact_retention(project_id)
        if retention is None:
            retention = ProjectArtifactRetention(project_id=project_id)
            self.session.add(retention)
        retention.report_retention_days = report_retention_days
        retention.evidence_retention_days = evidence_retention_days
        retention.max_disk_usage_mb = max_disk_usage_mb
        self.session.flush()
        return retention

    def list_audit_events(
        self,
        *,
        project_id: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        statement = select(AuditEvent)
        if project_id is not None:
            statement = statement.where(AuditEvent.project_id == project_id)
        statement = statement.order_by(AuditEvent.created_at.desc()).limit(limit)
        return list(self.session.scalars(statement))

    def _required(self, model: type[T], primary_key: str) -> T:
        instance = self.session.get(model, primary_key)
        if instance is None:
            raise LookupError(f"{model.__name__} not found: {primary_key}")
        return instance


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


def _detection_control_history_snapshot(control: DetectionControl) -> dict[str, Any]:
    return {
        "control_id": control.control_id,
        "name": control.name,
        "technique_id": control.technique_id,
        "technique_name": control.technique_name,
        "source_type": control.source_type,
        "coverage_level": control.coverage_level,
        "environment": control.environment,
        "owner": control.owner,
        "evidence_ref": control.evidence_ref,
        "evidence_refs": list(control.evidence_refs_json or []),
        "review_status": control.review_status,
        "notes": control.notes,
        "last_verified_at": control.last_verified_at,
    }


def _attack_context_has_technique(context: FindingAttackContext, technique_id: str) -> bool:
    for technique in context.techniques_json or []:
        if isinstance(technique, dict) and technique.get("attack_object_id") == technique_id:
            return True
        if isinstance(technique, dict) and technique.get("technique_id") == technique_id:
            return True
    return False


def _job_logs(job: WorkbenchJob) -> list[dict[str, Any]]:
    return list(job.logs_json) if isinstance(job.logs_json, list) else []


def _job_log_entry(message: str, *, progress: int) -> dict[str, Any]:
    return {"created_at": utc_now().isoformat(), "message": message, "progress": progress}
