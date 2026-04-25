"""Repository helpers for common Workbench database operations."""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypeVar

from sqlalchemy import Select, select
from sqlalchemy.orm import Session, selectinload

from vuln_prioritizer.db.models import (
    AnalysisRun,
    ApiToken,
    AttackMappingRecord,
    Component,
    DetectionControl,
    Finding,
    FindingAttackContext,
    FindingOccurrence,
    GitHubIssueExport,
    Project,
    ProjectConfigSnapshot,
    Vulnerability,
    utc_now,
)
from vuln_prioritizer.db.repository_artifacts import ArtifactRepositoryMixin
from vuln_prioritizer.db.repository_assets import AssetWaiverRepositoryMixin
from vuln_prioritizer.db.repository_providers import ProviderSnapshotRepositoryMixin

T = TypeVar("T")


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
            )
            .order_by(Finding.operational_rank, Vulnerability.cve_id)
            .join(Finding.vulnerability)
        )
        return list(self.session.scalars(statement))

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
            )
        )
        return self.session.scalar(statement)

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
        notes: str | None = None,
        last_verified_at: str | None = None,
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
        control.name = name
        control.technique_name = technique_name
        control.source_type = source_type
        control.coverage_level = coverage_level
        control.environment = environment
        control.owner = owner
        control.evidence_ref = evidence_ref
        control.notes = notes
        control.last_verified_at = last_verified_at
        self.session.flush()
        return control

    def list_project_detection_controls(self, project_id: str) -> list[DetectionControl]:
        statement = (
            select(DetectionControl)
            .where(DetectionControl.project_id == project_id)
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
            .order_by(DetectionControl.coverage_level, DetectionControl.name)
        )
        return list(self.session.scalars(statement))

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

    def _required(self, model: type[T], primary_key: str) -> T:
        instance = self.session.get(model, primary_key)
        if instance is None:
            raise LookupError(f"{model.__name__} not found: {primary_key}")
        return instance
