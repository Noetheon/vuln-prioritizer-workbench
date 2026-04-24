"""Repository helpers for common Workbench database operations."""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypeVar

from sqlalchemy import Select, select
from sqlalchemy.orm import Session, selectinload

from vuln_prioritizer.db.models import (
    AnalysisRun,
    Asset,
    Component,
    EvidenceBundle,
    Finding,
    FindingOccurrence,
    Project,
    ProviderSnapshot,
    Report,
    Vulnerability,
    utc_now,
)

T = TypeVar("T")


class WorkbenchRepository:
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

    def create_provider_snapshot(
        self,
        *,
        content_hash: str | None = None,
        nvd_last_sync: str | None = None,
        epss_date: str | None = None,
        kev_catalog_version: str | None = None,
        metadata_json: dict | None = None,
    ) -> ProviderSnapshot:
        snapshot = ProviderSnapshot(
            content_hash=content_hash,
            nvd_last_sync=nvd_last_sync,
            epss_date=epss_date,
            kev_catalog_version=kev_catalog_version,
            metadata_json=metadata_json or {},
        )
        self.session.add(snapshot)
        self.session.flush()
        return snapshot

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

    def upsert_asset(
        self,
        *,
        project_id: str,
        asset_id: str,
        target_ref: str | None = None,
        owner: str | None = None,
        business_service: str | None = None,
        environment: str | None = None,
        exposure: str | None = None,
        criticality: str | None = None,
    ) -> Asset:
        asset = self.session.scalar(
            select(Asset).where(Asset.project_id == project_id, Asset.asset_id == asset_id)
        )
        if asset is None:
            asset = Asset(project_id=project_id, asset_id=asset_id)
            self.session.add(asset)
        asset.target_ref = target_ref
        asset.owner = owner
        asset.business_service = business_service
        asset.environment = environment
        asset.exposure = exposure
        asset.criticality = criticality
        self.session.flush()
        return asset

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
            )
        )
        return self.session.scalar(statement)

    def add_report(
        self,
        *,
        project_id: str,
        analysis_run_id: str,
        kind: str,
        format: str,
        path: str,
        sha256: str,
    ) -> Report:
        report = Report(
            project_id=project_id,
            analysis_run_id=analysis_run_id,
            kind=kind,
            format=format,
            path=path,
            sha256=sha256,
        )
        self.session.add(report)
        self.session.flush()
        return report

    def get_report(self, report_id: str) -> Report | None:
        return self.session.get(Report, report_id)

    def list_run_reports(self, analysis_run_id: str) -> list[Report]:
        statement = (
            select(Report)
            .where(Report.analysis_run_id == analysis_run_id)
            .order_by(Report.created_at.desc())
        )
        return list(self.session.scalars(statement))

    def add_evidence_bundle(
        self,
        *,
        project_id: str,
        analysis_run_id: str,
        path: str,
        sha256: str,
        manifest_json: dict[str, Any],
    ) -> EvidenceBundle:
        bundle = EvidenceBundle(
            project_id=project_id,
            analysis_run_id=analysis_run_id,
            path=path,
            sha256=sha256,
            manifest_json=manifest_json,
        )
        self.session.add(bundle)
        self.session.flush()
        return bundle

    def get_evidence_bundle(self, bundle_id: str) -> EvidenceBundle | None:
        return self.session.get(EvidenceBundle, bundle_id)

    def list_run_evidence_bundles(self, analysis_run_id: str) -> list[EvidenceBundle]:
        statement = (
            select(EvidenceBundle)
            .where(EvidenceBundle.analysis_run_id == analysis_run_id)
            .order_by(EvidenceBundle.created_at.desc())
        )
        return list(self.session.scalars(statement))

    def _required(self, model: type[T], primary_key: str) -> T:
        instance = self.session.get(model, primary_key)
        if instance is None:
            raise LookupError(f"{model.__name__} not found: {primary_key}")
        return instance
