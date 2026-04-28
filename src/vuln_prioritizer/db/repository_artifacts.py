"""Artifact persistence helpers for Workbench repositories."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_prioritizer.db.models import EvidenceBundle, Report


class ArtifactRepositoryMixin:
    """Report and evidence-bundle persistence methods."""

    session: Session

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

    def list_project_reports(self, project_id: str) -> list[Report]:
        statement = (
            select(Report).where(Report.project_id == project_id).order_by(Report.created_at.desc())
        )
        return list(self.session.scalars(statement))

    def list_reports(self) -> list[Report]:
        statement = select(Report).order_by(Report.created_at.desc())
        return list(self.session.scalars(statement))

    def delete_report(self, report: Report) -> None:
        self.session.delete(report)
        self.session.flush()

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

    def list_project_evidence_bundles(self, project_id: str) -> list[EvidenceBundle]:
        statement = (
            select(EvidenceBundle)
            .where(EvidenceBundle.project_id == project_id)
            .order_by(EvidenceBundle.created_at.desc())
        )
        return list(self.session.scalars(statement))

    def list_evidence_bundles(self) -> list[EvidenceBundle]:
        statement = select(EvidenceBundle).order_by(EvidenceBundle.created_at.desc())
        return list(self.session.scalars(statement))

    def delete_evidence_bundle(self, bundle: EvidenceBundle) -> None:
        self.session.delete(bundle)
        self.session.flush()
