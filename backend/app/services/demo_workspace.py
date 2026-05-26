"""Local demo workspace seeding for the Workbench."""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlmodel import Session, col, func, select

from app.core.config import Settings
from app.core.local_actor import LocalWorkbenchActor
from app.models import (
    AnalysisRun,
    Asset,
    Finding,
    Project,
    Report,
    Waiver,
    WaiverCreate,
)
from app.models.base import get_datetime_utc
from app.repositories import RunRepository, WaiverRepository
from app.repositories.waivers import waiver_lifecycle_status
from app.services.artifact_cleanup import cleanup_project_artifacts
from app.services.import_execution import (
    ImportUploadContent,
    ProjectImportUploadRequest,
    execute_project_import_upload,
)
from app.services.report_artifacts import (
    ReportArtifactChecksumError,
    ReportArtifactNotFoundError,
    validated_report_path,
)
from app.services.reports import ReportService

DEMO_PROJECT_ID = uuid.UUID("00000000-0000-4000-8000-00000000d001")
DEMO_PROJECT_NAME = "Online Shop Demo Workspace"
DEMO_WORKSPACE_MARKER = "vpw-demo-workspace-v1"
DEMO_PROVIDER_SNAPSHOT = "demo_provider_snapshot.json"
EXPECTED_REPORT_FORMATS = (
    "markdown",
    "html",
    "json",
    "csv",
    "attack-navigator",
    "sarif",
    "zip",
)
EXPECTED_REPORT_FILENAMES = frozenset(
    {
        "technical-report.md",
        "executive-report.html",
        "analysis-result.v1.json",
        "findings.csv",
        "attack-navigator-layer.json",
        "results.sarif",
        "evidence-bundle.zip",
    }
)
EXPECTED_FINDING_COUNT = 24
EXPECTED_ASSET_COUNT = 21
EXPECTED_WAIVER_COUNT = 4
EXPECTED_WAIVER_STATUS_COUNTS = {
    "active": 3,
    "review_due": 1,
    "expired": 0,
}

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DATA_DIR = _REPO_ROOT / "data"
_DEMO_OCCURRENCES_FILENAME = "demo_workspace_occurrences.csv"
_DEMO_OPENVEX_FILENAME = "demo_workspace_openvex.json"
_ATTACK_MAPPING_FILENAME = "local_curated_demo_mappings.yml"


@dataclass(frozen=True, slots=True)
class DemoWorkspaceSnapshot:
    """Data representation and logic for Demo Workspace Snapshot."""

    project: Project | None
    latest_run: AnalysisRun | None
    reports: list[Report]
    finding_count: int
    asset_count: int
    waiver_count: int
    report_count: int
    waiver_status_counts: dict[str, int]

    @property
    def seeded(self) -> bool:
        """Seeded method for DemoWorkspaceSnapshot."""
        return self.project is not None and self.latest_run is not None and self.finding_count > 0

    @property
    def canonical(self) -> bool:
        """Canonical method for DemoWorkspaceSnapshot."""
        if not self.seeded or self.project is None:
            return False
        return (
            self.project.name == DEMO_PROJECT_NAME
            and DEMO_WORKSPACE_MARKER in (self.project.description or "")
            and self.finding_count == EXPECTED_FINDING_COUNT
            and self.asset_count == EXPECTED_ASSET_COUNT
            and self.waiver_count == EXPECTED_WAIVER_COUNT
            and self.report_count == len(EXPECTED_REPORT_FORMATS)
            and {report.filename for report in self.reports} == EXPECTED_REPORT_FILENAMES
            and {
                status: self.waiver_status_counts.get(status, 0)
                for status in EXPECTED_WAIVER_STATUS_COUNTS
            }
            == EXPECTED_WAIVER_STATUS_COUNTS
        )


def demo_workspace_enabled(settings: Settings) -> bool:
    """Return whether the local demo workspace mutation endpoints may run."""
    return settings.ENVIRONMENT == "local" and settings.DEMO_WORKSPACE_ENABLED


def read_demo_workspace_snapshot(session: Session) -> DemoWorkspaceSnapshot:
    """Read the deterministic demo workspace if it exists."""
    project = session.get(Project, DEMO_PROJECT_ID)
    if project is None:
        return DemoWorkspaceSnapshot(
            project=None,
            latest_run=None,
            reports=[],
            finding_count=0,
            asset_count=0,
            waiver_count=0,
            report_count=0,
            waiver_status_counts={},
        )

    latest_run = RunRepository(session).get_latest_analysis_run(project.id)
    reports = ReportServiceSnapshot(session).latest_run_reports(latest_run)
    return DemoWorkspaceSnapshot(
        project=project,
        latest_run=latest_run,
        reports=reports,
        finding_count=_count_for_project(session, "finding", project.id),
        asset_count=_count_for_project(session, "asset", project.id),
        waiver_count=_count_for_project(session, "waiver", project.id),
        report_count=_count_for_project(session, "report", project.id),
        waiver_status_counts=_waiver_status_counts(session, project.id),
    )


async def seed_demo_workspace(
    *,
    session: Session,
    settings: Settings,
    local_actor: LocalWorkbenchActor,
    reset: bool = False,
) -> DemoWorkspaceSnapshot:
    """Create the deterministic local demo workspace using normal import/report services."""
    snapshot = read_demo_workspace_snapshot(session)
    if snapshot.canonical and _report_artifacts_available(snapshot, settings) and not reset:
        return snapshot

    if snapshot.project is not None:
        delete_demo_workspace(session=session, settings=settings)
        session.commit()

    project = _create_demo_project(session)
    session.commit()
    session.refresh(project)

    await _run_seed_imports(session=session, settings=settings, local_actor=local_actor)
    latest_run = RunRepository(session).get_latest_analysis_run(DEMO_PROJECT_ID)
    if latest_run is None:
        raise RuntimeError("Demo workspace import did not create an analysis run.")
    seeded_project = session.get(Project, DEMO_PROJECT_ID)
    if seeded_project is None:
        raise RuntimeError("Demo workspace project disappeared during seed.")

    _create_demo_waivers(session, project_id=seeded_project.id)
    _create_demo_reports(
        session=session,
        settings=settings,
        project=seeded_project,
        run=latest_run,
    )
    session.commit()
    return read_demo_workspace_snapshot(session)


def delete_demo_workspace(*, session: Session, settings: Settings) -> None:
    """Remove the deterministic demo workspace and owned artifacts without committing."""
    project = session.get(Project, DEMO_PROJECT_ID)
    if project is None:
        return
    cleanup_project_artifacts(settings=settings, project_id=project.id)
    for report in session.exec(select(Report).where(Report.project_id == project.id)):
        session.delete(report)
    session.delete(project)
    session.flush()


class ReportServiceSnapshot:
    """Small report lookup adapter kept local to the demo service."""

    def __init__(self, session: Session) -> None:
        """Initialize a new instance of ReportServiceSnapshot."""
        self.session = session

    def latest_run_reports(self, latest_run: AnalysisRun | None) -> list[Report]:
        """Latest run reports method for ReportServiceSnapshot."""
        if latest_run is None:
            return []
        statement = (
            select(Report)
            .where(Report.analysis_run_id == latest_run.id)
            .order_by(col(Report.created_at).desc(), col(Report.id).desc())
        )
        return list(self.session.exec(statement).all())


def _report_artifacts_available(snapshot: DemoWorkspaceSnapshot, settings: Settings) -> bool:
    """Report artifacts available function."""
    if not snapshot.reports:
        return False
    try:
        for report in snapshot.reports:
            validated_report_path(report, settings)
    except (ReportArtifactChecksumError, ReportArtifactNotFoundError):
        return False
    return True


def _create_demo_project(session: Session) -> Project:
    """Create demo project function."""
    project = Project(
        id=DEMO_PROJECT_ID,
        name=DEMO_PROJECT_NAME,
        description=(
            "Deterministic local Online Shop risk operations review for exploring "
            "dashboard, findings, assets, waivers, provider replay, reports, "
            "and evidence bundles. "
            f"Managed marker: {DEMO_WORKSPACE_MARKER}."
        ),
    )
    session.add(project)
    session.flush()
    return project


async def _run_seed_imports(
    *,
    session: Session,
    settings: Settings,
    local_actor: LocalWorkbenchActor,
) -> None:
    """Run seed imports function."""
    demo_data_dir = _demo_data_dir(settings)
    await execute_project_import_upload(
        project_id=DEMO_PROJECT_ID,
        session=session,
        local_actor=local_actor,
        settings=settings,
        upload=ProjectImportUploadRequest(
            input_type="generic-occurrence-csv",
            file=_upload_content(
                demo_data_dir / "input_fixtures" / _DEMO_OCCURRENCES_FILENAME,
                content_type="text/csv",
            ),
            vex_file=_upload_content(
                demo_data_dir / "input_fixtures" / _DEMO_OPENVEX_FILENAME,
                content_type="application/json",
            ),
            provider_snapshot_file=DEMO_PROVIDER_SNAPSHOT,
            locked_provider_data=True,
            attack_source="local-curated",
            attack_mapping_file=_ATTACK_MAPPING_FILENAME,
        ),
        execution_mode="request",
    )


def _demo_data_dir(settings: Settings) -> Path:
    """Demo data dir function."""
    attack_artifact_dir = settings.attack_artifact_dir_path
    candidates = []
    if attack_artifact_dir.name == "attack":
        candidates.append(attack_artifact_dir.parent)
    candidates.append(_DATA_DIR)

    for candidate in candidates:
        input_fixtures = candidate / "input_fixtures"
        if (input_fixtures / _DEMO_OCCURRENCES_FILENAME).is_file() and (
            input_fixtures / _DEMO_OPENVEX_FILENAME
        ).is_file():
            return candidate
    return _DATA_DIR


def _create_demo_waivers(session: Session, *, project_id: uuid.UUID) -> None:
    """Create demo waivers function."""
    waiver_repo = WaiverRepository(session)
    for waiver in _demo_waivers():
        waiver_repo.create_project_waiver(project_id=project_id, waiver_in=waiver)
    waiver_repo.sync_project_waivers(project_id)


def _demo_waivers() -> tuple[WaiverCreate, ...]:
    """Demo waivers function."""
    today = get_datetime_utc().date()
    return (
        WaiverCreate(
            cve_id="CVE-2020-1472",
            asset_key="id-dc-02",
            owner="identity-risk",
            reason=(
                "Legacy domain controller isolated behind compensating controls "
                "until the approved maintenance window."
            ),
            expires_at=today + timedelta(days=90),
            review_at=today + timedelta(days=30),
            approval_ref="DEMO-RISK-1001",
        ),
        WaiverCreate(
            cve_id="CVE-2023-44487",
            asset_key="edge-cache-02",
            owner="edge-platform",
            reason=(
                "Traffic is rate-limited at the upstream CDN while the edge "
                "runtime is rolled through blue/green replacement."
            ),
            expires_at=today + timedelta(days=10),
            review_at=today,
            approval_ref="DEMO-RISK-1002",
        ),
        WaiverCreate(
            cve_id="CVE-2024-3094",
            asset_key="analytics-notebook-01",
            owner="data-platform",
            reason=(
                "Developer notebook is isolated from production paths and queued "
                "for image rebuild after active experiments finish."
            ),
            expires_at=today + timedelta(days=60),
            review_at=today + timedelta(days=21),
            approval_ref="DEMO-RISK-1003",
        ),
        WaiverCreate(
            cve_id="CVE-2024-3094",
            asset_key="build-host-1",
            owner="platform-security",
            reason=(
                "Build host is quarantined to signed internal source mirrors "
                "while the base image rebuild completes."
            ),
            expires_at=today + timedelta(days=45),
            review_at=today + timedelta(days=14),
            approval_ref="DEMO-RISK-1004",
        ),
    )


def _create_demo_reports(
    *,
    session: Session,
    settings: Settings,
    project: Project,
    run: AnalysisRun,
) -> None:
    """Create demo reports function."""
    report_service = ReportService(session, settings)
    report_service.create_markdown_report(run=run, project=project)
    report_service.create_html_report(run=run, project=project)
    report_service.create_analysis_json_export(run=run, project=project)
    report_service.create_findings_csv_export(run=run, project=project)
    report_service.create_attack_navigator_layer(run=run, project=project)
    report_service.create_sarif_report(run=run, project=project)
    report_service.create_evidence_bundle(run=run, project=project)


def _upload_content(path: Path, *, content_type: str) -> ImportUploadContent:
    """Upload content function."""
    return ImportUploadContent(
        filename=path.name,
        content_type=content_type,
        content=path.read_bytes(),
    )


def _count_for_project(session: Session, table: str, project_id: uuid.UUID) -> int:
    """Count for project function."""
    model_by_table: dict[str, Any] = {
        "asset": Asset,
        "finding": Finding,
        "report": Report,
        "waiver": Waiver,
    }
    model = model_by_table[table]
    statement = select(func.count()).select_from(model).where(model.project_id == project_id)
    return int(session.exec(statement).one())


def _waiver_status_counts(session: Session, project_id: uuid.UUID) -> dict[str, int]:
    """Waiver status counts function."""
    waivers = session.exec(select(Waiver).where(Waiver.project_id == project_id)).all()
    counts = Counter(waiver_lifecycle_status(waiver)[0] for waiver in waivers)
    return {status: counts.get(status, 0) for status in EXPECTED_WAIVER_STATUS_COUNTS}
