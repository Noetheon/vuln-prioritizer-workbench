from __future__ import annotations

import importlib
import inspect
import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import UniqueConstraint, create_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel

from app.core.config import Settings
from app.domain.engine.models import (
    KevData,
    ProviderSnapshotItem,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from app.domain.engine.provider_snapshot import generate_provider_snapshot_json
from app.importers.generic_occurrence_csv import GenericOccurrenceCsvImporter
from app.services import AnalysisService
from app.services.import_execution_context import _parsed_input_from_workbench_occurrences

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture()
def app_models() -> Any:
    models = importlib.import_module("app.models")
    models.import_table_models()
    return models


@pytest.fixture()
def repository_classes() -> Any:
    return importlib.import_module("app.repositories")


@pytest.fixture()
def session(app_models: Any) -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def test_project_routes_delegate_domain_persistence_to_repository() -> None:
    route_module = importlib.import_module("app.api.routes.projects")
    source = inspect.getsource(route_module)

    assert "ProjectRepository" in source
    assert "select(" not in source
    assert "func.count" not in source
    assert "session.add" not in source


def test_analysis_service_uses_demo_snapshot_only_when_enabled(session: Session) -> None:
    disabled = AnalysisService(
        session,
        Settings(PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data")),
    )
    enabled = AnalysisService(
        session,
        Settings(
            PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data"),
            DEMO_PROVIDER_SNAPSHOT_ENABLED=True,
        ),
    )

    assert disabled.default_provider_snapshot_file() is None
    assert enabled.default_provider_snapshot_file() == PROJECT_ROOT / "data" / (
        "demo_provider_snapshot.json"
    )


def test_analysis_service_locked_provider_data_uses_explicit_flag() -> None:
    source = inspect.getsource(AnalysisService.analyze_import)

    assert "use_locked_snapshot = locked_provider_data" in source
    assert "or snapshot_path is not None" not in source


def test_analysis_service_persists_selected_snapshot_sources(
    app_models: Any,
    session: Session,
    tmp_path: Path,
) -> None:
    snapshot_file = tmp_path / "provider-snapshot.json"
    report = ProviderSnapshotReport(
        metadata=ProviderSnapshotMetadata(
            generated_at="2026-05-01T12:00:00Z",
            selected_sources=["kev"],
            requested_cves=1,
        ),
        items=[
            ProviderSnapshotItem(
                cve_id="CVE-2026-0001",
                kev=KevData(cve_id="CVE-2026-0001", in_kev=True),
            )
        ],
        warnings=[],
    )
    snapshot_file.write_text(generate_provider_snapshot_json(report), encoding="utf-8")

    snapshot_id = AnalysisService(session, Settings()).persist_provider_snapshot(
        snapshot_file,
        locked_provider_data=False,
    )
    session.commit()

    assert snapshot_id is not None
    snapshot = session.get(app_models.ProviderSnapshot, snapshot_id)
    assert snapshot is not None
    assert snapshot.source_metadata_json["selected_sources"] == ["kev"]


def test_finding_identity_uses_project_dedup_key_unique_constraint(app_models: Any) -> None:
    unique_constraints = {
        constraint.name
        for constraint in app_models.Finding.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert unique_constraints == {"uq_finding_project_dedup_key"}


def test_workbench_parsed_input_preserves_parser_metadata(tmp_path: Path) -> None:
    input_file = tmp_path / "generic.csv"
    payload = "\n".join(
        [
            "# ignored before header",
            "cve_id;target_ref;component_name;fix_versions;ticket_url",
            'CVE-2024-3094;build-host-1;xz;"2.0.0|2.1.0";SEC-1001',
            "",
        ]
    ).encode()
    parsed_upload = GenericOccurrenceCsvImporter().parse_with_metadata(
        payload,
        filename=input_file.name,
    )

    parsed_input = _parsed_input_from_workbench_occurrences(
        parsed_upload.occurrences,
        input_path=input_file,
        input_type="generic-occurrence-csv",
        base_parsed_input=parsed_upload.parsed_input,
        asset_context_summary={"warnings": ["asset context warning"]},
        vex_summary=None,
    )

    assert parsed_input.total_rows == 1
    assert parsed_input.input_paths == [str(input_file)]
    assert parsed_input.source_summaries[0].total_rows == 1
    assert parsed_input.source_summaries[0].warning_count == 1
    assert parsed_input.occurrences[0].fix_versions == ["2.0.0", "2.1.0"]
    assert any("ticket_url" in warning for warning in parsed_input.warnings)
    assert "asset context warning" in parsed_input.warnings


def test_record_audit_event_bounds_detail_json(session: Session) -> None:
    from app.services.audit import record_audit_event

    event = record_audit_event(
        session,
        action="audit.boundary",
        resource_type="audit_event",
        detail={
            "username": "u" * 5000,
            "nested": {"note": "n" * 5000},
        },
    )
    session.commit()

    serialized = json.dumps(event.detail_json, separators=(",", ":"), sort_keys=True)
    assert len(serialized.encode("utf-8")) <= 4096
    assert len(event.detail_json["username"]) == 1024
    assert len(event.detail_json["nested"]["note"]) == 1024


def test_project_repository_lists_all_local_projects_and_leaves_commit_to_caller(
    app_models: Any,
    repository_classes: Any,
    session: Session,
) -> None:
    repository = repository_classes.ProjectRepository(session)
    owned = repository.create_project(
        app_models.ProjectCreate(name="Owned", description="Visible locally.")
    )
    session.add(
        app_models.Project(
            name="Other",
            description="Also visible locally.",
        )
    )
    session.commit()

    projects, count = repository.list_projects()

    assert {project.name for project in projects} == {"Owned", "Other"}
    assert count == 2
    assert repository.get_project(owned.id) is not None
    assert repository.get_project(uuid.uuid4()) is None

    rolled_back = repository.create_project(
        app_models.ProjectCreate(name="Rollback", description=None)
    )
    rolled_back_id = rolled_back.id
    session.rollback()

    assert session.get(app_models.Project, rolled_back_id) is None


def test_asset_finding_and_run_repositories_persist_domain_graph(
    app_models: Any,
    repository_classes: Any,
    session: Session,
) -> None:
    project = repository_classes.ProjectRepository(session).create_project(
        app_models.ProjectCreate(name="Repository Contract", description=None)
    )
    asset_repository = repository_classes.AssetRepository(session)
    finding_repository = repository_classes.FindingRepository(session)
    run_repository = repository_classes.RunRepository(session)

    asset = asset_repository.upsert_asset(
        project_id=project.id,
        asset_key="payments-api",
        name="Payments API",
        target_ref="registry.example.test/payments-api:2026.04.28",
        owner="platform",
        business_service="payments",
        environment=app_models.AssetEnvironment.PRODUCTION,
        exposure=app_models.AssetExposure.INTERNET_FACING,
        criticality=app_models.AssetCriticality.CRITICAL,
    )
    component = finding_repository.upsert_component(
        name="log4j-core",
        version="2.14.1",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        ecosystem="maven",
    )
    vulnerability = finding_repository.upsert_vulnerability(
        cve_id="CVE-2021-44228",
        source_id="CVE-2021-44228",
        cvss_score=10.0,
        severity="CRITICAL",
        provider_json={"nvd": {"lastModified": "2026-04-28T10:15:00Z"}},
    )
    finding = finding_repository.create_or_update_finding(
        project_id=project.id,
        vulnerability_id=vulnerability.id,
        component_id=component.id,
        asset_id=asset.id,
        cve_id="CVE-2021-44228",
    )
    snapshot = run_repository.get_or_create_provider_snapshot(
        content_hash="sha256:repo-contract",
        nvd_last_sync="2026-04-28T10:15:00Z",
        epss_date="2026-04-28",
        kev_catalog_version="2026-04-28",
        source_hashes_json={"nvd": "sha256:nvd"},
        source_metadata_json={
            "api_key": "super-secret-token",
            "source_path": "/tmp/workbench-provider-snapshot.json",
        },
    )
    same_snapshot = run_repository.get_or_create_provider_snapshot(
        content_hash="sha256:repo-contract",
    )
    run = run_repository.create_analysis_run(
        project_id=project.id,
        provider_snapshot_id=snapshot.id,
        input_type="trivy-json",
        filename="trivy.json",
        status=app_models.AnalysisRunStatus.RUNNING,
    )
    occurrence = run_repository.add_finding_occurrence(
        finding_id=finding.id,
        analysis_run_id=run.id,
        source="dependency-scan",
        scanner="trivy",
        raw_reference="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        fix_version="2.17.1",
        evidence_json={"input_line": 42},
    )
    finished = run_repository.finish_analysis_run(
        run.id,
        status=app_models.AnalysisRunStatus.COMPLETED_WITH_ERRORS,
        result_ref_json={"findings": 1, "degraded_providers": ["nvd"]},
        diagnostics_json={"nvd": "cache replay used"},
    )
    session.commit()

    assert same_snapshot.id == snapshot.id
    assert snapshot.source_metadata_json["api_key"] == "[REDACTED]"
    assert snapshot.source_metadata_json["source_path"] == "[REDACTED]"
    assert occurrence.finding_id == finding.id
    assert finished.finished_at is not None
    workflow = repository_classes.WorkflowRepository(session).get_latest_analysis_workflow(
        analysis_run_id=finished.id,
        kind=app_models.WorkflowRunKind.IMPORT,
    )
    assert workflow is not None
    assert workflow.result_ref_json["findings"] == 1
    assert workflow.diagnostics_json["nvd"] == "cache replay used"
    assert [item.id for item in asset_repository.list_project_assets(project.id)] == [asset.id]
    assert [item.id for item in finding_repository.list_project_findings(project.id)] == [
        finding.id
    ]
    assert [item.id for item in run_repository.list_analysis_runs(project.id)] == [run.id]


def test_user_auth_crud_surface_stays_outside_workbench_repositories() -> None:
    repositories = importlib.import_module("app.repositories")
    repository_exports = set(getattr(repositories, "__all__", ()))

    assert {
        "ProjectRepository",
        "AssetRepository",
        "FindingRepository",
        "RunRepository",
    }.issubset(repository_exports)
    assert "UserRepository" not in repository_exports
    assert "AuthRepository" not in repository_exports


def test_provider_snapshot_reuse_refreshes_replay_mode_metadata(
    repository_classes: Any,
    session: Session,
) -> None:
    run_repository = repository_classes.RunRepository(session)
    locked_snapshot = run_repository.get_or_create_provider_snapshot(
        content_hash="sha256:mode-reuse",
        nvd_last_sync="2026-04-28T10:15:00Z",
        epss_date="2026-04-28",
        kev_catalog_version="2026-04-28",
        source_hashes_json={"provider_snapshot": "sha256:mode-reuse"},
        source_metadata_json={
            "cache_only": True,
            "locked_provider_data": True,
            "selected_sources": ["nvd", "epss", "kev"],
        },
    )

    unlocked_snapshot = run_repository.get_or_create_provider_snapshot(
        content_hash="sha256:mode-reuse",
        nvd_last_sync="2026-04-28T10:15:00Z",
        epss_date="2026-04-28",
        kev_catalog_version="2026-04-28",
        source_hashes_json={"provider_snapshot": "sha256:mode-reuse"},
        source_metadata_json={
            "cache_only": True,
            "locked_provider_data": False,
            "selected_sources": ["nvd", "epss", "kev"],
        },
    )

    same_snapshot = run_repository.get_or_create_provider_snapshot(
        content_hash="sha256:mode-reuse",
    )

    assert unlocked_snapshot.id == locked_snapshot.id == same_snapshot.id
    assert same_snapshot.source_metadata_json["cache_only"] is True
    assert same_snapshot.source_metadata_json["locked_provider_data"] is False
