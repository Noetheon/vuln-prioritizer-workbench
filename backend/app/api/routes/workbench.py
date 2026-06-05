"""Workbench routes exposed through the active API namespace."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, SQLModel

from app.api.deps import LocalActor, SessionDep
from app.core.app_state import workbench_settings
from app.core.config import Settings
from app.core.migration_bootstrap import ALEMBIC_HEAD
from app.domain.engine import __version__
from app.models import (
    DemoWorkspaceCreate,
    DemoWorkspacePublic,
    DemoWorkspaceStatusPublic,
    WorkbenchCapabilitiesPublic,
    WorkbenchHealth,
    WorkbenchStatus,
    WorkflowRunKind,
)
from app.services.audit import record_audit_event
from app.services.demo_workspace import (
    DemoWorkspaceSnapshot,
    delete_demo_workspace,
    demo_workspace_enabled,
    read_demo_workspace_snapshot,
    seed_demo_workspace,
)
from app.services.import_errors import ImportServiceError
from app.services.report_artifacts import build_report_public
from app.services.report_models import ReportGenerationError
from app.services.run_workflow_projection import analysis_run_public
from app.services.workbench_capabilities import build_workbench_capabilities
from app.services.workflows import latest_analysis_workflow_public, latest_report_workflow_public

router = APIRouter(prefix="/workbench", tags=["workbench"])

REQUIRED_SCHEMA_TABLES = frozenset(
    table_name for table_name in SQLModel.metadata.tables if table_name != "alembic_version"
)
REQUIRED_ALEMBIC_TABLE = "alembic_version"


@router.get("/health", response_model=WorkbenchHealth)
def workbench_health() -> WorkbenchHealth:
    """Return minimal local liveness for browser and proxy checks."""
    return WorkbenchHealth(status="ok")


@router.get("/status")
def workbench_status(
    request: Request,
    session: SessionDep,
) -> WorkbenchStatus:
    """Return local Workbench readiness and version status."""
    active_settings = _request_settings(request)
    database, schema = _database_readiness(session)
    return WorkbenchStatus(
        status="ready" if database == "ready" and schema == "ready" else "not_ready",
        app=active_settings.PROJECT_NAME,
        core_package="app.domain.engine",
        core_version=__version__,
        database_status=database,
        schema_status=schema,
        api_docs_enabled=active_settings.api_docs_enabled,
        api_docs_path="/docs" if active_settings.api_docs_enabled else None,
    )


@router.get("/capabilities", response_model=WorkbenchCapabilitiesPublic)
def workbench_capabilities(
    request: Request,
    local_actor: LocalActor,
) -> WorkbenchCapabilitiesPublic:
    """Return the versioned Workbench runtime capability contract."""
    _ = local_actor
    return build_workbench_capabilities(_request_settings(request))


@router.get("/demo", response_model=DemoWorkspaceStatusPublic)
def read_demo_workspace(
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
) -> DemoWorkspaceStatusPublic:
    """Return the optional local demo workspace status."""
    _ = local_actor
    active_settings = _request_settings(request)
    return _demo_workspace_status(
        read_demo_workspace_snapshot(session),
        enabled=demo_workspace_enabled(active_settings),
    )


@router.post("/demo", response_model=DemoWorkspacePublic)
async def create_demo_workspace(
    *,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
    payload: DemoWorkspaceCreate,
) -> DemoWorkspacePublic:
    """Create or reset the deterministic local demo workspace."""
    active_settings = _request_settings(request)
    if not demo_workspace_enabled(active_settings):
        raise HTTPException(status_code=403, detail="Demo workspace is disabled.")
    try:
        snapshot = await seed_demo_workspace(
            session=session,
            settings=active_settings,
            local_actor=local_actor,
            reset=payload.reset,
        )
    except ImportServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    except ReportGenerationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record_audit_event(
        session,
        action="workbench.demo.reset" if payload.reset else "workbench.demo.seed",
        resource_type="project",
        resource_id=snapshot.project.id if snapshot.project is not None else None,
        actor=local_actor,
        project_id=snapshot.project.id if snapshot.project is not None else None,
        detail={
            "finding_count": snapshot.finding_count,
            "asset_count": snapshot.asset_count,
            "report_count": snapshot.report_count,
            "waiver_count": snapshot.waiver_count,
        },
    )
    session.commit()
    return _demo_workspace_public(snapshot, active_settings, session=session)


@router.delete("/demo", status_code=204)
def remove_demo_workspace(
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
) -> Response:
    """Remove the deterministic local demo workspace and its artifacts."""
    active_settings = _request_settings(request)
    if not demo_workspace_enabled(active_settings):
        raise HTTPException(status_code=403, detail="Demo workspace is disabled.")
    snapshot = read_demo_workspace_snapshot(session)
    record_audit_event(
        session,
        action="workbench.demo.delete",
        resource_type="project",
        resource_id=snapshot.project.id if snapshot.project is not None else None,
        actor=local_actor,
        project_id=snapshot.project.id if snapshot.project is not None else None,
        detail={"seeded": snapshot.seeded},
    )
    delete_demo_workspace(session=session, settings=active_settings)
    session.commit()
    return Response(status_code=204)


def _request_settings(request: Request) -> Settings:
    return workbench_settings(request, required=False)


def _demo_workspace_status(
    snapshot: DemoWorkspaceSnapshot,
    *,
    enabled: bool,
) -> DemoWorkspaceStatusPublic:
    return DemoWorkspaceStatusPublic(
        enabled=enabled,
        seeded=snapshot.seeded,
        project_id=snapshot.project.id if snapshot.project is not None else None,
        project_name=snapshot.project.name if snapshot.project is not None else None,
        latest_run_id=snapshot.latest_run.id if snapshot.latest_run is not None else None,
        finding_count=snapshot.finding_count,
        asset_count=snapshot.asset_count,
        report_count=snapshot.report_count,
        waiver_count=snapshot.waiver_count,
        message=(
            "Demo workspace is available."
            if enabled
            else "Demo workspace can be enabled with DEMO_WORKSPACE_ENABLED=true in local mode."
        ),
    )


def _demo_workspace_public(
    snapshot: DemoWorkspaceSnapshot,
    settings: Settings,
    *,
    session: Session,
) -> DemoWorkspacePublic:
    if snapshot.project is None or snapshot.latest_run is None:
        raise HTTPException(status_code=500, detail="Demo workspace seed did not complete.")
    return DemoWorkspacePublic(
        **_demo_workspace_status(snapshot, enabled=demo_workspace_enabled(settings)).model_dump(),
        project=snapshot.project,
        latest_run=analysis_run_public(
            snapshot.latest_run,
            session=session,
            workflow=latest_analysis_workflow_public(
                session,
                analysis_run_id=snapshot.latest_run.id,
                kind=WorkflowRunKind.IMPORT,
            ),
        ),
        reports=[
            build_report_public(
                report,
                settings,
                workflow=latest_report_workflow_public(session, report_id=report.id),
            )
            for report in snapshot.reports
        ],
    )


def _database_readiness(session: Session) -> tuple[str, str]:
    try:
        session.execute(text("SELECT 1")).one()
        inspector = inspect(session.get_bind())
        table_names = set(inspector.get_table_names())
        if not REQUIRED_SCHEMA_TABLES.issubset(table_names):
            return "ready", "not_ready"
        if REQUIRED_ALEMBIC_TABLE not in table_names:
            return "ready", "not_ready"
        if not _alembic_head_is_current(session):
            return "ready", "not_ready"
    except SQLAlchemyError:
        return "unavailable", "not_ready"
    return "ready", "ready"


def _alembic_head_is_current(session: Session) -> bool:
    rows = session.execute(text("SELECT version_num FROM alembic_version")).all()
    versions = {str(row[0]) for row in rows}
    return ALEMBIC_HEAD in versions
