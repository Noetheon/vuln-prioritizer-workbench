"""First-setup progress of a project for the Overview checklist."""

from __future__ import annotations

import uuid

from sqlalchemy import func, or_
from sqlmodel import Session, col, select

from app.models import (
    PROJECT_STATE_INPUT_TYPE,
    AnalysisRun,
    Asset,
    Finding,
    ProjectOnboardingPublic,
    Report,
)
from app.models.enums import (
    AnalysisRunStatus,
    AssetCriticality,
    AssetEnvironment,
    AssetExposure,
)
from app.services.provider_update_constants import PROVIDER_UPDATE_INPUT_TYPE
from app.services.report_formatting import REEVALUATION_INPUT_TYPE

# Runs that are not imports: evaluations, provider updates, recorded states.
NON_IMPORT_INPUT_TYPES = (
    REEVALUATION_INPUT_TYPE,
    PROVIDER_UPDATE_INPUT_TYPE,
    PROJECT_STATE_INPUT_TYPE,
)
COMPLETED_RUN_STATUSES = (
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
    AnalysisRunStatus.SUCCEEDED,
)


def project_onboarding(session: Session, project_id: uuid.UUID) -> ProjectOnboardingPublic:
    """Count what the setup checklist needs: imports, findings, asset context, reports."""
    import_count = _count(
        session,
        select(func.count())
        .select_from(AnalysisRun)
        .where(
            AnalysisRun.project_id == project_id,
            col(AnalysisRun.status).in_([str(status) for status in COMPLETED_RUN_STATUSES]),
            col(AnalysisRun.input_type).not_in(NON_IMPORT_INPUT_TYPES),
        ),
    )
    finding_count = _count(
        session,
        select(func.count()).select_from(Finding).where(Finding.project_id == project_id),
    )
    asset_count = _count(
        session,
        select(func.count()).select_from(Asset).where(Asset.project_id == project_id),
    )
    assets_with_context = _count(
        session,
        select(func.count())
        .select_from(Asset)
        .where(
            Asset.project_id == project_id,
            or_(
                func.length(func.trim(func.coalesce(Asset.owner, ""))) > 0,
                func.length(func.trim(func.coalesce(Asset.business_service, ""))) > 0,
                col(Asset.environment) != AssetEnvironment.UNKNOWN.value,
                col(Asset.exposure) != AssetExposure.UNKNOWN.value,
                col(Asset.criticality) != AssetCriticality.UNKNOWN.value,
            ),
        ),
    )
    report_count = _count(
        session,
        select(func.count()).select_from(Report).where(Report.project_id == project_id),
    )
    return ProjectOnboardingPublic(
        project_id=project_id,
        import_count=import_count,
        finding_count=finding_count,
        asset_count=asset_count,
        assets_with_context=assets_with_context,
        report_count=report_count,
        complete=report_count > 0,
    )


def _count(session: Session, statement: object) -> int:
    return int(session.exec(statement).one())  # type: ignore[call-overload]
