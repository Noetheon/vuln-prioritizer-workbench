"""Provider update request input and metadata helpers."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session, col, select

from app.domain.engine.security_redaction import redact_value
from app.domain.engine.utils import normalize_cve_id
from app.models import AnalysisRun, Finding, Project, ProviderUpdateJobCreate
from app.repositories import RunRepository
from app.services.provider_update_constants import (
    PROVIDER_UPDATE_PROJECT_NAME,
    VALID_PROVIDER_SOURCES,
)
from app.services.provider_update_errors import ProviderUpdateValidationError


def _normalize_sources(raw_sources: list[str]) -> list[str]:
    selected_sources: list[str] = []
    invalid_sources: list[str] = []
    for value in raw_sources:
        source = value.strip().lower()
        if source not in VALID_PROVIDER_SOURCES:
            invalid_sources.append(value)
            continue
        if source not in selected_sources:
            selected_sources.append(source)
    if invalid_sources:
        raise ProviderUpdateValidationError(
            "Invalid provider source(s): " + ", ".join(invalid_sources)
        )
    if not selected_sources:
        raise ProviderUpdateValidationError("At least one provider source is required.")
    return selected_sources


def _provider_update_cve_ids(
    session: Session,
    *,
    payload: ProviderUpdateJobCreate,
) -> list[str]:
    explicit_cves: list[str] = []
    invalid_cves: list[str] = []
    for value in payload.cve_ids:
        normalized = normalize_cve_id(value)
        if normalized is None:
            invalid_cves.append(value)
        elif normalized not in explicit_cves:
            explicit_cves.append(normalized)
    if invalid_cves:
        raise ProviderUpdateValidationError("Invalid CVE id(s): " + ", ".join(invalid_cves))

    if explicit_cves:
        cve_ids = explicit_cves
    else:
        statement = select(Finding.cve_id).order_by(col(Finding.cve_id))
        cve_ids = list(dict.fromkeys(session.exec(statement).all()))
    if payload.max_cves is not None:
        return cve_ids[: payload.max_cves]
    return cve_ids


def _provider_update_project(session: Session) -> Project:
    statement = select(Project).where(Project.name == PROVIDER_UPDATE_PROJECT_NAME)
    project = session.exec(statement).first()
    if project is not None:
        return project
    project = Project(
        name=PROVIDER_UPDATE_PROJECT_NAME,
        description="System project for global provider update jobs.",
    )
    session.add(project)
    session.flush()
    return project


def _other_running_update(repository: RunRepository, run_id: uuid.UUID) -> AnalysisRun | None:
    active_run = repository.get_running_provider_update_run()
    if active_run is None or active_run.id == run_id:
        return None
    return active_run


def _dict_payload(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _int_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    return 0


def _redacted_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redacted, _paths = redact_value(payload)
    return redacted if isinstance(redacted, dict) else {}


__all__ = [
    "_normalize_sources",
    "_provider_update_cve_ids",
    "_provider_update_project",
    "_other_running_update",
    "_dict_payload",
    "_string_list",
    "_int_value",
    "_redacted_payload",
]
