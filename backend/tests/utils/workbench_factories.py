"""Pure factories for Workbench domain model tests."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

from app import models as app_models
from app.core.local_actor import LocalWorkbenchActor, local_actor_id

app_models.import_table_models()

FIXED_STARTED_AT = datetime(2026, 4, 28, 12, 0, tzinfo=UTC)
FIXED_FINISHED_AT = datetime(2026, 4, 28, 12, 4, tzinfo=UTC)

_ID_NAMESPACE = uuid.UUID("9a371f52-26d7-45e5-9de7-7f9f14f3579d")
_T = TypeVar("_T")


@dataclass(frozen=True)
class WorkbenchGraph:
    """A coherent unsaved Workbench object graph for tests."""

    actor: LocalWorkbenchActor
    project: app_models.Project
    asset: app_models.Asset
    component: app_models.Component
    vulnerability: app_models.Vulnerability
    finding: app_models.Finding
    provider_snapshot: app_models.ProviderSnapshot
    analysis_run: app_models.AnalysisRun


def workbench_local_actor(index: int = 1, **overrides: Any) -> LocalWorkbenchActor:
    """Build a local actor fixture."""

    email = str(overrides.pop("email", f"owner-{index}@example.test"))
    values = {
        "id": local_actor_id(email),
        "email": f"owner-{index}@example.test",
        "is_active": True,
        "full_name": f"Workbench Owner {index}",
    }
    values["email"] = email
    values.update(overrides)
    return LocalWorkbenchActor(**values)


def workbench_project(
    index: int = 1,
    *,
    local_actor: LocalWorkbenchActor | None = None,
    **overrides: Any,
) -> app_models.Project:
    """Build an unsaved project."""

    _ = local_actor
    values = {
        "id": workbench_id("project", index),
        "name": f"Workbench Project {index}",
        "description": "Workbench domain fixture.",
        "created_at": _time(index),
        "updated_at": _time(index),
    }
    values.update(overrides)
    return app_models.Project(**values)


def workbench_asset(
    index: int = 1,
    *,
    project: app_models.Project | None = None,
    project_id: uuid.UUID | None = None,
    **overrides: Any,
) -> app_models.Asset:
    """Build an unsaved asset scoped to a project."""

    resolved_project_id = project_id or (
        project.id if project is not None else workbench_id("project", index)
    )
    values = {
        "id": workbench_id("asset", index),
        "project_id": resolved_project_id,
        "asset_key": f"payments-api-{index}",
        "name": f"Payments API {index}",
        "target_ref": f"registry.example.test/payments-api:{index}",
        "owner": "platform",
        "business_service": "payments",
        "environment": app_models.AssetEnvironment.PRODUCTION,
        "exposure": app_models.AssetExposure.INTERNET_FACING,
        "criticality": app_models.AssetCriticality.CRITICAL,
        "created_at": _time(index),
        "updated_at": _time(index),
    }
    values.update(overrides)
    asset = app_models.Asset(**values)
    if project is not None:
        asset.project = project
    return asset


def workbench_component(index: int = 1, **overrides: Any) -> app_models.Component:
    """Build an unsaved software component."""

    values = {
        "id": workbench_id("component", index),
        "name": "log4j-core",
        "version": f"2.14.{index}",
        "purl": f"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.{index}",
        "ecosystem": "maven",
        "package_type": "library",
        "created_at": _time(index),
        "updated_at": _time(index),
    }
    values.update(overrides)
    return app_models.Component(**values)


def workbench_vulnerability(index: int = 1, **overrides: Any) -> app_models.Vulnerability:
    """Build an unsaved vulnerability."""

    cve_id = _cve_id(index)
    values = {
        "id": workbench_id("vulnerability", index),
        "cve_id": cve_id,
        "source_id": cve_id,
        "title": f"Workbench vulnerability {cve_id}",
        "description": "Offline vulnerability fixture for Workbench tests.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "published_at": "2021-12-10T00:00:00Z",
        "modified_at": "2026-04-28T00:00:00Z",
        "provider_json": {"source": "fixture", "offline": True},
        "created_at": _time(index),
        "updated_at": _time(index),
    }
    values.update(overrides)
    return app_models.Vulnerability(**values)


def workbench_finding(
    index: int = 1,
    *,
    project: app_models.Project | None = None,
    project_id: uuid.UUID | None = None,
    asset: app_models.Asset | None = None,
    asset_id: uuid.UUID | None = None,
    component: app_models.Component | None = None,
    component_id: uuid.UUID | None = None,
    vulnerability: app_models.Vulnerability | None = None,
    vulnerability_id: uuid.UUID | None = None,
    **overrides: Any,
) -> app_models.Finding:
    """Build an unsaved prioritized finding."""

    resolved_project_id = project_id or (
        project.id if project is not None else workbench_id("project", index)
    )
    resolved_asset_id = _optional_related_id(asset_id, asset)
    resolved_component_id = _optional_related_id(component_id, component)
    resolved_vulnerability_id = vulnerability_id or (
        vulnerability.id if vulnerability is not None else workbench_id("vulnerability", index)
    )
    cve_id = vulnerability.cve_id if vulnerability is not None else _cve_id(index)
    values = {
        "id": workbench_id("finding", index),
        "project_id": resolved_project_id,
        "asset_id": resolved_asset_id,
        "component_id": resolved_component_id,
        "vulnerability_id": resolved_vulnerability_id,
        "cve_id": cve_id,
        "dedup_key": f"{resolved_project_id}:{cve_id}:{resolved_asset_id}:{resolved_component_id}",
        "status": app_models.FindingStatus.OPEN,
        "priority": app_models.FindingPriority.CRITICAL,
        "priority_rank": 1,
        "risk_score": 99.0,
        "operational_rank": 1,
        "in_kev": True,
        "epss": 0.9442,
        "cvss_base_score": 10.0,
        "attack_mapped": True,
        "recommended_action": "Patch affected component.",
        "rationale": "Fixture combines KEV, high EPSS, and internet-facing exposure.",
        "explanation_json": {"signals": ["kev", "epss", "internet-facing"]},
        "data_quality_json": {"fixture": True},
        "evidence_json": {"input": "offline-fixture"},
        "first_seen_at": _time(index),
        "last_seen_at": _time(index),
        "created_at": _time(index),
        "updated_at": _time(index),
    }
    values.update(overrides)
    finding = app_models.Finding(**values)
    _assign_if_present(finding, "project", project)
    _assign_if_present(finding, "asset", asset)
    _assign_if_present(finding, "component", component)
    _assign_if_present(finding, "vulnerability", vulnerability)
    return finding


def workbench_provider_snapshot(
    index: int = 1,
    **overrides: Any,
) -> app_models.ProviderSnapshot:
    """Build an unsaved provider snapshot."""

    values = {
        "id": workbench_id("provider-snapshot", index),
        "nvd_last_sync": "2026-04-28T10:15:00Z",
        "epss_date": "2026-04-28",
        "kev_catalog_version": "2026-04-28",
        "content_hash": f"sha256:fixture-provider-snapshot-{index}",
        "source_hashes_json": {
            "nvd": f"sha256:nvd-feed-{index}",
            "epss": f"sha256:epss-feed-{index}",
            "kev": f"sha256:kev-feed-{index}",
        },
        "source_metadata_json": {
            "selected_sources": ["nvd", "epss", "kev"],
            "cache_only": True,
            "requested_cves": 1,
        },
        "created_at": _time(index),
    }
    values.update(overrides)
    return app_models.ProviderSnapshot(**values)


def workbench_analysis_run(
    index: int = 1,
    *,
    project: app_models.Project | None = None,
    project_id: uuid.UUID | None = None,
    provider_snapshot: app_models.ProviderSnapshot | None = None,
    provider_snapshot_id: uuid.UUID | None = None,
    **overrides: Any,
) -> app_models.AnalysisRun:
    """Build an unsaved analysis run."""

    resolved_project_id = project_id or (
        project.id if project is not None else workbench_id("project", index)
    )
    resolved_provider_snapshot_id = _optional_related_id(provider_snapshot_id, provider_snapshot)
    values = {
        "id": workbench_id("analysis-run", index),
        "project_id": resolved_project_id,
        "provider_snapshot_id": resolved_provider_snapshot_id,
        "input_type": "cve-list",
        "filename": f"known-cves-{index}.txt",
        "status": app_models.AnalysisRunStatus.COMPLETED,
        "started_at": FIXED_STARTED_AT + timedelta(minutes=index - 1),
        "finished_at": FIXED_FINISHED_AT + timedelta(minutes=index - 1),
        "error_message": None,
    }
    values.update(overrides)
    analysis_run = app_models.AnalysisRun(**values)
    _assign_if_present(analysis_run, "project", project)
    _assign_if_present(analysis_run, "provider_snapshot", provider_snapshot)
    return analysis_run


def workbench_test_graph(index: int = 1) -> WorkbenchGraph:
    """Build a coherent, unsaved project-to-analysis-run Workbench graph."""

    actor = workbench_local_actor(index)
    project = workbench_project(index, local_actor=actor)
    asset = workbench_asset(index, project=project)
    component = workbench_component(index)
    vulnerability = workbench_vulnerability(index)
    finding = workbench_finding(
        index,
        project=project,
        asset=asset,
        component=component,
        vulnerability=vulnerability,
    )
    provider_snapshot = workbench_provider_snapshot(index)
    analysis_run = workbench_analysis_run(
        index,
        project=project,
        provider_snapshot=provider_snapshot,
    )
    return WorkbenchGraph(
        actor=actor,
        project=project,
        asset=asset,
        component=component,
        vulnerability=vulnerability,
        finding=finding,
        provider_snapshot=provider_snapshot,
        analysis_run=analysis_run,
    )


def workbench_id(name: str, index: int = 1) -> uuid.UUID:
    """Return a stable UUID for a factory object name and index."""

    return uuid.uuid5(_ID_NAMESPACE, f"{name}:{index}")


def _cve_id(index: int) -> str:
    return f"CVE-2026-{index:04d}"


def _time(index: int) -> datetime:
    return FIXED_STARTED_AT + timedelta(minutes=index - 1)


def _optional_related_id(explicit_id: uuid.UUID | None, related: Any | None) -> uuid.UUID | None:
    if explicit_id is not None:
        return explicit_id
    if related is None:
        return None
    return related.id


def _assign_if_present(target: Any, field: str, value: _T | None) -> None:
    if value is not None:
        setattr(target, field, value)
