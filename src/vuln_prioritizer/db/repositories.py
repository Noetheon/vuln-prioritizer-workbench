"""Repository helpers for common Workbench database operations."""

from __future__ import annotations

from typing import TypeVar

from sqlalchemy.orm import Session

from vuln_prioritizer.db.repository_artifacts import ArtifactRepositoryMixin
from vuln_prioritizer.db.repository_assets import AssetWaiverRepositoryMixin
from vuln_prioritizer.db.repository_attack import AttackRepositoryMixin
from vuln_prioritizer.db.repository_detection import DetectionControlRepositoryMixin
from vuln_prioritizer.db.repository_findings import FINDING_SORT_FIELDS, FindingRepositoryMixin
from vuln_prioritizer.db.repository_jobs import WorkbenchJobRepositoryMixin
from vuln_prioritizer.db.repository_projects import ProjectRunRepositoryMixin
from vuln_prioritizer.db.repository_providers import ProviderSnapshotRepositoryMixin
from vuln_prioritizer.db.repository_security import SecurityAuditRepositoryMixin

T = TypeVar("T")

__all__ = ["FINDING_SORT_FIELDS", "WorkbenchRepository"]


class WorkbenchRepository(
    ProviderSnapshotRepositoryMixin,
    ProjectRunRepositoryMixin,
    FindingRepositoryMixin,
    AttackRepositoryMixin,
    AssetWaiverRepositoryMixin,
    DetectionControlRepositoryMixin,
    ArtifactRepositoryMixin,
    WorkbenchJobRepositoryMixin,
    SecurityAuditRepositoryMixin,
):
    """Small repository facade for Workbench persistence flows."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def _required(self, model: type[T], primary_key: str) -> T:
        instance = self.session.get(model, primary_key)
        if instance is None:
            raise LookupError(f"{model.__name__} not found: {primary_key}")
        return instance
