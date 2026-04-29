"""Template Workbench repository exports."""

from app.repositories.assets import AssetRepository
from app.repositories.findings import FindingRepository
from app.repositories.projects import ProjectRepository
from app.repositories.runs import RunRepository

__all__ = [
    "AssetRepository",
    "FindingRepository",
    "ProjectRepository",
    "RunRepository",
]
