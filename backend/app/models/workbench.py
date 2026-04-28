"""Template Workbench status DTOs."""

from sqlmodel import SQLModel


class MigrationStatus(SQLModel):
    """Template migration state for the Workbench adapter."""

    phase: str
    legacy_workbench_mounted: bool


class WorkbenchStatus(SQLModel):
    """Status response returned by the template Workbench adapter."""

    status: str
    app: str
    core_package: str
    core_version: str
    legacy_api_prefix: str
    migration: MigrationStatus
