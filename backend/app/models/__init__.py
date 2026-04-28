"""Public model aggregator for the template-aligned backend app.

Keep imports from this package stable. API routes and tests should continue to
use ``from app.models import User, ProjectPublic`` while table definitions live
in focused modules.
"""

from app.models.assets import Asset, AssetBase, Component, ComponentBase
from app.models.auth import Token, TokenPayload
from app.models.enums import (
    AssetCriticality,
    AssetEnvironment,
    AssetExposure,
    FindingPriority,
    FindingStatus,
)
from app.models.findings import Finding, FindingBase
from app.models.projects import (
    Project,
    ProjectBase,
    ProjectCreate,
    ProjectPublic,
    ProjectsPublic,
    ProjectUpdate,
)
from app.models.registry import import_table_models
from app.models.users import User, UserBase, UserPublic, UsersPublic
from app.models.vulnerabilities import Vulnerability, VulnerabilityBase
from app.models.workbench import MigrationStatus, WorkbenchStatus

__all__ = [
    "Asset",
    "AssetBase",
    "AssetCriticality",
    "AssetEnvironment",
    "AssetExposure",
    "Component",
    "ComponentBase",
    "Finding",
    "FindingBase",
    "FindingPriority",
    "FindingStatus",
    "MigrationStatus",
    "Project",
    "ProjectBase",
    "ProjectCreate",
    "ProjectPublic",
    "ProjectsPublic",
    "ProjectUpdate",
    "Token",
    "TokenPayload",
    "User",
    "UserBase",
    "UserPublic",
    "UsersPublic",
    "Vulnerability",
    "VulnerabilityBase",
    "WorkbenchStatus",
    "import_table_models",
]
