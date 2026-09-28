"""Stable string enums for Workbench domain models."""

from enum import StrEnum


class AssetEnvironment(StrEnum):
    """Deployment environment for an affected asset."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    UNKNOWN = "unknown"


class AssetExposure(StrEnum):
    """Exposure level for an affected asset."""

    INTERNET_FACING = "internet-facing"
    INTERNAL = "internal"
    PRIVATE = "private"
    UNKNOWN = "unknown"


class AssetCriticality(StrEnum):
    """Business criticality for an affected asset."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class FindingPriority(StrEnum):
    """Rule-based finding priority label."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(StrEnum):
    """Finding lifecycle state."""

    OPEN = "open"
    IN_REVIEW = "in_review"
    REMEDIATING = "remediating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    SUPPRESSED = "suppressed"


# Analyst-owned work that still needs remediation.
ACTIONABLE_FINDING_STATUSES = frozenset(
    {FindingStatus.OPEN, FindingStatus.IN_REVIEW, FindingStatus.REMEDIATING}
)
# Analyst-owned closure. "resolved" is also set when a rescan no longer reports
# the finding; "fixed", "accepted", and "suppressed" stay owned by VEX/waivers.
CLOSED_WORKFLOW_STATUSES = frozenset({FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE})


class FindingSlaState(StrEnum):
    """Where open work stands against its recorded SLA due date."""

    OVERDUE = "overdue"
    DUE_SOON = "due_soon"
    ON_TRACK = "on_track"


class FindingLifecycleSource(StrEnum):
    """What caused a recorded finding status transition."""

    MANUAL = "manual"
    IMPORT_NOT_OBSERVED = "import_not_observed"
    IMPORT_REOBSERVED = "import_reobserved"


class AnalysisRunStatus(StrEnum):
    """Import or analysis run lifecycle state."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"
