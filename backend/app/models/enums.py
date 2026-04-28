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
    FIXED = "fixed"
    ACCEPTED = "accepted"
    SUPPRESSED = "suppressed"


class AnalysisRunStatus(StrEnum):
    """Import or analysis run lifecycle state."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"
