"""Priority logic facade for scoring and rationale helpers."""

from __future__ import annotations

import app.domain.engine.scoring_operational as _operational
import app.domain.engine.scoring_rationale as _rationale
from app.domain.engine.config import PRIORITY_RANKS
from app.domain.engine.models import (
    EpssData,
    KevData,
    NvdData,
    PriorityLabel,
    PriorityPolicy,
)

OPERATIONAL_BASE_SCORES = _operational.OPERATIONAL_BASE_SCORES
OPERATIONAL_SCORE_MAX = _operational.OPERATIONAL_SCORE_MAX
OPERATIONAL_SCORE_MIN = _operational.OPERATIONAL_SCORE_MIN
build_operational_score = _operational.build_operational_score
build_scoped_operational_score = _operational.build_scoped_operational_score
clamp_operational_score = _operational.clamp_operational_score
determine_priority_state = _operational.determine_priority_state
build_comparison_reason = _rationale.build_comparison_reason
build_rationale = _rationale.build_rationale
recommended_action = _rationale.recommended_action


def determine_priority(
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    policy: PriorityPolicy | None = None,
) -> tuple[PriorityLabel, int]:
    """Apply the fixed MVP priority rules."""
    active_policy = policy or PriorityPolicy()
    cvss = nvd.cvss_base_score
    epss_score = epss.epss

    if kev.in_kev or (
        epss_score is not None
        and epss_score >= active_policy.critical_epss_threshold
        and cvss is not None
        and cvss >= active_policy.critical_cvss_threshold
    ):
        label = PriorityLabel.CRITICAL
    elif (epss_score is not None and epss_score >= active_policy.high_epss_threshold) or (
        cvss is not None and cvss >= active_policy.high_cvss_threshold
    ):
        label = PriorityLabel.HIGH
    elif (cvss is not None and cvss >= active_policy.medium_cvss_threshold) or (
        epss_score is not None and epss_score >= active_policy.medium_epss_threshold
    ):
        label = PriorityLabel.MEDIUM
    else:
        label = PriorityLabel.LOW

    return label, PRIORITY_RANKS[label]


def build_priority_drivers(
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    policy: PriorityPolicy | None = None,
) -> list[str]:
    """Return structured priority rules that matched for this finding."""
    active_policy = policy or PriorityPolicy()
    drivers: list[str] = []
    cvss = nvd.cvss_base_score
    epss_score = epss.epss

    if kev.in_kev:
        drivers.append("kev")
    if (
        epss_score is not None
        and epss_score >= active_policy.critical_epss_threshold
        and cvss is not None
        and cvss >= active_policy.critical_cvss_threshold
    ):
        drivers.append("critical-epss-cvss")
    if epss_score is not None and epss_score >= active_policy.high_epss_threshold:
        drivers.append("high-epss")
    if cvss is not None and cvss >= active_policy.high_cvss_threshold:
        drivers.append("high-cvss")
    if cvss is not None and cvss >= active_policy.medium_cvss_threshold:
        drivers.append("medium-cvss")
    if epss_score is not None and epss_score >= active_policy.medium_epss_threshold:
        drivers.append("medium-epss")
    if not drivers:
        drivers.append("default-low")
    return drivers


def determine_cvss_only_priority(cvss_base_score: float | None) -> tuple[PriorityLabel, int]:
    """Apply the comparison baseline that only uses CVSS severity bands."""
    if cvss_base_score is not None and cvss_base_score >= 9.0:
        label = PriorityLabel.CRITICAL
    elif cvss_base_score is not None and cvss_base_score >= 7.0:
        label = PriorityLabel.HIGH
    elif cvss_base_score is not None and cvss_base_score >= 4.0:
        label = PriorityLabel.MEDIUM
    else:
        label = PriorityLabel.LOW

    return label, PRIORITY_RANKS[label]
