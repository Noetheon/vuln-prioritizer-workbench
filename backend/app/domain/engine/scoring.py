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
    SeverityProxy,
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


def effective_cvss(
    nvd: NvdData,
    severity_proxy: SeverityProxy | None = None,
) -> tuple[float | None, bool]:
    """Return the CVSS used by the base rule and whether a severity proxy supplied it."""
    if nvd.cvss_base_score is not None:
        return nvd.cvss_base_score, False
    if severity_proxy is not None:
        return severity_proxy.cvss_floor, True
    return None, False


def determine_priority(
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    policy: PriorityPolicy | None = None,
    *,
    severity_proxy: SeverityProxy | None = None,
) -> tuple[PriorityLabel, int]:
    """
    Apply the transparent CVSS/EPSS/KEV base priority rules.

    Without NVD CVSS, a source-reported severity band stands in at the lower
    bound of that band so unanalyzed CVEs are not silently ranked as Low.
    """
    active_policy = policy or PriorityPolicy()
    cvss, _ = effective_cvss(nvd, severity_proxy)
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
    *,
    severity_proxy: SeverityProxy | None = None,
) -> list[str]:
    """Return structured priority rules that matched for this finding."""
    active_policy = policy or PriorityPolicy()
    drivers: list[str] = []
    cvss, proxied = effective_cvss(nvd, severity_proxy)
    cvss_driver = "severity-proxy" if proxied else "cvss"
    epss_score = epss.epss

    if kev.in_kev:
        drivers.append("kev")
    if (
        epss_score is not None
        and epss_score >= active_policy.critical_epss_threshold
        and cvss is not None
        and cvss >= active_policy.critical_cvss_threshold
    ):
        drivers.append(f"critical-epss-{cvss_driver}")
    if epss_score is not None and epss_score >= active_policy.high_epss_threshold:
        drivers.append("high-epss")
    if cvss is not None and cvss >= active_policy.high_cvss_threshold:
        drivers.append(f"high-{cvss_driver}")
    if cvss is not None and cvss >= active_policy.medium_cvss_threshold:
        drivers.append(f"medium-{cvss_driver}")
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
