"""Offline governance rollups for persisted Workbench findings."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from sqlalchemy import inspect as sqlalchemy_inspect
from sqlalchemy.exc import NoInspectionAvailable
from sqlalchemy.orm.exc import DetachedInstanceError

from vuln_prioritizer.db.models import Asset, Finding, FindingOccurrence

RollupDimension = Literal["owner", "service"]

UNASSIGNED_OWNER = "Unassigned"
UNMAPPED_SERVICE = "Unmapped"
UNKNOWN_PRIORITY = "Unprioritized"

_CLOSED_STATUSES = {"accepted", "closed", "dismissed", "resolved", "suppressed"}
_PRIORITY_RANKS = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "informational": 5,
    "none": 6,
    "unprioritized": 99,
}


@dataclass(frozen=True, slots=True)
class GovernanceRollup:
    """Governance counts for one owner or business service bucket."""

    dimension: RollupDimension
    label: str
    finding_count: int
    actionable_count: int
    critical_count: int
    high_count: int
    kev_count: int
    attack_mapped_count: int
    waived_count: int
    suppressed_by_vex_count: int
    waiver_review_due_count: int
    expired_waiver_count: int
    under_investigation_count: int
    highest_priority: str
    priority_counts: dict[str, int] = field(default_factory=dict)
    status_counts: dict[str, int] = field(default_factory=dict)
    top_cves: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class WaiverLifecycleSummary:
    """Lifecycle counts derived from persisted waiver state."""

    total_findings: int
    waived_count: int
    active_count: int
    review_due_count: int
    expired_count: int
    unwaived_count: int
    unknown_status_count: int
    by_status: dict[str, int] = field(default_factory=dict)
    waiver_owner_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class VexSummary:
    """VEX coverage and suppression counts for persisted findings."""

    total_findings: int
    suppressed_findings: int
    unsuppressed_findings: int
    under_investigation_findings: int
    findings_with_vex_status: int
    status_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class WorkbenchGovernanceSummary:
    """Combined governance helper result for Workbench dashboards or exports."""

    total_findings: int
    owner_rollups: list[GovernanceRollup] = field(default_factory=list)
    service_rollups: list[GovernanceRollup] = field(default_factory=list)
    waiver_lifecycle: WaiverLifecycleSummary = field(
        default_factory=lambda: WaiverLifecycleSummary(
            total_findings=0,
            waived_count=0,
            active_count=0,
            review_due_count=0,
            expired_count=0,
            unwaived_count=0,
            unknown_status_count=0,
        )
    )
    vex: VexSummary = field(
        default_factory=lambda: VexSummary(
            total_findings=0,
            suppressed_findings=0,
            unsuppressed_findings=0,
            under_investigation_findings=0,
            findings_with_vex_status=0,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_governance_summary(
    findings: Iterable[Finding],
    *,
    limit: int | None = None,
    top_cves: int = 5,
) -> WorkbenchGovernanceSummary:
    """Build all Workbench governance rollups from already-loaded Finding rows."""
    finding_rows = list(findings)
    return WorkbenchGovernanceSummary(
        total_findings=len(finding_rows),
        owner_rollups=compute_owner_rollups(finding_rows, limit=limit, top_cves=top_cves),
        service_rollups=compute_service_rollups(finding_rows, limit=limit, top_cves=top_cves),
        waiver_lifecycle=summarize_waiver_lifecycle(finding_rows),
        vex=summarize_vex(finding_rows),
    )


def build_workbench_governance_summary(
    findings: Iterable[Finding],
    *,
    limit: int | None = None,
    top_cves: int = 5,
) -> WorkbenchGovernanceSummary:
    """Alias with the module name for callers that prefer explicit Workbench naming."""
    return build_governance_summary(findings, limit=limit, top_cves=top_cves)


def compute_owner_rollups(
    findings: Iterable[Finding],
    *,
    limit: int | None = None,
    top_cves: int = 5,
) -> list[GovernanceRollup]:
    """Roll findings up by asset owner, falling back to an unassigned bucket."""
    return _compute_rollups(
        list(findings),
        dimension="owner",
        label_getter=_owner_labels,
        limit=limit,
        top_cves=top_cves,
    )


def compute_service_rollups(
    findings: Iterable[Finding],
    *,
    limit: int | None = None,
    top_cves: int = 5,
) -> list[GovernanceRollup]:
    """Roll findings up by business service, falling back to an unmapped bucket."""
    return _compute_rollups(
        list(findings),
        dimension="service",
        label_getter=_service_labels,
        limit=limit,
        top_cves=top_cves,
    )


def summarize_waiver_lifecycle(findings: Iterable[Finding]) -> WaiverLifecycleSummary:
    """Summarize active, review-due, expired, and missing waiver state."""
    finding_rows = list(findings)
    status_counts: Counter[str] = Counter()
    owner_counts: Counter[str] = Counter()
    waived_count = 0
    active_count = 0
    review_due_count = 0
    expired_count = 0
    unwaived_count = 0
    unknown_status_count = 0

    for finding in finding_rows:
        payload = _finding_payload(finding)
        waived = _is_waived(finding, payload=payload)
        if waived:
            waived_count += 1

        waiver_owner = _string_or_none(getattr(finding, "waiver_owner", None)) or _string_or_none(
            payload.get("waiver_owner")
        )
        if waiver_owner is not None:
            owner_counts[waiver_owner] += 1

        status = _waiver_status(finding, payload=payload)
        if status is None:
            unwaived_count += 1
            continue

        status_counts[status] += 1
        if status == "active":
            active_count += 1
        elif status == "review_due":
            review_due_count += 1
        elif status == "expired":
            expired_count += 1
        else:
            unknown_status_count += 1

    return WaiverLifecycleSummary(
        total_findings=len(finding_rows),
        waived_count=waived_count,
        active_count=active_count,
        review_due_count=review_due_count,
        expired_count=expired_count,
        unwaived_count=unwaived_count,
        unknown_status_count=unknown_status_count,
        by_status=_sorted_counter(status_counts),
        waiver_owner_counts=_sorted_counter(owner_counts),
    )


def summarize_vex(findings: Iterable[Finding]) -> VexSummary:
    """Summarize VEX suppression and occurrence-level VEX statuses."""
    finding_rows = list(findings)
    status_counts: Counter[str] = Counter()
    suppressed_findings = 0
    under_investigation_findings = 0
    findings_with_vex_status = 0

    for finding in finding_rows:
        payload = _finding_payload(finding)
        finding_statuses = _vex_status_counts(finding, payload=payload)
        if finding_statuses:
            findings_with_vex_status += 1
            status_counts.update(finding_statuses)
        if _is_suppressed_by_vex(finding, payload=payload):
            suppressed_findings += 1
        if _is_under_investigation(finding, payload=payload, statuses=finding_statuses):
            under_investigation_findings += 1

    return VexSummary(
        total_findings=len(finding_rows),
        suppressed_findings=suppressed_findings,
        unsuppressed_findings=len(finding_rows) - suppressed_findings,
        under_investigation_findings=under_investigation_findings,
        findings_with_vex_status=findings_with_vex_status,
        status_counts=_sorted_counter(status_counts),
    )


def _compute_rollups(
    findings: list[Finding],
    *,
    dimension: RollupDimension,
    label_getter: Any,
    limit: int | None,
    top_cves: int,
) -> list[GovernanceRollup]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for label in label_getter(finding):
            grouped[label].append(finding)

    rollups = [
        _build_rollup(
            dimension=dimension,
            label=label,
            findings=bucket_findings,
            top_cves=top_cves,
        )
        for label, bucket_findings in grouped.items()
    ]
    rollups.sort(key=_rollup_sort_key)
    if limit is not None:
        return rollups[: max(limit, 0)]
    return rollups


def _build_rollup(
    *,
    dimension: RollupDimension,
    label: str,
    findings: list[Finding],
    top_cves: int,
) -> GovernanceRollup:
    priority_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    actionable_count = 0
    critical_count = 0
    high_count = 0
    kev_count = 0
    attack_mapped_count = 0
    waived_count = 0
    suppressed_by_vex_count = 0
    waiver_review_due_count = 0
    expired_waiver_count = 0
    under_investigation_count = 0

    for finding in findings:
        payload = _finding_payload(finding)
        priority = _priority_label(finding, payload=payload)
        status = _finding_status(finding, payload=payload)
        waiver_status = _waiver_status(finding, payload=payload)

        priority_counts[priority] += 1
        status_counts[status] += 1
        if _is_actionable(finding, payload=payload):
            actionable_count += 1
        if priority == "Critical":
            critical_count += 1
        elif priority == "High":
            high_count += 1
        if bool(getattr(finding, "in_kev", False) or payload.get("in_kev")):
            kev_count += 1
        if bool(getattr(finding, "attack_mapped", False) or payload.get("attack_mapped")):
            attack_mapped_count += 1
        if _is_waived(finding, payload=payload):
            waived_count += 1
        if _is_suppressed_by_vex(finding, payload=payload):
            suppressed_by_vex_count += 1
        if waiver_status == "review_due":
            waiver_review_due_count += 1
        elif waiver_status == "expired":
            expired_waiver_count += 1
        if _is_under_investigation(
            finding,
            payload=payload,
            statuses=_vex_status_counts(finding, payload=payload),
        ):
            under_investigation_count += 1

    ranked_findings = sorted(findings, key=_finding_sort_key)
    top_cve_values = _top_cves(ranked_findings, limit=top_cves)
    highest_priority = _priority_label(ranked_findings[0]) if ranked_findings else UNKNOWN_PRIORITY

    return GovernanceRollup(
        dimension=dimension,
        label=label,
        finding_count=len(findings),
        actionable_count=actionable_count,
        critical_count=critical_count,
        high_count=high_count,
        kev_count=kev_count,
        attack_mapped_count=attack_mapped_count,
        waived_count=waived_count,
        suppressed_by_vex_count=suppressed_by_vex_count,
        waiver_review_due_count=waiver_review_due_count,
        expired_waiver_count=expired_waiver_count,
        under_investigation_count=under_investigation_count,
        highest_priority=highest_priority,
        priority_counts=_sorted_counter(priority_counts),
        status_counts=_sorted_counter(status_counts),
        top_cves=top_cve_values,
    )


def _owner_labels(finding: Finding) -> list[str]:
    labels: list[str] = []
    asset = _loaded_relationship(finding, "asset")
    if isinstance(asset, Asset):
        _append_text(labels, asset.owner)
    for occurrence in _occurrence_payloads(finding):
        _append_text(labels, occurrence.get("asset_owner"))
    return _dedupe(labels) or [UNASSIGNED_OWNER]


def _service_labels(finding: Finding) -> list[str]:
    labels: list[str] = []
    asset = _loaded_relationship(finding, "asset")
    if isinstance(asset, Asset):
        _append_text(labels, asset.business_service)
    for occurrence in _occurrence_payloads(finding):
        _append_text(labels, occurrence.get("asset_business_service"))
    return _dedupe(labels) or [UNMAPPED_SERVICE]


def _finding_payload(finding: Finding) -> dict[str, Any]:
    finding_json = getattr(finding, "finding_json", None)
    if isinstance(finding_json, dict) and finding_json:
        return finding_json
    explanation_json = getattr(finding, "explanation_json", None)
    if isinstance(explanation_json, dict):
        return explanation_json
    return {}


def _occurrence_payloads(finding: Finding) -> list[dict[str, Any]]:
    payload = _finding_payload(finding)
    provenance = payload.get("provenance")
    occurrences = provenance.get("occurrences") if isinstance(provenance, dict) else None
    if isinstance(occurrences, list) and occurrences:
        return [item for item in occurrences if isinstance(item, dict)]

    related = _loaded_relationship(finding, "occurrences")
    if not isinstance(related, list):
        return []
    payloads: list[dict[str, Any]] = []
    for occurrence in related:
        if not isinstance(occurrence, FindingOccurrence):
            continue
        evidence = occurrence.evidence_json
        if isinstance(evidence, dict):
            payloads.append(evidence)
    return payloads


def _loaded_relationship(finding: Finding, name: str) -> Any:
    try:
        state = sqlalchemy_inspect(finding)
    except NoInspectionAvailable:
        return getattr(finding, name, None)

    if name in state.unloaded:
        return None
    try:
        return getattr(finding, name, None)
    except DetachedInstanceError:
        return None


def _priority_label(finding: Finding, *, payload: dict[str, Any] | None = None) -> str:
    payload = payload if payload is not None else _finding_payload(finding)
    label = (
        _string_or_none(getattr(finding, "priority", None))
        or _string_or_none(payload.get("priority_label"))
        or UNKNOWN_PRIORITY
    )
    normalized = label.casefold()
    if normalized in _PRIORITY_RANKS:
        return " ".join(part.capitalize() for part in normalized.split())
    return label


def _priority_rank(finding: Finding) -> int:
    raw_rank = getattr(finding, "priority_rank", None)
    if isinstance(raw_rank, int):
        return raw_rank
    payload = _finding_payload(finding)
    payload_rank = payload.get("priority_rank")
    if isinstance(payload_rank, int):
        return payload_rank
    priority = _priority_label(finding, payload=payload).casefold()
    return _PRIORITY_RANKS.get(priority, 99)


def _finding_status(finding: Finding, *, payload: dict[str, Any] | None = None) -> str:
    payload = payload if payload is not None else _finding_payload(finding)
    status = _status_key(getattr(finding, "status", None) or payload.get("status"))
    if status is not None:
        return status
    if _is_suppressed_by_vex(finding, payload=payload):
        return "suppressed"
    if _is_waived(finding, payload=payload):
        return "accepted"
    return "open"


def _waiver_status(finding: Finding, *, payload: dict[str, Any] | None = None) -> str | None:
    payload = payload if payload is not None else _finding_payload(finding)
    status = _status_key(getattr(finding, "waiver_status", None))
    if status is not None:
        return status
    status = _status_key(payload.get("waiver_status"))
    if status is not None:
        return status
    if _is_waived(finding, payload=payload):
        return "active"
    return None


def _is_actionable(finding: Finding, *, payload: dict[str, Any] | None = None) -> bool:
    payload = payload if payload is not None else _finding_payload(finding)
    if _is_waived(finding, payload=payload) or _is_suppressed_by_vex(finding, payload=payload):
        return False
    return _finding_status(finding, payload=payload) not in _CLOSED_STATUSES


def _is_waived(finding: Finding, *, payload: dict[str, Any] | None = None) -> bool:
    payload = payload if payload is not None else _finding_payload(finding)
    return bool(getattr(finding, "waived", False) or payload.get("waived"))


def _is_suppressed_by_vex(finding: Finding, *, payload: dict[str, Any] | None = None) -> bool:
    payload = payload if payload is not None else _finding_payload(finding)
    return bool(getattr(finding, "suppressed_by_vex", False) or payload.get("suppressed_by_vex"))


def _is_under_investigation(
    finding: Finding,
    *,
    payload: dict[str, Any] | None = None,
    statuses: Counter[str] | None = None,
) -> bool:
    payload = payload if payload is not None else _finding_payload(finding)
    if bool(getattr(finding, "under_investigation", False)):
        return True
    if bool(payload.get("under_investigation")):
        return True
    status_counts = (
        statuses if statuses is not None else _vex_status_counts(finding, payload=payload)
    )
    return status_counts.get("under_investigation", 0) > 0


def _vex_status_counts(finding: Finding, *, payload: dict[str, Any] | None = None) -> Counter[str]:
    payload = payload if payload is not None else _finding_payload(finding)
    provenance = payload.get("provenance")
    raw_statuses = provenance.get("vex_statuses") if isinstance(provenance, dict) else None
    counts: Counter[str] = Counter()
    if isinstance(raw_statuses, dict):
        for raw_status, raw_count in raw_statuses.items():
            status = _status_key(raw_status)
            if status is None:
                continue
            counts[status] += _positive_int(raw_count, default=1)
        if counts:
            return counts

    for occurrence in _occurrence_payloads(finding):
        status = _status_key(occurrence.get("vex_status"))
        if status is not None:
            counts[status] += 1
    return counts


def _top_cves(findings: list[Finding], *, limit: int) -> list[str]:
    if limit <= 0:
        return []
    values: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        cve_id = _string_or_none(getattr(finding, "cve_id", None))
        if cve_id is None or cve_id in seen:
            continue
        values.append(cve_id)
        seen.add(cve_id)
        if len(values) >= limit:
            break
    return values


def _finding_sort_key(finding: Finding) -> tuple[object, ...]:
    payload = _finding_payload(finding)
    return (
        0 if _is_actionable(finding, payload=payload) else 1,
        _priority_rank(finding),
        0 if bool(getattr(finding, "in_kev", False) or payload.get("in_kev")) else 1,
        -_float_value(getattr(finding, "risk_score", None)),
        -_float_value(getattr(finding, "epss", None) or payload.get("epss")),
        -_float_value(getattr(finding, "cvss_base_score", None) or payload.get("cvss_base_score")),
        _string_or_none(getattr(finding, "cve_id", None)) or "",
    )


def _rollup_sort_key(rollup: GovernanceRollup) -> tuple[object, ...]:
    return (
        0 if rollup.actionable_count else 1,
        _PRIORITY_RANKS.get(rollup.highest_priority.casefold(), 99),
        -rollup.critical_count,
        -rollup.high_count,
        -rollup.kev_count,
        -rollup.attack_mapped_count,
        -rollup.finding_count,
        rollup.label.casefold(),
    )


def _append_text(values: list[str], value: object) -> None:
    text = _string_or_none(value)
    if text is not None:
        values.append(text)


def _dedupe(values: Iterable[str]) -> list[str]:
    deduped: dict[str, str] = {}
    for value in values:
        normalized = value.casefold()
        deduped.setdefault(normalized, value)
    return sorted(deduped.values(), key=str.casefold)


def _string_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text or None


def _status_key(value: object) -> str | None:
    text = _string_or_none(value)
    if text is None:
        return None
    return text.casefold().replace("-", "_").replace(" ", "_")


def _positive_int(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value if value > 0 else default
    if isinstance(value, float):
        return int(value) if value > 0 else default
    if isinstance(value, str) and value.isdecimal():
        parsed = int(value)
        return parsed if parsed > 0 else default
    return default


def _float_value(value: object) -> float:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    return 0.0


def _sorted_counter(counter: Counter[str]) -> dict[str, int]:
    return {
        key: count for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    }


__all__ = [
    "GovernanceRollup",
    "VexSummary",
    "WaiverLifecycleSummary",
    "WorkbenchGovernanceSummary",
    "build_governance_summary",
    "build_workbench_governance_summary",
    "compute_owner_rollups",
    "compute_service_rollups",
    "summarize_vex",
    "summarize_waiver_lifecycle",
]
