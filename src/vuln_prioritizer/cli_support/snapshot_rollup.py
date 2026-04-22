"""Snapshot and rollup CLI support helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from vuln_prioritizer.models import (
    RemediationPlan,
    RollupBucket,
    RollupCandidate,
    SnapshotDiffItem,
    SnapshotDiffSummary,
)

from .common import RollupBy, exit_input_validation


def load_json_document_or_exit(input_path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        exit_input_validation(f"{input_path} is not valid JSON: {exc.msg}.")
    if not isinstance(payload, dict):
        exit_input_validation(f"{input_path} must contain a top-level JSON object.")
    return payload


def load_snapshot_payload(input_path: Path) -> dict[str, Any]:
    payload = load_json_document_or_exit(input_path)
    metadata = payload.get("metadata")
    findings = payload.get("findings")
    if (
        not isinstance(metadata, dict)
        or not isinstance(findings, list)
        or metadata.get("snapshot_kind") != "snapshot"
    ):
        exit_input_validation(
            "snapshot diff expects JSON files produced by `snapshot create --format json`."
        )
    return payload


def load_rollup_payload(input_path: Path) -> tuple[str, dict[str, Any]]:
    payload = load_json_document_or_exit(input_path)
    metadata = payload.get("metadata")
    findings = payload.get("findings")
    if not isinstance(metadata, dict) or not isinstance(findings, list):
        exit_input_validation("rollup expects an analysis JSON export or a snapshot JSON export.")
    metadata_dict = cast(dict[str, Any], metadata)
    input_kind = "snapshot" if metadata_dict.get("snapshot_kind") == "snapshot" else "analysis"
    return input_kind, payload


def build_snapshot_diff(
    before_payload: dict[str, Any],
    after_payload: dict[str, Any],
    *,
    include_unchanged: bool,
) -> tuple[list[SnapshotDiffItem], SnapshotDiffSummary]:
    before_findings = {item["cve_id"]: item for item in before_payload["findings"]}
    after_findings = {item["cve_id"]: item for item in after_payload["findings"]}
    counters = {
        "added": 0,
        "removed": 0,
        "priority_up": 0,
        "priority_down": 0,
        "context_changed": 0,
        "unchanged": 0,
    }
    items: list[SnapshotDiffItem] = []

    for cve_id in sorted(set(before_findings) | set(after_findings)):
        before = before_findings.get(cve_id)
        after = after_findings.get(cve_id)
        if before is None:
            counters["added"] += 1
            items.append(build_snapshot_diff_item(cve_id, "added", None, after, []))
            continue
        if after is None:
            counters["removed"] += 1
            items.append(build_snapshot_diff_item(cve_id, "removed", before, None, []))
            continue

        before_rank = int(before.get("priority_rank", 99))
        after_rank = int(after.get("priority_rank", 99))
        if after_rank < before_rank:
            counters["priority_up"] += 1
            items.append(build_snapshot_diff_item(cve_id, "priority_up", before, after, []))
            continue
        if after_rank > before_rank:
            counters["priority_down"] += 1
            items.append(build_snapshot_diff_item(cve_id, "priority_down", before, after, []))
            continue

        changed_fields = find_snapshot_context_changes(before, after)
        if changed_fields:
            counters["context_changed"] += 1
            items.append(
                build_snapshot_diff_item(cve_id, "context_changed", before, after, changed_fields)
            )
            continue

        counters["unchanged"] += 1
        if include_unchanged:
            items.append(build_snapshot_diff_item(cve_id, "unchanged", before, after, []))

    items.sort(key=lambda item: (snapshot_category_order(item.category), item.cve_id))
    return items, SnapshotDiffSummary(**counters)


def build_snapshot_diff_item(
    cve_id: str,
    category: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    changed_fields: list[str],
) -> SnapshotDiffItem:
    return SnapshotDiffItem(
        cve_id=cve_id,
        category=category,
        before_priority=None if before is None else before.get("priority_label"),
        after_priority=None if after is None else after.get("priority_label"),
        before_rank=None if before is None else before.get("priority_rank"),
        after_rank=None if after is None else after.get("priority_rank"),
        before_targets=[] if before is None else before.get("provenance", {}).get("targets", []),
        after_targets=[] if after is None else after.get("provenance", {}).get("targets", []),
        before_asset_ids=[]
        if before is None
        else before.get("provenance", {}).get("asset_ids", []),
        after_asset_ids=[] if after is None else after.get("provenance", {}).get("asset_ids", []),
        before_services=[] if before is None else finding_services(before),
        after_services=[] if after is None else finding_services(after),
        context_change_fields=changed_fields,
    )


def find_snapshot_context_changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    changed: list[str] = []
    if before.get("in_kev") != after.get("in_kev"):
        changed.append("kev")
    if before.get("attack_mapped") != after.get("attack_mapped"):
        changed.append("attack_mapped")
    if before.get("attack_relevance") != after.get("attack_relevance"):
        changed.append("attack_relevance")
    if sorted(before.get("attack_techniques", [])) != sorted(after.get("attack_techniques", [])):
        changed.append("attack_techniques")
    if sorted(before.get("attack_tactics", [])) != sorted(after.get("attack_tactics", [])):
        changed.append("attack_tactics")
    if sorted(before.get("provenance", {}).get("targets", [])) != sorted(
        after.get("provenance", {}).get("targets", [])
    ):
        changed.append("targets")
    if sorted(before.get("provenance", {}).get("asset_ids", [])) != sorted(
        after.get("provenance", {}).get("asset_ids", [])
    ):
        changed.append("asset_ids")
    if finding_services(before) != finding_services(after):
        changed.append("services")
    if before.get("provenance", {}).get("vex_statuses", {}) != after.get("provenance", {}).get(
        "vex_statuses", {}
    ):
        changed.append("vex")
    return changed


def finding_services(finding: dict[str, Any]) -> list[str]:
    services = sorted(
        {
            occurrence.get("asset_business_service")
            for occurrence in finding.get("provenance", {}).get("occurrences", [])
            if occurrence.get("asset_business_service")
        }
    )
    return services


def snapshot_category_order(category: str) -> int:
    return {
        "added": 0,
        "removed": 1,
        "priority_up": 2,
        "priority_down": 3,
        "context_changed": 4,
        "unchanged": 5,
    }.get(category, 99)


def build_rollup_buckets(
    payload: dict[str, Any],
    *,
    dimension: str,
    top: int,
) -> list[RollupBucket]:
    by_bucket: dict[str, list[dict[str, Any]]] = {}
    for finding in payload.get("findings", []):
        bucket_names = rollup_bucket_names(finding, dimension=dimension)
        for bucket_name in bucket_names:
            by_bucket.setdefault(bucket_name, []).append(finding)

    provisional_buckets: list[RollupBucket] = []
    for bucket_name, findings in by_bucket.items():
        sorted_findings = sorted(findings, key=rollup_finding_sort_key)
        actionable_findings = [finding for finding in sorted_findings if not finding.get("waived")]
        ranking_findings = actionable_findings or sorted_findings
        top_candidates = [build_rollup_candidate(finding) for finding in sorted_findings[:top]]
        provisional_buckets.append(
            RollupBucket(
                bucket=bucket_name,
                dimension=dimension,
                actionable_count=len(actionable_findings),
                finding_count=len(findings),
                critical_count=sum(
                    1 for finding in findings if finding.get("priority_label") == "Critical"
                ),
                high_count=sum(
                    1 for finding in findings if finding.get("priority_label") == "High"
                ),
                kev_count=sum(1 for finding in findings if finding.get("in_kev")),
                attack_mapped_count=sum(1 for finding in findings if finding.get("attack_mapped")),
                waived_count=sum(1 for finding in findings if finding.get("waived")),
                waiver_review_due_count=sum(
                    1 for finding in findings if finding.get("waiver_status") == "review_due"
                ),
                expired_waiver_count=sum(
                    1 for finding in findings if finding.get("waiver_status") == "expired"
                ),
                internet_facing_count=sum(
                    1 for finding in findings if finding_is_internet_facing(finding)
                ),
                production_count=sum(1 for finding in findings if finding_is_production(finding)),
                highest_priority=str(ranking_findings[0].get("priority_label", "Low")),
                rank_reason=rollup_bucket_rank_reason(
                    findings=findings,
                    actionable_findings=actionable_findings,
                    highest_priority=str(ranking_findings[0].get("priority_label", "Low")),
                ),
                context_hints=rollup_bucket_context_hints(findings),
                top_cves=[candidate.cve_id for candidate in top_candidates],
                owners=finding_top_owners(findings, top=top),
                recommended_actions=finding_top_actions(findings, top=top),
                top_candidates=top_candidates,
            )
        )

    provisional_buckets.sort(key=rollup_bucket_sort_key)
    return [
        bucket.model_copy(update={"remediation_rank": remediation_rank})
        for remediation_rank, bucket in enumerate(provisional_buckets, start=1)
    ]


def rollup_bucket_names(finding: dict[str, Any], *, dimension: str) -> list[str]:
    if dimension == RollupBy.asset.value:
        asset_ids = finding.get("provenance", {}).get("asset_ids", [])
        return sorted(asset_ids) if asset_ids else ["Unmapped"]
    services = finding_services(finding)
    return services if services else ["Unmapped"]


def rollup_finding_sort_key(finding: dict[str, Any]) -> tuple[object, ...]:
    priority_rank = int(finding.get("priority_rank", 99))
    return (
        1 if finding.get("waived") else 0,
        priority_rank,
        0 if finding.get("in_kev") else 1,
        0 if finding_is_internet_facing(finding) else 1,
        0 if finding_is_production(finding) else 1,
        criticality_order(finding.get("highest_asset_criticality")),
        -float(finding.get("epss") or 0.0),
        -float(finding.get("cvss_base_score") or 0.0),
        str(finding.get("cve_id", "")),
    )


def rollup_bucket_sort_key(bucket: RollupBucket) -> tuple[object, ...]:
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(bucket.highest_priority, 99)
    return (
        0 if bucket.actionable_count > 0 else 1,
        rank,
        -bucket.kev_count,
        -bucket.internet_facing_count,
        -bucket.production_count,
        -bucket.critical_count,
        -bucket.actionable_count,
        -bucket.finding_count,
        bucket.bucket,
    )


def finding_top_owners(findings: list[dict[str, Any]], *, top: int) -> list[str]:
    counts: dict[str, int] = {}
    for finding in findings:
        owners = finding_owner_hints(finding)
        for owner in owners:
            counts[owner] = counts.get(owner, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [owner for owner, _ in ordered[:top]]


def finding_top_actions(findings: list[dict[str, Any]], *, top: int) -> list[str]:
    counts: dict[str, int] = {}
    for finding in findings:
        action = str(finding.get("recommended_action") or "").strip()
        if not action:
            continue
        counts[action] = counts.get(action, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [action for action, _ in ordered[:top]]


def build_rollup_candidate(finding: dict[str, Any]) -> RollupCandidate:
    return RollupCandidate(
        cve_id=str(finding.get("cve_id", "N.A.")),
        priority_label=str(finding.get("priority_label", "Low")),
        waived=bool(finding.get("waived")),
        waiver_status=string_or_none(finding.get("waiver_status")),
        in_kev=bool(finding.get("in_kev")),
        highest_asset_criticality=string_or_none(finding.get("highest_asset_criticality")),
        highest_asset_exposure=string_or_none(
            finding.get("provenance", {}).get("highest_asset_exposure")
        ),
        asset_ids=[
            str(asset_id)
            for asset_id in finding.get("provenance", {}).get("asset_ids", [])
            if asset_id
        ],
        services=finding_services(finding),
        owners=sorted(finding_owner_hints(finding)),
        remediation=RemediationPlan.model_validate(finding.get("remediation") or {}),
        recommended_action=str(finding.get("recommended_action") or "Review remediation options."),
        rank_reason=rollup_candidate_reason(finding),
    )


def rollup_bucket_context_hints(findings: list[dict[str, Any]]) -> list[str]:
    kev_count = sum(1 for finding in findings if finding.get("in_kev"))
    internet_facing_count = sum(1 for finding in findings if finding_is_internet_facing(finding))
    production_count = sum(1 for finding in findings if finding_is_production(finding))
    under_investigation_count = sum(1 for finding in findings if finding.get("under_investigation"))
    waiver_owners = sorted(
        {str(finding.get("waiver_owner")) for finding in findings if finding.get("waiver_owner")}
    )

    hints: list[str] = []
    if kev_count:
        hints.append(f"{kev_count} KEV")
    if internet_facing_count:
        hints.append(f"{internet_facing_count} internet-facing")
    if production_count:
        hints.append(f"{production_count} prod")
    if under_investigation_count:
        hints.append(f"{under_investigation_count} under investigation")
    if waiver_owners:
        hints.append("waiver owners: " + ", ".join(waiver_owners))
    review_due_count = sum(
        1 for finding in findings if finding.get("waiver_status") == "review_due"
    )
    expired_count = sum(1 for finding in findings if finding.get("waiver_status") == "expired")
    if review_due_count:
        hints.append(f"{review_due_count} waiver review due")
    if expired_count:
        hints.append(f"{expired_count} waiver expired")
    return hints


def rollup_bucket_rank_reason(
    *,
    findings: list[dict[str, Any]],
    actionable_findings: list[dict[str, Any]],
    highest_priority: str,
) -> str:
    kev_count = sum(1 for finding in actionable_findings if finding.get("in_kev"))
    internet_facing_count = sum(
        1 for finding in actionable_findings if finding_is_internet_facing(finding)
    )
    production_count = sum(1 for finding in actionable_findings if finding_is_production(finding))

    if not actionable_findings:
        return (
            "No actionable findings remain in this bucket; it is ranked after buckets with active "
            "remediation work."
        )

    signals = [f"highest actionable priority {highest_priority}"]
    if kev_count:
        signals.append(f"{kev_count} KEV finding(s)")
    if internet_facing_count:
        signals.append(f"{internet_facing_count} internet-facing finding(s)")
    if production_count:
        signals.append(f"{production_count} production finding(s)")
    if len(actionable_findings) != len(findings):
        signals.append(f"{len(findings) - len(actionable_findings)} waived finding(s)")
    expired_count = sum(1 for finding in findings if finding.get("waiver_status") == "expired")
    if expired_count:
        signals.append(f"{expired_count} expired waiver(s)")
    return "Ranked by " + ", ".join(signals) + "."


def rollup_candidate_reason(finding: dict[str, Any]) -> str:
    reasons = [str(finding.get("priority_label", "Low"))]
    if finding.get("in_kev"):
        reasons.append("KEV")
    if finding_is_internet_facing(finding):
        reasons.append("internet-facing")
    if finding_is_production(finding):
        reasons.append("prod")
    criticality = string_or_none(finding.get("highest_asset_criticality"))
    if criticality:
        reasons.append(f"{criticality} criticality")
    if finding.get("waiver_status") == "review_due":
        reasons.append("waiver review due")
    elif finding.get("waived"):
        waiver_owner = string_or_none(finding.get("waiver_owner"))
        reasons.append(f"waived by {waiver_owner}" if waiver_owner else "waived")
    elif finding.get("waiver_status") == "expired":
        reasons.append("waiver expired")
    return ", ".join(reasons)


def finding_owner_hints(finding: dict[str, Any]) -> set[str]:
    owners = {
        str(occurrence.get("asset_owner"))
        for occurrence in finding.get("provenance", {}).get("occurrences", [])
        if occurrence.get("asset_owner")
    }
    if finding.get("waiver_owner"):
        owners.add(str(finding.get("waiver_owner")))
    return owners


def finding_is_internet_facing(finding: dict[str, Any]) -> bool:
    highest_exposure = string_or_none(finding.get("provenance", {}).get("highest_asset_exposure"))
    if highest_exposure and highest_exposure.lower() == "internet-facing":
        return True
    return any(
        string_or_none(occurrence.get("asset_exposure"), lowercase=True) == "internet-facing"
        for occurrence in finding.get("provenance", {}).get("occurrences", [])
    )


def finding_is_production(finding: dict[str, Any]) -> bool:
    return any(
        string_or_none(occurrence.get("asset_environment"), lowercase=True)
        in {"prod", "production"}
        for occurrence in finding.get("provenance", {}).get("occurrences", [])
    )


def criticality_order(value: object) -> int:
    criticality = string_or_none(value, lowercase=True)
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(criticality or "", 4)


def string_or_none(value: object, *, lowercase: bool = False) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text.lower() if lowercase else text
