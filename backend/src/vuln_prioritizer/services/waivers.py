"""Risk-acceptance waiver loading and matching."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import yaml
from pydantic import ValidationError

from vuln_prioritizer.models import PrioritizedFinding, WaiverHealthSummary, WaiverRule
from vuln_prioritizer.utils import normalize_cve_id

DEFAULT_WAIVER_REVIEW_WINDOW_DAYS = 14


def load_waiver_rules(path: Path | None) -> list[WaiverRule]:
    """Load waiver rules from YAML."""
    if path is None:
        return []
    if not path.exists() or not path.is_file():
        raise ValueError(f"Waiver file does not exist: {path}")

    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"{path} is not valid YAML: {exc}") from exc

    if not isinstance(document, dict):
        raise ValueError(f"{path} must contain a top-level YAML object.")
    raw_rules = document.get("waivers")
    if not isinstance(raw_rules, list):
        raise ValueError(f"{path} must contain a top-level `waivers` list.")

    rules: list[WaiverRule] = []
    for index, raw_rule in enumerate(raw_rules, start=1):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"Waiver entry #{index} in {path} must be a YAML object.")
        normalized_cve = normalize_cve_id(raw_rule.get("cve_id"))
        if normalized_cve is None:
            raise ValueError(f"Waiver entry #{index} in {path} has an invalid CVE identifier.")
        rule_document = dict(raw_rule)
        rule_document["cve_id"] = normalized_cve
        for list_field in ("asset_ids", "targets", "services"):
            if list_field in rule_document:
                rule_document[list_field] = _normalize_scope_values(
                    rule_document[list_field],
                    field_name=list_field,
                    entry_index=index,
                    source_path=path,
                )
        if rule_document.get("expires_on") is not None:
            rule_document["expires_on"] = str(rule_document["expires_on"])
        if rule_document.get("review_on") is not None:
            rule_document["review_on"] = str(rule_document["review_on"])
        try:
            rule = WaiverRule.model_validate(rule_document)
        except ValidationError as exc:
            raise ValueError(f"Waiver entry #{index} in {path} is invalid: {exc}") from exc
        _validate_rule_dates(rule, source_path=path)
        rules.append(rule)
    _validate_unique_rule_ids(rules, source_path=path)
    return rules


def summarize_waiver_rules(
    rules: list[WaiverRule],
    *,
    today: date | None = None,
    review_window_days: int = DEFAULT_WAIVER_REVIEW_WINDOW_DAYS,
) -> WaiverHealthSummary:
    """Summarize waiver lifecycle state across a waiver file."""
    active_date = today or datetime.now(UTC).date()
    summary = WaiverHealthSummary(
        total_rules=len(rules),
        review_window_days=review_window_days,
    )
    for rule in rules:
        status = waiver_rule_status(
            rule,
            today=active_date,
            review_window_days=review_window_days,
        )
        if status == "expired":
            summary = summary.model_copy(update={"expired_count": summary.expired_count + 1})
        elif status == "review_due":
            summary = summary.model_copy(update={"review_due_count": summary.review_due_count + 1})
        else:
            summary = summary.model_copy(update={"active_count": summary.active_count + 1})
    return summary


def waiver_rule_status(
    rule: WaiverRule,
    *,
    today: date,
    review_window_days: int = DEFAULT_WAIVER_REVIEW_WINDOW_DAYS,
) -> str:
    """Return `active`, `review_due`, or `expired` for a waiver rule."""
    expires_on = _expires_on(rule)
    if expires_on < today:
        return "expired"

    review_on = _review_on(rule)
    if review_on is not None and review_on <= today:
        return "review_due"

    if expires_on <= today + timedelta(days=review_window_days):
        return "review_due"

    return "active"


def apply_waivers(
    findings: list[PrioritizedFinding],
    rules: list[WaiverRule],
    *,
    today: date | None = None,
) -> tuple[list[PrioritizedFinding], list[str]]:
    """Apply the best matching waiver lifecycle state per finding."""
    if not rules:
        return findings, []

    active_date = today or datetime.now(UTC).date()
    warnings: list[str] = []
    by_cve: dict[str, list[WaiverRule]] = {}
    matched_rule_labels: set[str] = set()
    for rule in rules:
        by_cve.setdefault(rule.cve_id, []).append(rule)
        if _waiver_scope(rule) == "global":
            warnings.append(
                f"Global waiver {_waiver_label(rule)} for {rule.cve_id} can match every asset "
                "scope for that CVE."
            )

    updated_findings: list[PrioritizedFinding] = []
    for finding in findings:
        candidates = by_cve.get(finding.cve_id, [])
        matching_active: list[tuple[WaiverRule, str]] = []
        matching_expired: list[WaiverRule] = []
        for rule in candidates:
            if not _waiver_matches_finding(rule, finding):
                continue
            matched_rule_labels.add(_waiver_label(rule))
            status = waiver_rule_status(rule, today=active_date)
            if status == "expired":
                matching_expired.append(rule)
            else:
                matching_active.append((rule, status))

        if not matching_active:
            if matching_expired:
                matching_expired.sort(key=_waiver_sort_key)
                selected = matching_expired[0]
                if len(matching_expired) > 1:
                    ignored = ", ".join(_waiver_label(rule) for rule in matching_expired[1:])
                    warnings.append(
                        f"Multiple expired waivers matched {finding.cve_id}; using "
                        f"{_waiver_label(selected)} for reporting and ignoring {ignored}."
                    )
                else:
                    warnings.append(
                        f"Matched expired waiver {_waiver_label(selected)} for {finding.cve_id}."
                    )
                updated_findings.append(_apply_expired_waiver(finding, selected, today=active_date))
                continue
            updated_findings.append(finding)
            continue

        matching_active.sort(key=lambda item: _waiver_sort_key(item[0]))
        selected, selected_status = matching_active[0]
        if len(matching_active) > 1:
            ignored = ", ".join(_waiver_label(rule) for rule, _ in matching_active[1:])
            warnings.append(
                f"Multiple active waivers matched {finding.cve_id}; using "
                f"{_waiver_label(selected)} and ignoring {ignored}."
            )
        if selected_status == "review_due":
            warnings.append(f"Waiver {_waiver_label(selected)} for {finding.cve_id} is review due.")
        updated_findings.append(
            _apply_single_waiver(
                finding,
                selected,
                today=active_date,
                status=selected_status,
            )
        )

    unmatched_labels = [
        _waiver_label(rule) for rule in rules if _waiver_label(rule) not in matched_rule_labels
    ]
    for label in unmatched_labels:
        warnings.append(f"Waiver {label} did not match any finding.")

    return updated_findings, warnings


def _validate_rule_dates(rule: WaiverRule, *, source_path: Path) -> None:
    try:
        _expires_on(rule)
    except ValueError as exc:
        raise ValueError(
            f"Waiver {_waiver_label(rule)} in {source_path} has an invalid expires_on date."
        ) from exc
    if rule.review_on is not None:
        try:
            review_on = _review_on(rule)
        except ValueError as exc:
            raise ValueError(
                f"Waiver {_waiver_label(rule)} in {source_path} has an invalid review_on date."
            ) from exc
        expires_on = _expires_on(rule)
        if review_on is not None and review_on > expires_on:
            raise ValueError(
                f"Waiver {_waiver_label(rule)} in {source_path} has review_on after expires_on."
            )


def _expires_on(rule: WaiverRule) -> date:
    return date.fromisoformat(rule.expires_on)


def _review_on(rule: WaiverRule) -> date | None:
    if rule.review_on is None:
        return None
    return date.fromisoformat(rule.review_on)


def _waiver_matches_finding(rule: WaiverRule, finding: PrioritizedFinding) -> bool:
    finding_asset_ids = _normalized_set(finding.provenance.asset_ids)
    if rule.asset_ids and not _normalized_set(rule.asset_ids).intersection(finding_asset_ids):
        return False
    finding_targets = _normalized_set(finding.provenance.targets)
    if rule.targets and not _normalized_set(rule.targets).intersection(finding_targets):
        return False
    finding_services = {
        occurrence.asset_business_service
        for occurrence in finding.provenance.occurrences
        if occurrence.asset_business_service
    }
    if rule.services and not _normalized_set(rule.services).intersection(
        _normalized_set(finding_services)
    ):
        return False
    return True


def _validate_unique_rule_ids(rules: list[WaiverRule], *, source_path: Path) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for rule in rules:
        if not rule.id:
            continue
        normalized = rule.id.casefold()
        if normalized in seen:
            duplicates.add(rule.id)
        seen.add(normalized)
    if duplicates:
        raise ValueError(
            f"{source_path} contains duplicate waiver id(s): " + ", ".join(sorted(duplicates)) + "."
        )


def _normalize_scope_values(
    value: object,
    *,
    field_name: str,
    entry_index: int,
    source_path: Path,
) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(
            f"Waiver entry #{entry_index} in {source_path} has invalid {field_name}: "
            "expected a list."
        )
    normalized: list[str] = []
    for item in value:
        if item is None:
            continue
        text = str(item).strip()
        if text and text not in normalized:
            normalized.append(text)
    return normalized


def _normalized_set(values: object) -> set[str]:
    if not isinstance(values, list | set | tuple):
        return set()
    return {str(value).strip().casefold() for value in values if str(value).strip()}


def _apply_single_waiver(
    finding: PrioritizedFinding,
    rule: WaiverRule,
    *,
    today: date,
    status: str,
) -> PrioritizedFinding:
    days_remaining = (_expires_on(rule) - today).days
    status_note = "review due" if status == "review_due" else "active"
    waiver_note = (
        f"Waiver {_waiver_label(rule)} owned by {rule.owner} is {status_note} and expires on "
        f"{rule.expires_on}: {rule.reason.rstrip('.')}."
    )
    if status == "review_due":
        context_note = (
            f"Waiver review is due for {rule.owner}; confirm the acceptance before "
            f"{rule.expires_on}."
        )
    else:
        context_note = (
            f"Waiver active for {rule.owner} until {rule.expires_on}; review the acceptance "
            "before expiry."
        )
    existing_context = finding.context_recommendation or ""
    context_recommendation = (
        f"{existing_context.rstrip('.')} {context_note}".strip()
        if existing_context
        else context_note
    )
    return finding.model_copy(
        update={
            "waived": True,
            "waiver_status": status,
            "waiver_reason": rule.reason,
            "waiver_owner": rule.owner,
            "waiver_expires_on": rule.expires_on,
            "waiver_review_on": rule.review_on,
            "waiver_days_remaining": days_remaining,
            "waiver_scope": _waiver_scope(rule),
            "waiver_id": rule.id,
            "waiver_matched_scope": _waiver_scope(rule),
            "waiver_approval_ref": rule.approval_ref,
            "waiver_ticket_url": rule.ticket_url,
            "rationale": f"{finding.rationale.rstrip('.')} {waiver_note}",
            "context_recommendation": context_recommendation,
        }
    )


def _apply_expired_waiver(
    finding: PrioritizedFinding,
    rule: WaiverRule,
    *,
    today: date,
) -> PrioritizedFinding:
    days_remaining = (_expires_on(rule) - today).days
    waiver_note = (
        f"Waiver {_waiver_label(rule)} owned by {rule.owner} expired on {rule.expires_on}: "
        f"{rule.reason.rstrip('.')}."
    )
    context_note = f"Waiver expired on {rule.expires_on}; reassess the risk acceptance immediately."
    existing_context = finding.context_recommendation or ""
    context_recommendation = (
        f"{existing_context.rstrip('.')} {context_note}".strip()
        if existing_context
        else context_note
    )
    return finding.model_copy(
        update={
            "waived": False,
            "waiver_status": "expired",
            "waiver_reason": rule.reason,
            "waiver_owner": rule.owner,
            "waiver_expires_on": rule.expires_on,
            "waiver_review_on": rule.review_on,
            "waiver_days_remaining": days_remaining,
            "waiver_scope": _waiver_scope(rule),
            "waiver_id": rule.id,
            "waiver_matched_scope": _waiver_scope(rule),
            "waiver_approval_ref": rule.approval_ref,
            "waiver_ticket_url": rule.ticket_url,
            "rationale": f"{finding.rationale.rstrip('.')} {waiver_note}",
            "context_recommendation": context_recommendation,
        }
    )


def _waiver_label(rule: WaiverRule) -> str:
    return rule.id or f"{rule.cve_id}:{rule.owner}:{rule.expires_on}"


def _waiver_scope(rule: WaiverRule) -> str:
    parts: list[str] = []
    if rule.asset_ids:
        parts.append("asset_ids=" + ",".join(rule.asset_ids))
    if rule.targets:
        parts.append("targets=" + ",".join(rule.targets))
    if rule.services:
        parts.append("services=" + ",".join(rule.services))
    if not parts:
        return "global"
    return "; ".join(parts)


def _waiver_sort_key(rule: WaiverRule) -> tuple[int, int, str, str]:
    specificity = sum(1 for values in (rule.asset_ids, rule.targets, rule.services) if values)
    total_scope_values = len(rule.asset_ids) + len(rule.targets) + len(rule.services)
    return (-specificity, -total_scope_values, rule.expires_on, _waiver_label(rule))
