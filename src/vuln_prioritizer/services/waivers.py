"""Risk-acceptance waiver loading and matching."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from vuln_prioritizer.models import PrioritizedFinding, WaiverRule
from vuln_prioritizer.utils import normalize_cve_id


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
        if rule_document.get("expires_on") is not None:
            rule_document["expires_on"] = str(rule_document["expires_on"])
        try:
            rule = WaiverRule.model_validate(rule_document)
        except ValidationError as exc:
            raise ValueError(f"Waiver entry #{index} in {path} is invalid: {exc}") from exc
        _validate_rule_dates(rule, source_path=path)
        rules.append(rule)
    return rules


def apply_waivers(
    findings: list[PrioritizedFinding],
    rules: list[WaiverRule],
    *,
    today: date | None = None,
) -> tuple[list[PrioritizedFinding], list[str]]:
    """Apply the best matching active waiver per finding."""
    if not rules:
        return findings, []

    active_date = today or datetime.now(UTC).date()
    warnings: list[str] = []
    by_cve: dict[str, list[WaiverRule]] = {}
    for rule in rules:
        by_cve.setdefault(rule.cve_id, []).append(rule)

    updated_findings: list[PrioritizedFinding] = []
    for finding in findings:
        candidates = by_cve.get(finding.cve_id, [])
        matching_active: list[WaiverRule] = []
        for rule in candidates:
            if _expires_on(rule) < active_date:
                if _waiver_matches_finding(rule, finding):
                    warnings.append(
                        f"Ignored expired waiver {_waiver_label(rule)} for {finding.cve_id}."
                    )
                continue
            if _waiver_matches_finding(rule, finding):
                matching_active.append(rule)

        if not matching_active:
            updated_findings.append(finding)
            continue

        matching_active.sort(key=_waiver_sort_key)
        selected = matching_active[0]
        if len(matching_active) > 1:
            ignored = ", ".join(_waiver_label(rule) for rule in matching_active[1:])
            warnings.append(
                f"Multiple active waivers matched {finding.cve_id}; using "
                f"{_waiver_label(selected)} and ignoring {ignored}."
            )
        updated_findings.append(_apply_single_waiver(finding, selected))

    return updated_findings, warnings


def _validate_rule_dates(rule: WaiverRule, *, source_path: Path) -> None:
    try:
        _expires_on(rule)
    except ValueError as exc:
        raise ValueError(
            f"Waiver {_waiver_label(rule)} in {source_path} has an invalid expires_on date."
        ) from exc


def _expires_on(rule: WaiverRule) -> date:
    return date.fromisoformat(rule.expires_on)


def _waiver_matches_finding(rule: WaiverRule, finding: PrioritizedFinding) -> bool:
    if rule.asset_ids and not set(rule.asset_ids).intersection(finding.provenance.asset_ids):
        return False
    if rule.targets and not set(rule.targets).intersection(finding.provenance.targets):
        return False
    finding_services = {
        occurrence.asset_business_service
        for occurrence in finding.provenance.occurrences
        if occurrence.asset_business_service
    }
    if rule.services and not set(rule.services).intersection(finding_services):
        return False
    return True


def _apply_single_waiver(finding: PrioritizedFinding, rule: WaiverRule) -> PrioritizedFinding:
    waiver_note = (
        f"Active waiver {_waiver_label(rule)} owned by {rule.owner} expires on "
        f"{rule.expires_on}: {rule.reason.rstrip('.')}."
    )
    context_note = (
        f"Waiver active for {rule.owner} until {rule.expires_on}; review the acceptance before "
        "expiry."
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
            "waiver_reason": rule.reason,
            "waiver_owner": rule.owner,
            "waiver_expires_on": rule.expires_on,
            "waiver_scope": _waiver_scope(rule),
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
