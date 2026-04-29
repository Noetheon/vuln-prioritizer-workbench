"""Detection-control and ATT&CK coverage helpers for Workbench routes."""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Any

import yaml
from fastapi import HTTPException

from vuln_prioritizer.api.workbench_waivers import _strip_or_none

DETECTION_COVERAGE_LEVELS = {"covered", "partial", "not_covered", "unknown", "not_applicable"}
DETECTION_REVIEW_STATUSES = {"unreviewed", "needs_review", "reviewed", "rejected", "stale"}
WEAK_DETECTION_COVERAGE_LEVELS = {"partial", "not_covered", "unknown"}


def _parse_detection_control_rows(filename: str, content: bytes) -> list[dict[str, Any]]:
    suffix = Path(filename).suffix.lower()
    if suffix == ".csv":
        text = content.decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text)))
    elif suffix in {".yml", ".yaml"}:
        document = yaml.safe_load(content.decode("utf-8")) or {}
        raw_rows = document.get("controls", document) if isinstance(document, dict) else document
        if not isinstance(raw_rows, list):
            raise HTTPException(
                status_code=422, detail="Detection controls YAML must contain a list."
            )
        rows = [row for row in raw_rows if isinstance(row, dict)]
    else:
        raise HTTPException(status_code=422, detail="Detection controls must be CSV or YAML.")
    parsed = [
        _detection_control_values(row, index=index) for index, row in enumerate(rows, start=1)
    ]
    if not parsed:
        raise HTTPException(status_code=422, detail="Detection controls file is empty.")
    return parsed


def _detection_control_values(row: dict[str, Any], *, index: int) -> dict[str, Any]:
    technique_id = _strip_or_none(str(row.get("technique_id") or row.get("technique") or ""))
    if technique_id is None or not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
        raise HTTPException(
            status_code=422,
            detail=f"Detection control row {index} has an invalid technique_id.",
        )
    coverage_level = _normalize_coverage_level(row.get("coverage_level") or row.get("coverage"))
    name = _strip_or_none(str(row.get("name") or row.get("control_name") or "")) or technique_id
    return {
        "control_id": _strip_or_none(str(row.get("id") or row.get("control_id") or "")),
        "name": name,
        "technique_id": technique_id,
        "technique_name": _strip_or_none(str(row.get("technique_name") or "")),
        "source_type": _strip_or_none(str(row.get("source_type") or "")),
        "coverage_level": coverage_level,
        "environment": _strip_or_none(str(row.get("environment") or "")),
        "owner": _strip_or_none(str(row.get("owner") or "")),
        "evidence_ref": _strip_or_none(str(row.get("evidence_ref") or "")),
        "evidence_refs_json": _normalize_evidence_refs(row.get("evidence_refs")),
        "review_status": _normalize_review_status(row.get("review_status")),
        "notes": _strip_or_none(str(row.get("notes") or "")),
        "last_verified_at": _strip_or_none(str(row.get("last_verified_at") or "")),
    }


def _normalize_coverage_level(value: object) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    if normalized not in DETECTION_COVERAGE_LEVELS:
        raise HTTPException(status_code=422, detail=f"Unsupported coverage level: {value!r}.")
    return normalized


def _normalize_review_status(value: object) -> str:
    normalized = str(value or "unreviewed").strip().lower().replace("-", "_").replace(" ", "_")
    if normalized not in DETECTION_REVIEW_STATUSES:
        raise HTTPException(status_code=422, detail=f"Unsupported review status: {value!r}.")
    return normalized


def _normalize_evidence_refs(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        raw_values = value
    else:
        raw_values = str(value).replace("\n", ",").split(",")
    refs = [str(item).strip() for item in raw_values if str(item).strip()]
    return list(dict.fromkeys(refs))


def _coverage_gap_payload(
    contexts: list[Any],
    controls: list[Any],
    findings: list[Any],
) -> dict[str, Any]:
    finding_by_id = {finding.id: finding for finding in findings}
    controls_by_technique: dict[str, list[Any]] = {}
    for control in controls:
        controls_by_technique.setdefault(control.technique_id, []).append(control)
    rollups: dict[str, dict[str, Any]] = {}
    for context in contexts:
        if not context.mapped:
            continue
        for technique in context.techniques_json or []:
            if not isinstance(technique, dict):
                continue
            technique_id = _technique_id_from_dict(technique)
            if technique_id is None:
                continue
            rollup = rollups.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "name": _technique_name_from_dict(technique),
                    "tactic_ids": _tactic_ids_from_dict(technique),
                    "finding_ids": set(),
                    "critical_finding_count": 0,
                    "kev_finding_count": 0,
                },
            )
            rollup["finding_ids"].add(context.finding_id)
            finding = finding_by_id.get(context.finding_id)
            if finding is not None and finding.priority.lower() == "critical":
                rollup["critical_finding_count"] += 1
            if finding is not None and finding.in_kev:
                rollup["kev_finding_count"] += 1
    for technique_id, technique_controls in controls_by_technique.items():
        if technique_id in rollups:
            continue
        first_control = technique_controls[0] if technique_controls else None
        rollups[technique_id] = {
            "technique_id": technique_id,
            "name": first_control.technique_name if first_control else None,
            "tactic_ids": [],
            "finding_ids": set(),
            "critical_finding_count": 0,
            "kev_finding_count": 0,
        }
    items = []
    for technique_id, rollup in sorted(rollups.items()):
        technique_controls = controls_by_technique.get(technique_id, [])
        coverage_level = _rollup_coverage_level(technique_controls)
        evidence_refs = [
            control.evidence_ref for control in technique_controls if control.evidence_ref
        ]
        owner = next((control.owner for control in technique_controls if control.owner), None)
        items.append(
            {
                "technique_id": technique_id,
                "name": rollup["name"],
                "tactic_ids": list(rollup["tactic_ids"]),
                "finding_count": len(rollup["finding_ids"]),
                "critical_finding_count": int(rollup["critical_finding_count"]),
                "kev_finding_count": int(rollup["kev_finding_count"]),
                "coverage_level": coverage_level,
                "control_count": len(technique_controls),
                "owner": owner,
                "evidence_refs": evidence_refs,
                "recommended_action": _coverage_recommended_action(coverage_level),
            }
        )
    summary: dict[str, int] = {level: 0 for level in sorted(DETECTION_COVERAGE_LEVELS)}
    for item in items:
        summary[item["coverage_level"]] = summary.get(item["coverage_level"], 0) + 1
    return {"items": items, "summary": summary}


def _rollup_coverage_level(controls: list[Any]) -> str:
    levels = {control.coverage_level for control in controls}
    if not levels:
        return "unknown"
    if "covered" in levels:
        return "covered"
    if "partial" in levels:
        return "partial"
    if "not_covered" in levels:
        return "not_covered"
    if "unknown" in levels:
        return "unknown"
    return "not_applicable"


def _coverage_recommended_action(level: str) -> str:
    if level == "covered":
        return "Maintain detection evidence and keep verification current."
    if level == "partial":
        return "Review partial coverage and add compensating telemetry or analytics."
    if level == "not_covered":
        return "Prioritize defensive coverage or document compensating controls."
    if level == "not_applicable":
        return "Keep not-applicable rationale documented for review."
    return "Treat coverage as unknown until an owner verifies detection evidence."


def _coverage_gap_score(level: str) -> int:
    return {"not_covered": 100, "unknown": 80, "partial": 60}.get(level, 0)


def _technique_id_from_dict(technique: dict[str, Any]) -> str | None:
    value = (
        technique.get("attack_object_id")
        or technique.get("technique_id")
        or technique.get("external_id")
        or technique.get("id")
    )
    return str(value) if value else None


def _technique_name_from_dict(technique: dict[str, Any]) -> str | None:
    value = (
        technique.get("attack_object_name")
        or technique.get("technique_name")
        or technique.get("name")
    )
    return str(value) if value else None


def _tactic_ids_from_dict(technique: dict[str, Any]) -> list[str]:
    raw = technique.get("tactic_ids") or technique.get("tactics") or []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(item) for item in raw if item]
    return []


def _technique_metadata_from_contexts(contexts: list[Any], technique_id: str) -> dict[str, Any]:
    for context in contexts:
        for technique in context.techniques_json or []:
            if not isinstance(technique, dict):
                continue
            if _technique_id_from_dict(technique) == technique_id:
                return {
                    "name": _technique_name_from_dict(technique),
                    "tactics": _tactic_ids_from_dict(technique),
                    "deprecated": bool(technique.get("deprecated")),
                    "revoked": bool(technique.get("revoked")),
                }
    return {"name": None, "tactics": [], "deprecated": False, "revoked": False}


def _detection_control_payload(control: Any) -> dict[str, Any]:
    return {
        "id": control.id,
        "project_id": control.project_id,
        "control_id": control.control_id,
        "name": control.name,
        "technique_id": control.technique_id,
        "technique_name": control.technique_name,
        "source_type": control.source_type,
        "coverage_level": control.coverage_level,
        "environment": control.environment,
        "owner": control.owner,
        "evidence_ref": control.evidence_ref,
        "evidence_refs": list(control.evidence_refs_json or []),
        "review_status": control.review_status,
        "history_count": len(getattr(control, "history", []) or []),
        "attachment_count": len(getattr(control, "attachments", []) or []),
        "notes": control.notes,
        "last_verified_at": control.last_verified_at,
    }
