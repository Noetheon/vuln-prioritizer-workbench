"""Local defensive context overlays for known CVEs."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from vuln_prioritizer.models import DefensiveContext, PrioritizedFinding
from vuln_prioritizer.utils import normalize_cve_id

ALLOWED_DEFENSIVE_CONTEXT_SOURCES = frozenset(
    {
        "osv",
        "ghsa",
        "vulnrichment",
        "ssvc",
    }
)
_SOURCE_ALIASES = {
    "github": "ghsa",
    "github-advisory": "ghsa",
    "github-advisory-db": "ghsa",
    "github_advisory": "ghsa",
    "cisa-vulnrichment": "vulnrichment",
    "cisa_vulnrichment": "vulnrichment",
}
_CONTEXT_FIELDS = set(DefensiveContext.model_fields)


@dataclass(frozen=True)
class DefensiveContextLoadResult:
    contexts: dict[str, list[DefensiveContext]]
    sources: list[str]
    warnings: list[str]


def load_defensive_context_file(path: Path | None) -> DefensiveContextLoadResult:
    """Load optional OSV/GHSA/Vulnrichment/SSVC context from a local JSON file."""

    if path is None:
        return DefensiveContextLoadResult(contexts={}, sources=[], warnings=[])
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid defensive context JSON: {exc.msg}.") from exc

    contexts: dict[str, list[DefensiveContext]] = {}
    warnings: list[str] = []
    for index, raw_item in enumerate(_iter_context_items(payload), start=1):
        try:
            context = _normalize_context_item(raw_item)
        except ValueError as exc:
            warnings.append(f"Ignored defensive context item {index}: {exc}")
            continue
        contexts.setdefault(context.cve_id, []).append(context)

    normalized = {
        cve_id: sorted(items, key=_context_sort_key) for cve_id, items in sorted(contexts.items())
    }
    return DefensiveContextLoadResult(
        contexts=normalized,
        sources=defensive_context_sources(normalized),
        warnings=warnings,
    )


def merge_defensive_contexts(
    *context_sets: Mapping[str, Sequence[DefensiveContext]],
) -> dict[str, list[DefensiveContext]]:
    """Merge context maps while keeping deterministic order and removing duplicates."""

    merged: dict[str, list[DefensiveContext]] = {}
    seen: set[tuple[str, str, str | None, str | None]] = set()
    for context_set in context_sets:
        for cve_id, contexts in context_set.items():
            for context in contexts:
                key = (context.cve_id, context.source, context.source_id, context.title)
                if key in seen:
                    continue
                seen.add(key)
                merged.setdefault(cve_id, []).append(context)
    return {cve_id: sorted(items, key=_context_sort_key) for cve_id, items in merged.items()}


def defensive_context_sources(
    contexts: Mapping[str, Sequence[DefensiveContext]],
) -> list[str]:
    """Return sorted source names present in the context map."""

    return sorted({context.source for items in contexts.values() for context in items})


def attach_defensive_contexts(
    findings: Sequence[PrioritizedFinding],
    contexts: Mapping[str, Sequence[DefensiveContext]],
) -> list[PrioritizedFinding]:
    """Attach context overlays to findings without changing priority or ranks."""

    updated: list[PrioritizedFinding] = []
    for finding in findings:
        finding_contexts = list(contexts.get(finding.cve_id, []))
        provider_evidence = finding.provider_evidence
        if provider_evidence is not None:
            provider_evidence = provider_evidence.model_copy(
                update={"defensive_contexts": finding_contexts}
            )
        updated.append(
            finding.model_copy(
                update={
                    "defensive_contexts": finding_contexts,
                    "provider_evidence": provider_evidence,
                }
            )
        )
    return updated


def defensive_context_hit_count(findings: Iterable[PrioritizedFinding]) -> int:
    return sum(1 for finding in findings if finding.defensive_contexts)


def _iter_context_items(payload: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, Mapping):
                yield item
        return
    if not isinstance(payload, Mapping):
        raise ValueError("Defensive context JSON must be an object or array.")

    for key in ("items", "contexts", "defensive_contexts"):
        items = payload.get(key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, Mapping):
                    yield item
            return

    for raw_cve_id, value in payload.items():
        cve_id = normalize_cve_id(str(raw_cve_id))
        if cve_id is None:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, Mapping):
                yield {"cve_id": cve_id, **dict(item)}


def _normalize_context_item(raw_item: Mapping[str, Any]) -> DefensiveContext:
    cve_id = _first_text(raw_item, "cve_id", "cve", "cveId")
    normalized_cve = normalize_cve_id(cve_id or "")
    if normalized_cve is None:
        raise ValueError("missing or invalid cve_id.")

    source = _normalize_source(_first_text(raw_item, "source", "provider", "database"))
    if source is None:
        raise ValueError(
            "source must be one of: " + ", ".join(sorted(ALLOWED_DEFENSIVE_CONTEXT_SOURCES)) + "."
        )

    clean: dict[str, Any] = {
        key: value for key, value in raw_item.items() if key in _CONTEXT_FIELDS
    }
    clean["cve_id"] = normalized_cve
    clean["source"] = source
    clean.setdefault(
        "source_id",
        _first_text(raw_item, "source_id", "id", "advisory_id", "ghsa_id", "osv_id"),
    )
    clean.setdefault("title", _first_text(raw_item, "title", "name"))
    clean.setdefault("summary", _first_text(raw_item, "summary", "description", "details"))
    clean.setdefault("url", _first_text(raw_item, "url", "link"))
    clean.setdefault("references", _string_list(raw_item.get("references")))
    clean.setdefault("tags", _string_list(raw_item.get("tags")))
    ssvc = raw_item.get("ssvc")
    if isinstance(ssvc, Mapping):
        clean.setdefault("ssvc_decision", _first_text(ssvc, "decision", "priority"))
        clean.setdefault("exploitation", _first_text(ssvc, "exploitation"))
        clean.setdefault("automatable", _first_text(ssvc, "automatable"))
        clean.setdefault("technical_impact", _first_text(ssvc, "technical_impact"))

    try:
        return DefensiveContext.model_validate(clean)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def _normalize_source(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower().replace("_", "-")
    normalized = _SOURCE_ALIASES.get(normalized, normalized)
    return normalized if normalized in ALLOWED_DEFENSIVE_CONTEXT_SOURCES else None


def _first_text(mapping: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _context_sort_key(context: DefensiveContext) -> tuple[str, str, str]:
    return (context.source, context.source_id or "", context.title or "")
