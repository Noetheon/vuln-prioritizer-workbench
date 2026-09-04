"""Offline importer contracts for normalizing uploaded vulnerability inputs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from app.domain.asset_identity import (
    normalize_asset_identity_value,
    normalize_asset_target_kind,
)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
InputPayload = bytes | str


class ImporterError(Exception):
    """Base class for importer contract failures."""


class ImporterParseError(ImporterError):
    """Raised when an importer cannot parse the supplied input."""


class ImporterValidationError(ImporterError, ValueError):
    """Raised when normalized importer output fails contract validation."""


@dataclass(frozen=True, slots=True)
class NormalizedOccurrence:
    """Provider-free occurrence DTO emitted by importers before persistence."""

    cve_id: str
    component_name: str | None = None
    component_version: str | None = None
    target_kind: str = "generic"
    target_ref: str | None = None
    asset_id: str | None = None
    source: str = "import"
    fix_version: str | None = None
    raw_evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Post init   method for NormalizedOccurrence."""
        if not isinstance(self.cve_id, str):
            raise ImporterValidationError("Occurrence cve_id must be a string")
        if not isinstance(self.source, str):
            raise ImporterValidationError("Occurrence source must be a string")
        cve = self.cve_id.strip().upper()
        if not CVE_PATTERN.fullmatch(cve):
            raise ImporterValidationError(f"Invalid CVE identifier: {self.cve_id!r}")
        source = self.source.strip()
        if not source:
            raise ImporterValidationError("Occurrence source must not be blank")
        if not isinstance(self.raw_evidence, Mapping):
            raise ImporterValidationError("Occurrence raw_evidence must be a mapping")
        raw_evidence = dict(self.raw_evidence)
        if not all(isinstance(key, str) for key in raw_evidence):
            raise ImporterValidationError("Occurrence raw_evidence keys must be strings")

        raw_target_kind = raw_evidence.get("target_kind")
        target_kind = self.target_kind
        if target_kind == "generic" and isinstance(raw_target_kind, str):
            target_kind = raw_target_kind
        if not isinstance(target_kind, str):
            raise ImporterValidationError("Occurrence target_kind must be a string")
        target_kind = normalize_asset_target_kind(target_kind) or "generic"
        target_ref = _normalized_optional_string(
            self.target_ref,
            fallback=raw_evidence.get("target_ref"),
            field_name="target_ref",
        )
        asset_id = _normalized_optional_string(
            self.asset_id,
            fallback=raw_evidence.get("asset_id"),
            field_name="asset_id",
        )

        object.__setattr__(self, "cve_id", cve)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "target_kind", target_kind)
        object.__setattr__(self, "target_ref", target_ref)
        object.__setattr__(self, "asset_id", asset_id)
        object.__setattr__(self, "raw_evidence", raw_evidence)


def _normalized_optional_string(
    value: str | None,
    *,
    fallback: object,
    field_name: str,
) -> str | None:
    candidate: object = value if value is not None else fallback
    if candidate is None:
        return None
    if not isinstance(candidate, str):
        raise ImporterValidationError(f"Occurrence {field_name} must be a string or null")
    normalized = normalize_asset_identity_value(candidate)
    return normalized or None


@runtime_checkable
class Importer(Protocol):
    """Pure parser that turns one input payload into normalized occurrences."""

    @property
    def input_type(self) -> str:
        """Stable Workbench input type claimed by the importer."""
        raise TypeError("Protocol declaration only")

    def parse(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> list[NormalizedOccurrence]:
        """Parse payload bytes/text without provider, database, or network access."""
        raise TypeError("Protocol declaration only")
