"""Offline importer contracts for normalizing uploaded vulnerability inputs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

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

    cve: str
    component: str | None = None
    version: str | None = None
    asset_ref: str | None = None
    source: str = "import"
    fix_version: str | None = None
    raw_evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.cve, str):
            raise ImporterValidationError("Occurrence cve must be a string")
        if not isinstance(self.source, str):
            raise ImporterValidationError("Occurrence source must be a string")
        cve = self.cve.strip().upper()
        if not CVE_PATTERN.fullmatch(cve):
            raise ImporterValidationError(f"Invalid CVE identifier: {self.cve!r}")
        source = self.source.strip()
        if not source:
            raise ImporterValidationError("Occurrence source must not be blank")
        if not isinstance(self.raw_evidence, Mapping):
            raise ImporterValidationError("Occurrence raw_evidence must be a mapping")
        raw_evidence = dict(self.raw_evidence)
        if not all(isinstance(key, str) for key in raw_evidence):
            raise ImporterValidationError("Occurrence raw_evidence keys must be strings")

        object.__setattr__(self, "cve", cve)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "raw_evidence", raw_evidence)


@runtime_checkable
class Importer(Protocol):
    """Pure parser that turns one input payload into normalized occurrences."""

    @property
    def input_type(self) -> str:
        """Stable Workbench input type claimed by the importer."""
        ...

    def parse(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> list[NormalizedOccurrence]:
        """Parse payload bytes/text without provider, database, or network access."""
        ...
