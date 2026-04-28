"""Importer registry keyed by Workbench input type."""

from __future__ import annotations

import builtins
from collections.abc import Iterable

from app.importers.contracts import (
    Importer,
    ImporterError,
    ImporterValidationError,
    InputPayload,
    NormalizedOccurrence,
)
from app.importers.legacy import default_importers


class UnsupportedInputTypeError(ImporterError, LookupError):
    """Raised when no importer is registered for an input type."""

    def __init__(self, input_type: str, supported: Iterable[str]) -> None:
        supported_types = tuple(sorted(supported))
        message = f"Unsupported input type {input_type!r}"
        if supported_types:
            message = f"{message}. Supported input types: {', '.join(supported_types)}"
        super().__init__(message)
        self.input_type = input_type
        self.supported = supported_types


class DuplicateInputTypeError(ImporterValidationError):
    """Raised when two importers claim the same input type."""

    def __init__(self, input_type: str) -> None:
        super().__init__(f"Duplicate importer input type: {input_type!r}")
        self.input_type = input_type


class ImporterRegistry:
    """Small in-memory registry for offline input importers."""

    def __init__(self, importers: Iterable[Importer] = ()) -> None:
        self._importers: dict[str, Importer] = {}
        for importer in importers:
            self.register(importer)

    def register(self, importer: Importer) -> None:
        """Register an importer by its normalized input type."""
        input_type = _normalize_input_type(importer.input_type)
        if input_type in self._importers:
            raise DuplicateInputTypeError(input_type)
        self._importers[input_type] = importer

    def list_input_types(self) -> tuple[str, ...]:
        """Return supported input types in stable order."""
        return tuple(sorted(self._importers))

    def list(self) -> tuple[str, ...]:
        """Return supported input types in stable order."""
        return self.list_input_types()

    def supported_input_types(self) -> tuple[str, ...]:
        """Return supported input types in stable order."""
        return self.list_input_types()

    def get(self, input_type: str) -> Importer:
        """Return the importer for an input type, or raise a clear lookup error."""
        normalized = _normalize_input_type(input_type)
        try:
            return self._importers[normalized]
        except KeyError as exc:
            raise UnsupportedInputTypeError(normalized, self._importers) from exc

    def parse(
        self,
        input_type: str,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> builtins.list[NormalizedOccurrence]:
        """Parse input through the importer registered for the input type."""
        return builtins.list(self.get(input_type).parse(payload, filename=filename))


def build_importer_registry(importers: Iterable[Importer] | None = None) -> ImporterRegistry:
    """Build an importer registry from the supplied offline importers."""
    selected_importers = default_importers() if importers is None else importers
    return ImporterRegistry(selected_importers)


def _normalize_input_type(input_type: str) -> str:
    normalized = input_type.strip().lower()
    if not normalized:
        raise ImporterValidationError("Importer input_type must not be blank")
    return normalized
