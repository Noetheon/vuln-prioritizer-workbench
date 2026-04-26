"""Static input-parser extension contracts.

This module intentionally defines local parser contracts only. It does not discover
entry points, import modules from user supplied paths, or load code from URLs.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from vuln_prioritizer.models import ParsedInput

STATIC_EXTENSION_POLICY = "static-local-only"
ParserFunction = Callable[[Path], ParsedInput]


@dataclass(frozen=True)
class InputParserDefinition:
    """Declarative contract for a locally registered input parser."""

    name: str
    parser: ParserFunction
    file_suffixes: tuple[str, ...] = ()
    media_types: tuple[str, ...] = ()
    fixture_names: tuple[str, ...] = ()
    remote_code_loading: bool = False


def validate_input_parser_definition(definition: InputParserDefinition) -> None:
    """Validate a parser definition without executing the parser."""

    if not definition.name or definition.name.strip() != definition.name:
        raise ValueError("Input parser names must be non-empty and trimmed.")
    if definition.remote_code_loading:
        raise ValueError("Input parser definitions must not load remote code.")
    if not callable(definition.parser):
        raise ValueError(f"Input parser {definition.name!r} is not callable.")
    for suffix in definition.file_suffixes:
        if not suffix.startswith("."):
            raise ValueError(f"Input parser {definition.name!r} has invalid suffix {suffix!r}.")


def build_input_parser_registry(
    definitions: tuple[InputParserDefinition, ...],
) -> Mapping[str, ParserFunction]:
    """Build the static parser registry used by the loader."""

    registry: dict[str, ParserFunction] = {}
    for definition in definitions:
        validate_input_parser_definition(definition)
        if definition.name in registry:
            raise ValueError(f"Duplicate input parser name: {definition.name}")
        registry[definition.name] = definition.parser
    return registry


__all__ = [
    "InputParserDefinition",
    "ParserFunction",
    "STATIC_EXTENSION_POLICY",
    "build_input_parser_registry",
    "validate_input_parser_definition",
]
