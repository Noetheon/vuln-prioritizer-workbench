"""Small local SARIF 2.1.0 validation helpers.

The project does not need the full SARIF schema at runtime, but CI/CD integrations
should still catch malformed files before upload to GitHub Code Scanning.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]

SARIF_MINIMUM_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["version", "runs"],
    "additionalProperties": True,
    "properties": {
        "version": {"const": "2.1.0"},
        "$schema": {"type": "string"},
        "runs": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "additionalProperties": True,
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "additionalProperties": True,
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name"],
                                "additionalProperties": True,
                                "properties": {
                                    "name": {"type": "string", "minLength": 1},
                                    "version": {"type": "string"},
                                },
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["ruleId", "level", "message", "locations"],
                            "additionalProperties": True,
                            "properties": {
                                "ruleId": {"type": "string", "minLength": 1},
                                "level": {
                                    "enum": [
                                        "none",
                                        "note",
                                        "warning",
                                        "error",
                                    ]
                                },
                                "message": {
                                    "type": "object",
                                    "required": ["text"],
                                    "additionalProperties": True,
                                    "properties": {"text": {"type": "string", "minLength": 1}},
                                },
                                "locations": {
                                    "type": "array",
                                    "minItems": 1,
                                    "items": {
                                        "type": "object",
                                        "required": ["physicalLocation"],
                                        "additionalProperties": True,
                                        "properties": {
                                            "physicalLocation": {
                                                "type": "object",
                                                "required": ["artifactLocation"],
                                                "additionalProperties": True,
                                                "properties": {
                                                    "artifactLocation": {
                                                        "type": "object",
                                                        "required": ["uri"],
                                                        "additionalProperties": True,
                                                        "properties": {
                                                            "uri": {
                                                                "type": "string",
                                                                "minLength": 1,
                                                            }
                                                        },
                                                    }
                                                },
                                            }
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}


def load_sarif_payload(path: Path) -> dict[str, Any]:
    """Load a SARIF JSON document from disk."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc.msg}.") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return payload


def validate_sarif_payload(payload: dict[str, Any]) -> list[str]:
    """Return deterministic validation errors for the local SARIF contract."""
    validator = jsonschema.Draft202012Validator(SARIF_MINIMUM_SCHEMA)
    errors: list[str] = []
    for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(f"{location}: {error.message}")
    return errors


def validate_sarif_file(path: Path) -> tuple[dict[str, Any], list[str]]:
    """Load and validate a SARIF file."""
    payload = load_sarif_payload(path)
    return payload, validate_sarif_payload(payload)
