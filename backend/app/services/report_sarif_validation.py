"""
Small local SARIF 2.1.0 validation helpers.

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
                                "required": ["name", "rules"],
                                "additionalProperties": True,
                                "properties": {
                                    "name": {"type": "string", "minLength": 1},
                                    "version": {"type": "string"},
                                    "rules": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "required": ["id"],
                                            "additionalProperties": True,
                                            "properties": {
                                                "id": {"type": "string", "minLength": 1}
                                            },
                                        },
                                    },
                                },
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "ruleId",
                                "level",
                                "message",
                                "locations",
                                "partialFingerprints",
                            ],
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
                                "partialFingerprints": {
                                    "type": "object",
                                    "minProperties": 1,
                                    "additionalProperties": {
                                        "type": "string",
                                        "minLength": 1,
                                    },
                                },
                                "properties": {"type": "object", "additionalProperties": True},
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
    errors.extend(_validate_rule_references(payload))
    errors.extend(_validate_workbench_results(payload))
    return errors


def _validate_rule_references(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for run_index, run in enumerate(payload.get("runs", [])):
        if not isinstance(run, dict):
            continue
        raw_tool = run.get("tool")
        tool = raw_tool if isinstance(raw_tool, dict) else {}
        raw_driver = tool.get("driver")
        driver = raw_driver if isinstance(raw_driver, dict) else {}
        rule_ids = {
            str(rule.get("id"))
            for rule in driver.get("rules", [])
            if isinstance(rule, dict) and rule.get("id")
        }
        for result_index, result in enumerate(run.get("results", [])):
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "")
            if rule_id and rule_id not in rule_ids:
                errors.append(
                    f"runs.{run_index}.results.{result_index}.ruleId: "
                    f"{rule_id!r} is not declared in tool.driver.rules"
                )
    return errors


def _validate_workbench_results(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for run_index, run in enumerate(payload.get("runs", [])):
        if not isinstance(run, dict):
            continue
        raw_tool = run.get("tool")
        tool = raw_tool if isinstance(raw_tool, dict) else {}
        raw_driver = tool.get("driver")
        driver = raw_driver if isinstance(raw_driver, dict) else {}
        tool_name = str(driver.get("name") or "")
        if not tool_name.startswith("vuln-prioritizer-workbench"):
            continue
        for result_index, result in enumerate(run.get("results", [])):
            if not isinstance(result, dict):
                continue
            raw_properties = result.get("properties")
            properties = raw_properties if isinstance(raw_properties, dict) else {}
            cve = properties.get("cve")
            if not isinstance(cve, str) or not cve.startswith("CVE-"):
                errors.append(
                    f"runs.{run_index}.results.{result_index}.properties.cve: "
                    "vuln-prioritizer-workbench SARIF results must declare a CVE ID"
                )
            references = properties.get("references")
            if not isinstance(references, list) or not references:
                errors.append(
                    f"runs.{run_index}.results.{result_index}.properties.references: "
                    "vuln-prioritizer-workbench SARIF results must declare "
                    "at least one reference URL"
                )
                continue
            for reference_index, reference in enumerate(references):
                if not isinstance(reference, str) or not reference.startswith(
                    ("http://", "https://")
                ):
                    errors.append(
                        f"runs.{run_index}.results.{result_index}."
                        f"properties.references.{reference_index}: "
                        "reference must be an HTTP(S) URL"
                    )
    return errors


def validate_sarif_file(path: Path) -> tuple[dict[str, Any], list[str]]:
    """Load and validate a SARIF file."""
    payload = load_sarif_payload(path)
    return payload, validate_sarif_payload(payload)
