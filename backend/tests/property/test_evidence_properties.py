from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from utils.property_profiles import property_settings

from app.domain.engine.models import EvidenceBundleFile, EvidenceBundleManifest
from app.services.report_bundle_archive_verification import (
    describe_evidence_bundle_mismatch,
    validate_evidence_manifest_structure,
)
from app.services.report_sarif_validation import validate_sarif_payload

pytestmark = pytest.mark.property
PROPERTY_SETTINGS = property_settings()


@st.composite
def valid_sarif(draw: st.DrawFn) -> dict[str, Any]:
    cve = f"CVE-{draw(st.integers(1999, 2099))}-{draw(st.integers(1000, 9999999))}"
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "vuln-prioritizer-workbench", "rules": [{"id": cve}]}},
                "results": [
                    {
                        "ruleId": cve,
                        "level": draw(st.sampled_from(["none", "note", "warning", "error"])),
                        "message": {"text": f"Review {cve}"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "input.json"}}}
                        ],
                        "partialFingerprints": {
                            "finding": hashlib.sha256(cve.encode()).hexdigest()
                        },
                        "properties": {"cve": cve, "references": [f"https://example.test/{cve}"]},
                    }
                ],
            }
        ],
    }


@PROPERTY_SETTINGS
@given(payload=valid_sarif())
def test_generated_valid_sarif_is_accepted_without_mutating_input(payload: dict[str, Any]) -> None:
    before = deepcopy(payload)
    assert validate_sarif_payload(payload) == []
    assert payload == before


@pytest.mark.parametrize(
    "defect",
    ["version", "runs", "rule-reference", "cve", "reference-url", "fingerprint", "message"],
)
@PROPERTY_SETTINGS
@given(payload=valid_sarif())
def test_generated_sarif_contract_defects_are_rejected(
    payload: dict[str, Any], defect: str
) -> None:
    result = payload["runs"][0]["results"][0]
    if defect == "version":
        payload["version"] = "2.0.0"
    elif defect == "runs":
        payload["runs"] = []
    elif defect == "rule-reference":
        result["ruleId"] = "undeclared-rule"
    elif defect == "cve":
        result["properties"]["cve"] = ""
    elif defect == "reference-url":
        result["properties"]["references"] = ["file:///private/evidence"]
    elif defect == "fingerprint":
        result["partialFingerprints"] = {}
    else:
        result["message"] = {}
    before = deepcopy(payload)
    errors = validate_sarif_payload(payload)
    assert errors, f"Accepted SARIF defect: {defect}"
    assert all(isinstance(error, str) and error for error in errors)
    assert validate_sarif_payload(payload) == errors
    assert payload == before


@pytest.mark.parametrize("field", ["runs", "tool", "driver", "rules", "results"])
@PROPERTY_SETTINGS
@given(
    payload=valid_sarif(),
    malformed=st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=32)),
)
def test_malformed_sarif_containers_return_errors(
    payload: dict[str, Any],
    malformed: object,
    field: str,
) -> None:
    run = payload["runs"][0]
    if field == "runs":
        payload[field] = malformed
    elif field in {"tool", "results"}:
        run[field] = malformed
    elif field == "driver":
        run["tool"][field] = malformed
    else:
        run["tool"]["driver"][field] = malformed
    assert validate_sarif_payload(payload), f"Accepted malformed {field}"


def manifest(paths: list[str], content: bytes) -> EvidenceBundleManifest:
    return EvidenceBundleManifest(
        generated_at="2026-09-30T00:00:00Z",
        source_analysis_path="analysis-result.v2.json",
        files=[
            EvidenceBundleFile(
                path=path,
                kind="generated",
                size_bytes=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
            for path in paths
        ],
    )


member_paths = st.lists(
    st.sampled_from(["analysis-result.v2.json", "findings.csv", "reports/technical-report.md"]),
    min_size=1,
    max_size=3,
    unique=True,
)


@PROPERTY_SETTINGS
@given(paths=member_paths, content=st.binary(max_size=128))
def test_unique_manifest_members_are_accepted(paths: list[str], content: bytes) -> None:
    assert validate_evidence_manifest_structure(manifest(paths, content)) == []


@pytest.mark.parametrize("defect", ["duplicate", "self-reference"])
@PROPERTY_SETTINGS
@given(paths=member_paths, content=st.binary(max_size=128))
def test_manifest_duplicate_and_self_reference_are_rejected(
    paths: list[str],
    content: bytes,
    defect: str,
) -> None:
    bad_path = paths[0] if defect == "duplicate" else "manifest.json"
    payload = manifest([*paths, bad_path], content)
    before = payload.model_dump_json()
    errors = validate_evidence_manifest_structure(payload)
    assert len(errors) == 1
    assert errors[0].path == bad_path
    assert errors[0].status == "error"
    assert errors[0].kind == "generated"
    assert errors[0].detail == (
        "Manifest declares the same bundle member path more than once."
        if defect == "duplicate"
        else "Manifest must not declare manifest.json as a bundle member."
    )
    assert payload.model_dump_json() == before


@pytest.mark.parametrize(
    "size_changed,digest_changed", [(False, True), (True, False), (True, True)]
)
@PROPERTY_SETTINGS
@given(content=st.binary(max_size=128), extra_size=st.integers(1, 2048))
def test_mismatch_description_identifies_the_changed_evidence(
    content: bytes,
    extra_size: int,
    size_changed: bool,
    digest_changed: bool,
) -> None:
    expected = manifest(["analysis-result.v2.json"], content).files[0]
    size = len(content) + extra_size if size_changed else len(content)
    digest = hashlib.sha256(content + b"x").hexdigest() if digest_changed else expected.sha256
    description = describe_evidence_bundle_mismatch(
        expected=expected,
        actual_size=size,
        actual_sha256=digest,
    )
    assert isinstance(description, str)
    assert description.startswith("Archive member does not match the manifest:")
    assert ("sha256 mismatch" in description) is digest_changed
    assert ("size " in description) is size_changed
    details = []
    if size_changed:
        details.append(f"size {size} != manifest {len(content)}")
    if digest_changed:
        details.append("sha256 mismatch")
    assert description == "Archive member does not match the manifest: " + ", ".join(details) + "."


def test_sarif_missing_root_fields_identifies_the_root() -> None:
    errors = validate_sarif_payload({})
    assert errors and all(error.startswith("$: ") for error in errors)


@pytest.mark.parametrize(
    "payload",
    [
        {"version": "2.1.0", "runs": None},
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "x", "rules": None}}, "results": []}],
        },
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "x", "rules": []}}, "results": None}],
        },
    ],
)
def test_null_sarif_containers_regression(payload: dict[str, Any]) -> None:
    assert validate_sarif_payload(payload)
