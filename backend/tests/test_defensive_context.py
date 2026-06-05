from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from app.domain.engine.models import (
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
    ProviderEvidence,
)
from app.domain.engine.services.defensive_context import (
    attach_defensive_contexts,
    defensive_context_hit_count,
    defensive_context_sources,
    load_defensive_context_file,
    merge_defensive_contexts,
)


def test_defensive_context_loader_accepts_keyed_payload_aliases_and_nested_ssvc(
    tmp_path: Path,
) -> None:
    path = tmp_path / "context.json"
    path.write_text(
        json.dumps(
            {
                "CVE-2024-3094": [
                    {
                        "database": "github-advisory-db",
                        "id": "GHSA-demo",
                        "name": "Backdoored xz release",
                        "details": "Package metadata from GHSA.",
                        "references": "https://github.com/advisories/GHSA-demo",
                        "tags": ["supply-chain", "backdoor"],
                    },
                    {
                        "provider": "cisa_vulnrichment",
                        "advisory_id": "VU-2024-3094",
                        "summary": "CISA enriched triage details.",
                        "ssvc": {
                            "decision": "act",
                            "exploitation": "active",
                            "automatable": "yes",
                            "technical_impact": "total",
                        },
                    },
                    {"provider": "unsupported", "id": "ignored"},
                ],
                "not-a-cve": [{"provider": "osv", "id": "ignored"}],
            }
        ),
        encoding="utf-8",
    )

    result = load_defensive_context_file(path)

    assert result.sources == ["ghsa", "vulnrichment"]
    assert len(result.contexts["CVE-2024-3094"]) == 2
    assert result.warnings == [
        "Ignored defensive context item 3: source must be one of: ghsa, osv, ssvc, vulnrichment."
    ]
    ghsa = result.contexts["CVE-2024-3094"][0]
    vulnrichment = result.contexts["CVE-2024-3094"][1]
    assert ghsa.source == "ghsa"
    assert ghsa.source_id == "GHSA-demo"
    assert ghsa.references == ["https://github.com/advisories/GHSA-demo"]
    assert ghsa.tags == ["supply-chain", "backdoor"]
    assert vulnrichment.source == "vulnrichment"
    assert vulnrichment.ssvc_decision == "act"
    assert vulnrichment.exploitation == "active"
    assert vulnrichment.automatable == "yes"
    assert vulnrichment.technical_impact == "total"


def test_defensive_context_loader_handles_array_payload_and_invalid_files(tmp_path: Path) -> None:
    array_path = tmp_path / "array.json"
    array_path.write_text(
        json.dumps(
            [
                {
                    "cve": "cve-2021-44228",
                    "source": "osv",
                    "osv_id": "OSV-2021-44228",
                    "description": "Log4Shell advisory.",
                },
                "ignored-non-object",
            ]
        ),
        encoding="utf-8",
    )
    invalid_json_path = tmp_path / "invalid.json"
    invalid_json_path.write_text("{", encoding="utf-8")
    invalid_shape_path = tmp_path / "invalid-shape.json"
    invalid_shape_path.write_text('"not an object"', encoding="utf-8")

    result = load_defensive_context_file(array_path)

    assert defensive_context_sources(result.contexts) == ["osv"]
    assert result.contexts["CVE-2021-44228"][0].source_id == "OSV-2021-44228"
    with pytest.raises(ValueError, match="not valid defensive context JSON"):
        load_defensive_context_file(invalid_json_path)
    with pytest.raises(ValueError, match="must be an object or array"):
        load_defensive_context_file(invalid_shape_path)
    with pytest.raises(ValueError, match="could not be read"):
        load_defensive_context_file(tmp_path / "missing.json")


def test_defensive_context_merge_and_attach_updates_provider_evidence() -> None:
    result = load_defensive_context_file(None)
    assert result.contexts == {}
    assert result.sources == []
    assert result.warnings == []

    context_a = load_defensive_context_file(
        _write_json_context(
            {
                "items": [
                    {
                        "cve_id": "CVE-2024-3094",
                        "source": "osv",
                        "source_id": "OSV-2024-3094",
                        "title": "OSV row",
                    }
                ]
            }
        )
    ).contexts
    context_b = load_defensive_context_file(
        _write_json_context(
            {
                "contexts": [
                    {
                        "cveId": "CVE-2024-3094",
                        "provider": "osv",
                        "source_id": "OSV-2024-3094",
                        "title": "OSV row",
                    },
                    {
                        "cveId": "CVE-2024-3094",
                        "provider": "ssvc",
                        "source_id": "SSVC-2024-3094",
                        "title": "SSVC row",
                    },
                ]
            }
        )
    ).contexts

    merged = merge_defensive_contexts(context_a, context_b)
    finding = PrioritizedFinding(
        cve_id="CVE-2024-3094",
        priority_label="High",
        priority_rank=2,
        rationale="High-risk finding.",
        provider_evidence=ProviderEvidence(
            nvd=NvdData(cve_id="CVE-2024-3094"),
            epss=EpssData(cve_id="CVE-2024-3094"),
            kev=KevData(cve_id="CVE-2024-3094"),
        ),
        recommended_action="Patch.",
    )

    [updated] = attach_defensive_contexts([finding], merged)

    assert [item.source for item in merged["CVE-2024-3094"]] == ["osv", "ssvc"]
    assert defensive_context_hit_count([updated]) == 1
    assert [item.source for item in updated.defensive_contexts] == ["osv", "ssvc"]
    assert updated.provider_evidence is not None
    assert updated.provider_evidence.defensive_contexts == updated.defensive_contexts


def _write_json_context(payload: object) -> Path:
    path = Path(tempfile.mkdtemp(prefix="defensive-context-")) / "context.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path
