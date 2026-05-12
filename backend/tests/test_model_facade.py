from __future__ import annotations

import pytest
from pydantic import ValidationError

from vuln_prioritizer import (
    model_base,
    models,
    models_artifacts,
    models_attack,
    models_input,
    models_provider,
    models_remediation,
    models_waivers,
)


def test_models_facade_reexports_base_model_identity() -> None:
    assert models.StrictModel is model_base.StrictModel


@pytest.mark.parametrize(
    ("facade_name", "module_name"),
    [
        ("AttackMapping", "AttackMapping"),
        ("AttackMappingType", "AttackMappingType"),
        ("AttackReviewStatus", "AttackReviewStatus"),
        ("AttackTechnique", "AttackTechnique"),
        ("AttackTactic", "AttackTactic"),
        ("AttackSummary", "AttackSummary"),
        ("AttackData", "AttackData"),
        ("CveAttackMapping", "CveAttackMapping"),
        ("FindingAttackContext", "FindingAttackContext"),
    ],
)
def test_models_facade_reexports_attack_model_identities(
    facade_name: str, module_name: str
) -> None:
    assert getattr(models, facade_name) is getattr(models_attack, module_name)


def test_vpw055_attack_mapping_models_validate_required_review_fields() -> None:
    mapping = models.CveAttackMapping(
        cve_id="CVE-2021-44228",
        technique_id="T1190",
        source="CTID Mappings Explorer",
        confidence=0.9,
        rationale="Reviewed defensive mapping from CVE impact to ATT&CK context.",
        defensive_note="Use for triage and detection review only.",
        tactic_ids=["TA0001"],
        review_status="reviewed",
    )
    context = models.FindingAttackContext(
        finding_id="finding-1",
        cve_id="CVE-2021-44228",
        mapped=True,
        mappings=[mapping],
        techniques=[
            models.AttackTechnique(
                attack_object_id="T1190",
                name="Exploit Public-Facing Application",
                tactics=["initial-access"],
            )
        ],
        tactics=[models.AttackTactic(tactic_id="TA0001", name="Initial Access")],
        defensive_note="Defensive context only.",
    )

    assert mapping.technique_id == "T1190"
    assert context.mapped is True

    with pytest.raises(ValidationError):
        models.CveAttackMapping(
            cve_id="CVE-2021-44228",
            technique_id="TA0001",
            source="CTID Mappings Explorer",
            confidence=0.9,
            rationale="Tactic IDs are not valid technique IDs.",
            defensive_note="Defensive context only.",
        )

    with pytest.raises(ValidationError):
        models.CveAttackMapping(
            cve_id="CVE-2021-44228",
            technique_id="T1190",
            source="",
            confidence=0.9,
            rationale="Missing source must fail.",
            defensive_note="Defensive context only.",
        )

    with pytest.raises(ValidationError):
        models.CveAttackMapping(
            cve_id="CVE-2021-44228",
            technique_id="T1190",
            source="CTID Mappings Explorer",
            confidence=1.2,
            rationale="Confidence must be normalized.",
            defensive_note="Defensive context only.",
        )


@pytest.mark.parametrize(
    ("facade_name", "module_name"),
    [
        ("InputItem", "InputItem"),
        ("InputOccurrence", "InputOccurrence"),
        ("InputSourceSummary", "InputSourceSummary"),
        ("ParsedInput", "ParsedInput"),
        ("FindingProvenance", "FindingProvenance"),
        ("AssetContextRecord", "AssetContextRecord"),
        ("ContextPolicyProfile", "ContextPolicyProfile"),
        ("VexStatement", "VexStatement"),
    ],
)
def test_models_facade_reexports_input_model_identities(facade_name: str, module_name: str) -> None:
    assert getattr(models, facade_name) is getattr(models_input, module_name)


@pytest.mark.parametrize(
    ("facade_name", "module_name"),
    [
        ("EvidenceBundleFile", "EvidenceBundleFile"),
        ("EvidenceBundleInputHash", "EvidenceBundleInputHash"),
        ("EvidenceBundleManifest", "EvidenceBundleManifest"),
        ("EvidenceBundleVerificationMetadata", "EvidenceBundleVerificationMetadata"),
        ("EvidenceBundleVerificationSummary", "EvidenceBundleVerificationSummary"),
        ("EvidenceBundleVerificationItem", "EvidenceBundleVerificationItem"),
    ],
)
def test_models_facade_reexports_artifact_model_identities(
    facade_name: str, module_name: str
) -> None:
    assert getattr(models, facade_name) is getattr(models_artifacts, module_name)


@pytest.mark.parametrize(
    ("facade_name", "module_name"),
    [
        ("NvdData", "NvdData"),
        ("EpssData", "EpssData"),
        ("KevData", "KevData"),
        ("ProviderEvidence", "ProviderEvidence"),
        ("ProviderLookupDiagnostics", "ProviderLookupDiagnostics"),
    ],
)
def test_models_facade_reexports_provider_model_identities(
    facade_name: str, module_name: str
) -> None:
    assert getattr(models, facade_name) is getattr(models_provider, module_name)


@pytest.mark.parametrize(
    ("facade_name", "module_name"),
    [
        ("RemediationComponent", "RemediationComponent"),
        ("RemediationPlan", "RemediationPlan"),
    ],
)
def test_models_facade_reexports_remediation_model_identities(
    facade_name: str, module_name: str
) -> None:
    assert getattr(models, facade_name) is getattr(models_remediation, module_name)


@pytest.mark.parametrize(
    ("facade_name", "module_name"),
    [
        ("WaiverRule", "WaiverRule"),
        ("WaiverHealthSummary", "WaiverHealthSummary"),
    ],
)
def test_models_facade_reexports_waiver_model_identities(
    facade_name: str, module_name: str
) -> None:
    assert getattr(models, facade_name) is getattr(models_waivers, module_name)


def test_moved_models_keep_strict_frozen_behavior_and_default_factories() -> None:
    with pytest.raises(ValidationError):
        models.EvidenceBundleManifest(
            generated_at="2026-04-25T00:00:00Z",
            source_analysis_path="analysis.json",
            unexpected=True,
        )

    summary = models.EvidenceBundleManifest(
        generated_at="2026-04-25T00:00:00Z",
        source_analysis_path="analysis.json",
    )
    with pytest.raises(ValidationError):
        summary.source_analysis_path = "changed.json"

    first = models.EvidenceBundleManifest(
        generated_at="2026-04-25T00:00:00Z",
        source_analysis_path="analysis.json",
    )
    second = models.EvidenceBundleManifest(
        generated_at="2026-04-25T00:00:00Z",
        source_analysis_path="analysis.json",
    )

    assert first.files == []
    assert second.files == []
    assert first.files is not second.files

    attack = models.AttackData(cve_id="CVE-2026-0001")
    assert attack.mappings == []
    assert attack.techniques == []
    assert attack.mapping_types == []

    parsed = models.ParsedInput()
    occurrence = models.InputOccurrence(cve_id="CVE-2026-0001")
    provenance = models.FindingProvenance()
    assert parsed.occurrences == []
    assert parsed.unique_cves == []
    assert occurrence.fix_versions == []
    assert provenance.occurrences == []
    assert provenance.vex_statuses == {}

    nvd = models.NvdData(cve_id="CVE-2026-0001")
    assert nvd.cwes == []
    assert nvd.references == []
    assert nvd.reference_tags == {}

    remediation = models.RemediationPlan()
    component = models.RemediationComponent()
    assert remediation.components == []
    assert component.fixed_versions == []
    assert component.targets == []
    assert component.asset_ids == []

    waiver = models.WaiverRule(
        cve_id="CVE-2026-0001",
        owner="security",
        reason="Accepted for test",
        expires_on="2026-05-01",
    )
    assert waiver.asset_ids == []
    assert waiver.targets == []
    assert waiver.services == []
