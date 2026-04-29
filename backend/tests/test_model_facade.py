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
    models_state,
    models_waivers,
)


def test_models_facade_reexports_base_model_identity() -> None:
    assert models.StrictModel is model_base.StrictModel


@pytest.mark.parametrize(
    ("facade_name", "module_name"),
    [
        ("AttackMapping", "AttackMapping"),
        ("AttackTechnique", "AttackTechnique"),
        ("AttackSummary", "AttackSummary"),
        ("AttackData", "AttackData"),
    ],
)
def test_models_facade_reexports_attack_model_identities(
    facade_name: str, module_name: str
) -> None:
    assert getattr(models, facade_name) is getattr(models_attack, module_name)


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
        ("StateInitMetadata", "StateInitMetadata"),
        ("StateInitSummary", "StateInitSummary"),
        ("StateInitReport", "StateInitReport"),
        ("StateImportMetadata", "StateImportMetadata"),
        ("StateImportSummary", "StateImportSummary"),
        ("StateImportReport", "StateImportReport"),
        ("StateHistoryMetadata", "StateHistoryMetadata"),
        ("StateHistoryEntry", "StateHistoryEntry"),
        ("StateHistoryReport", "StateHistoryReport"),
        ("StateWaiverMetadata", "StateWaiverMetadata"),
        ("StateWaiverEntry", "StateWaiverEntry"),
        ("StateWaiverReport", "StateWaiverReport"),
        ("StateTopServicesMetadata", "StateTopServicesMetadata"),
        ("StateTopServiceEntry", "StateTopServiceEntry"),
        ("StateTopServicesReport", "StateTopServicesReport"),
        ("StateTrendsMetadata", "StateTrendsMetadata"),
        ("StateTrendEntry", "StateTrendEntry"),
        ("StateTrendsReport", "StateTrendsReport"),
        ("StateServiceHistoryMetadata", "StateServiceHistoryMetadata"),
        ("StateServiceHistoryEntry", "StateServiceHistoryEntry"),
        ("StateServiceHistoryReport", "StateServiceHistoryReport"),
    ],
)
def test_models_facade_reexports_state_model_identities(facade_name: str, module_name: str) -> None:
    assert getattr(models, facade_name) is getattr(models_state, module_name)


@pytest.mark.parametrize(
    ("facade_name", "module_name"),
    [
        ("DoctorCheck", "DoctorCheck"),
        ("DoctorSummary", "DoctorSummary"),
        ("DoctorReport", "DoctorReport"),
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
        models.StateInitSummary(unexpected=True)

    summary = models.StateInitSummary()
    with pytest.raises(ValidationError):
        summary.snapshot_count = 3

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
