"""Preserve provider diagnostics at the typed evidence boundary."""

from app.decision_core.producer import _provider_quality_flags
from app.domain.engine.models import ProviderDataQualityFlag


def test_provider_diagnostics_preserve_structured_fields_and_unstructured_evidence():
    typed = ProviderDataQualityFlag(
        source="nvd", code="unavailable", message="Offline", severity="error"
    )
    raw = {"source": "epss", "code": "stale", "message": "Retained snapshot", "severity": "warning"}
    converted = _provider_quality_flags({"nvd": [typed, "Older provider warning"], "epss": [raw]})
    assert {
        key: getattr(converted["nvd"][0], key) for key in typed.model_dump()
    } == typed.model_dump()
    unknown = converted["nvd"][1]
    assert (unknown.source, unknown.code, unknown.message, unknown.severity) == (
        "unknown",
        "unstructured_provider_flag",
        "Older provider warning",
        "warning",
    )
    assert converted["epss"][0].source == "epss"
    assert converted["epss"][0].message == "Retained snapshot"
    assert raw["message"] == "Retained snapshot"
