from __future__ import annotations

from paths import DATA_ROOT
from sqlmodel import Session, select
from utils.template_workbench import TemplateApiEnv, auth_headers

from app.services.attack_stix_snapshot import (
    import_attack_stix_snapshot,
    validate_attack_technique_ids,
)

ATTACK_STIX_FIXTURE = DATA_ROOT / "attack" / "attack_stix_enterprise_16.1_subset.json"


def test_vpw077_imports_attack_stix_snapshot_catalog_and_provider_status(
    template_api_env: TemplateApiEnv,
) -> None:
    with Session(template_api_env.engine) as session:
        result = import_attack_stix_snapshot(session, ATTACK_STIX_FIXTURE)
        session.commit()

    assert result.created is True
    assert result.attack_version == "16.1"
    assert result.domain == "enterprise"
    assert result.stix_spec_version == "2.1"
    assert result.tactic_count == 2
    assert result.technique_count == 3
    assert result.mitigation_count == 2
    assert result.mitigation_relationship_count == 1
    assert result.warnings == []

    with Session(template_api_env.engine) as session:
        tactics = session.exec(select(template_api_env.app_models.AttackStixTactic)).all()
        techniques = session.exec(select(template_api_env.app_models.AttackStixTechnique)).all()
        mitigations = session.exec(select(template_api_env.app_models.AttackStixMitigation)).all()
        relationships = session.exec(
            select(template_api_env.app_models.AttackStixTechniqueMitigation)
        ).all()
        repeat = import_attack_stix_snapshot(session, ATTACK_STIX_FIXTURE)
        validation = validate_attack_technique_ids(
            session,
            ["T1190", "T9999", "T4040"],
            snapshot_id=result.snapshot_id,
        )
        tactic_ids = sorted(tactic.tactic_id for tactic in tactics)
        technique_ids = sorted(technique.technique_id for technique in techniques)
        t1190_tactics = [
            technique.tactic_ids_json
            for technique in techniques
            if technique.technique_id == "T1190"
        ][0]
        mitigation_by_id = {mitigation.mitigation_id: mitigation for mitigation in mitigations}
        relationship_mitigation_id = relationships[0].mitigation_id
        relationship_technique_id = relationships[0].technique_id
        legacy_mitigation_deprecated = mitigation_by_id["T9998"].deprecated
        session.commit()

    assert repeat.created is False
    assert repeat.snapshot_id == result.snapshot_id
    assert tactic_ids == ["TA0001", "TA0002"]
    assert technique_ids == ["T1059", "T1190", "T9999"]
    assert t1190_tactics == ["TA0001"]
    assert sorted(mitigation_by_id) == ["M1051", "T9998"]
    assert legacy_mitigation_deprecated is True
    assert relationship_mitigation_id == "M1051"
    assert relationship_technique_id == "T1190"
    assert validation.valid_technique_ids == ["T1190", "T9999"]
    assert validation.missing_technique_ids == ["T4040"]
    assert validation.revoked_or_deprecated_technique_ids == ["T9999"]

    response = template_api_env.client.get(
        "/api/v1/providers/status",
        headers=auth_headers(template_api_env.client),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["snapshot"]["id"] == str(result.provider_snapshot_id)
    assert payload["snapshot"]["content_hash"] == result.bundle_sha256
    assert payload["snapshot"]["selected_sources"] == ["attack_stix"]
    assert payload["snapshot"]["source_hashes"] == {"attack_stix": result.bundle_sha256}
    assert payload["snapshot"]["source_metadata"]["attack_version"] == "16.1"
    assert payload["snapshot"]["source_metadata"]["domain"] == "enterprise"
    assert payload["snapshot"]["source_metadata"]["stix_spec_version"] == "2.1"
    assert payload["snapshot"]["source_metadata"]["technique_count"] == 3
    assert payload["snapshot"]["mode"] == "attack-stix"

    sources = {source["name"]: source for source in payload["sources"]}
    assert sources["attack_stix"]["selected"] is True
    assert sources["attack_stix"]["available"] is True
    assert sources["attack_stix"]["value"] == "16.1"
    assert sources["attack_stix"]["last_sync"] is not None
