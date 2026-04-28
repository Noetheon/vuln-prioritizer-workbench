from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from vuln_prioritizer.commands import db as db_command
from vuln_prioritizer.models import AttackData, AttackMapping, AttackTechnique
from vuln_prioritizer.providers.attack_metadata import AttackMetadataProvider
from vuln_prioritizer.providers.attack_stix import AttackStixProvider
from vuln_prioritizer.services.workbench_attack import (
    WorkbenchAttackValidationError,
    attack_mapping_payload,
    attack_technique_payload,
    confidence_for_source,
    mapping_rationale,
    navigator_layer_from_contexts,
    review_status_for_source,
    threat_context_rank,
    top_technique_rows,
    validate_attack_artifact_path,
    validate_workbench_attack_source,
    workbench_mapping_source,
)
from vuln_prioritizer.workbench_config import (
    DEFAULT_ALLOWED_HOSTS,
    WorkbenchSettings,
    ensure_workbench_directories,
    load_workbench_settings,
    sqlite_path_from_url,
)


@dataclass
class _AttackContext:
    cve_id: str
    techniques_json: list[dict[str, object]] | None


def test_workbench_attack_source_guardrails_allow_only_reviewable_sources() -> None:
    validate_workbench_attack_source("ctid")
    validate_workbench_attack_source(" local_curated ")
    validate_workbench_attack_source("manual")

    with pytest.raises(WorkbenchAttackValidationError, match="Heuristic or LLM"):
        validate_workbench_attack_source("heuristic")
    with pytest.raises(WorkbenchAttackValidationError, match="Heuristic or LLM"):
        validate_workbench_attack_source("llm_generated")
    with pytest.raises(WorkbenchAttackValidationError, match="Unsupported"):
        validate_workbench_attack_source("blog")

    assert workbench_mapping_source("ctid-mappings-explorer") == "ctid"
    assert workbench_mapping_source("local_curated") == "local_curated"
    assert workbench_mapping_source("manual") == "manual"
    assert workbench_mapping_source("none") == "none"
    with pytest.raises(WorkbenchAttackValidationError, match="Unsupported"):
        workbench_mapping_source("local-csv")


def test_workbench_attack_review_confidence_and_payload_helpers() -> None:
    mapping = AttackMapping(
        capability_id="CVE-2024-0001",
        attack_object_id="T1190",
        attack_object_name="Exploit Public-Facing Application",
        mapping_type="exploitation_technique",
        capability_group="public-app",
        capability_description="Exploit exposed app",
    )
    technique = AttackTechnique(
        attack_object_id="T1190",
        name="Exploit Public-Facing Application",
        tactics=["initial-access"],
    )
    mapped_attack = AttackData(cve_id="CVE-2024-0001", mapped=True, attack_relevance="High")

    assert review_status_for_source("ctid", mapped=True) == "source_reviewed"
    assert review_status_for_source("manual", mapped=True) == "needs_review"
    assert review_status_for_source("manual", mapped=False) == "not_applicable"
    assert confidence_for_source("ctid") == 1.0
    assert confidence_for_source("manual") == 0.8
    assert confidence_for_source("local_curated") == 0.7
    assert confidence_for_source("unknown") is None
    assert mapping_rationale(mapping, mapped_attack) == "Exploit exposed app"
    assert (
        mapping_rationale(
            AttackMapping(
                capability_id="CVE-2024-0001",
                attack_object_id="T1059",
                comments="Curated analyst rationale.",
            ),
            mapped_attack,
        )
        == "Curated analyst rationale."
    )
    assert (
        mapping_rationale(
            AttackMapping(capability_id="CVE-2024-0001", attack_object_id="T1110"),
            AttackData(cve_id="CVE-2024-0001", attack_rationale="Imported CTID rationale."),
        )
        == "Imported CTID rationale."
    )
    assert "approved local source" in mapping_rationale(
        AttackMapping(capability_id="CVE-2024-0001", attack_object_id="T1021"),
        AttackData(cve_id="CVE-2024-0001"),
    )
    assert attack_mapping_payload(mapping)["attack_object_id"] == "T1190"
    assert attack_technique_payload(technique)["name"] == "Exploit Public-Facing Application"
    assert threat_context_rank(AttackData(cve_id="CVE-1", attack_relevance="High")) == 1
    assert threat_context_rank(AttackData(cve_id="CVE-2", attack_relevance="Medium")) == 2
    assert threat_context_rank(AttackData(cve_id="CVE-3", attack_relevance="Low")) == 3
    assert threat_context_rank(AttackData(cve_id="CVE-4")) == 99


def test_workbench_attack_top_techniques_and_navigator_layer() -> None:
    contexts = [
        _AttackContext(
            cve_id="CVE-2024-0001",
            techniques_json=[
                {
                    "attack_object_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactics": ["initial-access"],
                    "url": "https://attack.mitre.org/techniques/T1190/",
                },
                {"attack_object_id": "", "name": "ignored"},
            ],
        ),
        _AttackContext(
            cve_id="CVE-2024-0002",
            techniques_json=[
                {
                    "attack_object_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactics": ["initial-access"],
                },
                {"attack_object_id": "T1059", "name": "Command and Scripting Interpreter"},
            ],
        ),
        _AttackContext(cve_id="CVE-2024-0003", techniques_json=None),
    ]

    rows = top_technique_rows(contexts, limit=1)
    layer = navigator_layer_from_contexts(contexts, layer_name="custom layer")

    assert rows == [
        {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactics": ["initial-access"],
            "url": "https://attack.mitre.org/techniques/T1190/",
            "count": 2,
            "cves": ["CVE-2024-0001", "CVE-2024-0002"],
        }
    ]
    assert layer["name"] == "custom layer"
    assert layer["gradient"]["maxValue"] == 2
    assert layer["techniques"][0]["techniqueID"] == "T1190"
    assert "CVE-2024-0001" in layer["techniques"][0]["comment"]


def test_workbench_settings_environment_and_path_helpers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("VULN_PRIORITIZER_DB_URL", "sqlite:///custom/workbench.db")
    monkeypatch.setenv("VULN_PRIORITIZER_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("VULN_PRIORITIZER_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR", str(tmp_path / "snapshots"))
    monkeypatch.setenv("VULN_PRIORITIZER_ATTACK_ARTIFACT_DIR", str(tmp_path / "attack"))
    monkeypatch.setenv("VULN_PRIORITIZER_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("VULN_PRIORITIZER_MAX_UPLOAD_MB", "7")
    monkeypatch.setenv("VULN_PRIORITIZER_NVD_API_KEY_ENV", "CUSTOM_NVD_KEY")
    monkeypatch.setenv("VULN_PRIORITIZER_CSRF_TOKEN", "fixed-token")
    monkeypatch.setenv("VULN_PRIORITIZER_ALLOWED_HOSTS", "example.test, localhost, ")

    settings = load_workbench_settings()
    ensure_workbench_directories(settings)

    assert settings.database_url == "sqlite:///custom/workbench.db"
    assert settings.max_upload_mb == 7
    assert settings.max_upload_bytes == 7 * 1024 * 1024
    assert settings.nvd_api_key_env == "CUSTOM_NVD_KEY"
    assert settings.csrf_token == "fixed-token"
    assert settings.allowed_hosts == ("example.test", "localhost")
    assert settings.upload_dir.is_dir()
    assert settings.report_dir.is_dir()
    assert settings.provider_cache_dir.is_dir()
    assert settings.attack_artifact_dir.is_dir()
    assert sqlite_path_from_url("sqlite:///:memory:") is None
    assert sqlite_path_from_url("sqlite:////tmp/workbench.db") == Path("/tmp/workbench.db")
    assert sqlite_path_from_url("sqlite:///relative.db") == Path("relative.db")
    assert sqlite_path_from_url("postgresql://localhost/workbench") is None


def test_workbench_settings_invalid_env_values_fall_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULN_PRIORITIZER_MAX_UPLOAD_MB", "0")
    monkeypatch.setenv("VULN_PRIORITIZER_ALLOWED_HOSTS", " , ")

    settings = load_workbench_settings()

    assert settings.max_upload_mb == 25
    assert settings.allowed_hosts == DEFAULT_ALLOWED_HOSTS

    monkeypatch.setenv("VULN_PRIORITIZER_MAX_UPLOAD_MB", "not-an-int")
    assert load_workbench_settings().max_upload_mb == 25


def test_db_init_uses_workbench_settings_and_migrations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, str]] = []
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'nested' / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
        attack_artifact_dir=tmp_path / "attack",
    )

    def fake_ensure_workbench_directories(active_settings: WorkbenchSettings) -> None:
        assert active_settings == settings
        calls.append(("ensure", active_settings.database_url))

    def fake_upgrade_database(database_url: str) -> None:
        calls.append(("upgrade", database_url))

    monkeypatch.setattr(db_command, "load_workbench_settings", lambda: settings)
    monkeypatch.setattr(
        db_command,
        "ensure_workbench_directories",
        fake_ensure_workbench_directories,
    )
    monkeypatch.setattr(db_command, "upgrade_database", fake_upgrade_database)

    db_command.db_init()

    assert calls == [("ensure", settings.database_url), ("upgrade", settings.database_url)]
    assert (tmp_path / "nested").is_dir()


def test_workbench_attack_artifact_path_requires_json() -> None:
    validate_attack_artifact_path(Path("attack.json"), label="ATT&CK mapping file")
    with pytest.raises(WorkbenchAttackValidationError, match="must be a JSON file"):
        validate_attack_artifact_path(Path("attack.csv"), label="ATT&CK mapping file")


def test_attack_stix_provider_parses_bundle_and_reports_guardrail_warnings(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "enterprise-attack.json"
    raw_payload = {
        "type": "bundle",
        "spec_version": "2.1",
        "x_mitre_attack_version": "16.1",
        "objects": [
            "ignored",
            {"type": "identity", "name": "MITRE"},
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "name": "Exploit Public-Facing Application",
                "x_mitre_domains": ["enterprise-attack"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1190",
                        "url": "https://attack.mitre.org/techniques/T1190/",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                    {"kill_chain_name": "other", "phase_name": "ignored"},
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Override Name",
                "x_mitre_domains": ["enterprise-attack"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
                "revoked": True,
                "x_mitre_deprecated": True,
            },
            {
                "type": "attack-pattern",
                "name": "Missing external ID",
                "external_references": [{"source_name": "mitre-attack"}],
            },
        ],
    }
    raw_content = b"stix fixture bytes"

    techniques, metadata, warnings = AttackStixProvider().load_payload(
        raw_payload,
        source_path=source_path,
        raw_content=raw_content,
    )

    assert techniques["T1190"].name == "Override Name"
    assert techniques["T1190"].revoked is True
    assert techniques["T1190"].deprecated is True
    assert techniques["T1190"].tactics == []
    assert metadata["attack_version"] == "16.1"
    assert metadata["domain"] == "enterprise"
    assert metadata["metadata_source"] == "mitre-attack-stix"
    assert metadata["metadata_file"] == str(source_path)
    assert metadata["stix_spec_version"] == "2.1"
    assert any("not a JSON object" in warning for warning in warnings)
    assert any("overrides duplicate T1190" in warning for warning in warnings)
    assert any("without ATT&CK external ID or name" in warning for warning in warnings)


def test_attack_stix_provider_rejects_non_bundle_payloads(tmp_path: Path) -> None:
    provider = AttackStixProvider()
    with pytest.raises(ValueError, match="must be a STIX bundle"):
        provider.load_payload({}, source_path=tmp_path / "bad.json", raw_content=b"{}")
    with pytest.raises(ValueError, match="missing an objects array"):
        provider.load_payload(
            {"type": "bundle"},
            source_path=tmp_path / "bad.json",
            raw_content=b"{}",
        )


def test_attack_metadata_provider_rejects_invalid_files(tmp_path: Path) -> None:
    provider = AttackMetadataProvider()

    with pytest.raises(FileNotFoundError, match="metadata file not found"):
        provider.load(tmp_path / "missing.json")

    non_json = tmp_path / "metadata.txt"
    non_json.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON file"):
        provider.load(non_json)

    invalid_json = tmp_path / "metadata.json"
    invalid_json.write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        provider.load(invalid_json)

    missing_techniques = tmp_path / "missing-techniques.json"
    missing_techniques.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="missing a techniques array"):
        provider.load(missing_techniques)


def test_attack_metadata_provider_parses_local_metadata_with_warnings(
    tmp_path: Path,
) -> None:
    metadata_file = tmp_path / "metadata.json"
    metadata_file.write_text(
        """
        {
          "attack_version": "16.1",
          "domain": "enterprise",
          "techniques": [
            "ignored",
            {"attack_object_id": "", "name": "Missing ID"},
            {
              "attack_object_id": "T1190",
              "name": "Exploit Public-Facing Application",
              "tactics": ["initial-access", "initial-access", null],
              "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
              "attack_object_id": "T1190",
              "name": "Override",
              "tactics": "not-list",
              "revoked": true,
              "deprecated": true
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    techniques, metadata, warnings = AttackMetadataProvider().load(metadata_file)

    assert techniques["T1190"].name == "Override"
    assert techniques["T1190"].tactics == []
    assert techniques["T1190"].revoked is True
    assert techniques["T1190"].deprecated is True
    assert metadata["attack_version"] == "16.1"
    assert metadata["domain"] == "enterprise"
    assert metadata["metadata_source"] == "local-technique-metadata"
    assert metadata["metadata_file"] == str(metadata_file)
    assert any("not a JSON object" in warning for warning in warnings)
    assert any("without attack_object_id or name" in warning for warning in warnings)
    assert any("overrides duplicate T1190" in warning for warning in warnings)


def test_attack_metadata_provider_delegates_stix_bundle(tmp_path: Path) -> None:
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text('{"type": "bundle", "objects": []}', encoding="utf-8")

    techniques, metadata, warnings = AttackMetadataProvider().load(bundle_file)

    assert techniques == {}
    assert metadata["metadata_source"] == "mitre-attack-stix"
    assert warnings == []
