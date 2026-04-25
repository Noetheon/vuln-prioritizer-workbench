from __future__ import annotations

from sqlalchemy import inspect, select

from vuln_prioritizer.db import (
    Finding,
    WorkbenchRepository,
    create_schema,
    create_session_factory,
    create_sqlite_engine,
)
from vuln_prioritizer.db.migrations import WORKBENCH_TABLES, get_target_metadata
from vuln_prioritizer.db.session import session_scope


def test_in_memory_sqlite_schema_contains_mvp_tables() -> None:
    engine = create_sqlite_engine(":memory:")

    create_schema(engine)

    table_names = set(inspect(engine).get_table_names())
    assert set(WORKBENCH_TABLES).issubset(table_names)
    assert get_target_metadata().tables.keys() >= set(WORKBENCH_TABLES)


def test_temp_sqlite_schema_creates_database_file(tmp_path) -> None:
    db_path = tmp_path / "workbench.sqlite"
    engine = create_sqlite_engine(db_path)

    create_schema(engine)

    assert db_path.exists()
    assert set(WORKBENCH_TABLES).issubset(inspect(engine).get_table_names())


def test_repository_round_trip_persists_workbench_finding() -> None:
    engine = create_sqlite_engine(":memory:")
    create_schema(engine)
    factory = create_session_factory(engine)

    with session_scope(factory) as session:
        repo = WorkbenchRepository(session)
        project = repo.create_project("demo", "Demo service")
        provider_snapshot = repo.create_provider_snapshot(
            content_hash="sha256:demo",
            epss_date="2026-04-24",
            metadata_json={"sources": ["nvd", "epss", "kev"]},
        )
        run = repo.create_analysis_run(
            project_id=project.id,
            input_type="trivy-json",
            input_filename="trivy.json",
            status="running",
            provider_snapshot_id=provider_snapshot.id,
        )
        asset = repo.upsert_asset(
            project_id=project.id,
            asset_id="asset-api",
            target_ref="repo:api",
            owner="platform",
            business_service="checkout",
            environment="prod",
            exposure="internet-facing",
            criticality="critical",
        )
        component = repo.upsert_component(
            name="openssl",
            version="3.0.0",
            purl="pkg:generic/openssl@3.0.0",
            ecosystem="generic",
        )
        vulnerability = repo.upsert_vulnerability(
            cve_id="CVE-2026-0001",
            description="Synthetic test vulnerability.",
            cvss_score=9.8,
            severity="Critical",
            provider_json={"epss": 0.91, "kev": True},
        )
        finding = repo.create_or_update_finding(
            project_id=project.id,
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            component_id=component.id,
            asset_id=asset.id,
            priority="Critical",
            risk_score=98.0,
            operational_rank=1,
            explanation_json={"drivers": ["KEV", "internet-facing asset"]},
        )
        repo.upsert_attack_mapping(
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            attack_object_id="T1190",
            attack_object_name="Exploit Public-Facing Application",
            mapping_type="exploitation_technique",
            source="ctid",
            source_hash="f" * 64,
            source_path="data/attack/mapping.json",
            metadata_hash="e" * 64,
            metadata_path="data/attack/metadata.json",
            confidence=1.0,
            review_status="source_reviewed",
            rationale="Imported from CTID mapping fixture.",
            references_json=["https://example.invalid/advisory"],
            mapping_json={"attack_object_id": "T1190"},
        )
        repo.create_or_update_finding_attack_context(
            finding_id=finding.id,
            analysis_run_id=run.id,
            cve_id=vulnerability.cve_id,
            mapped=True,
            source="ctid",
            source_hash="f" * 64,
            source_path="data/attack/mapping.json",
            metadata_hash="e" * 64,
            metadata_path="data/attack/metadata.json",
            attack_relevance="High",
            threat_context_rank=1,
            review_status="source_reviewed",
            techniques_json=[
                {
                    "attack_object_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactics": ["initial-access"],
                }
            ],
            tactics_json=["initial-access"],
            mappings_json=[{"attack_object_id": "T1190"}],
        )
        repo.add_finding_occurrence(
            finding_id=finding.id,
            analysis_run_id=run.id,
            scanner="trivy",
            raw_reference="trivy:0",
            fix_version="3.0.9",
            evidence_json={"path": "/app/requirements.txt"},
        )
        repo.finish_analysis_run(run.id, summary_json={"findings": 1})

    with session_scope(factory) as session:
        repo = WorkbenchRepository(session)
        project = repo.get_project_by_name("demo")
        assert project is not None

        findings = repo.list_project_findings(project.id)
        assert len(findings) == 1
        assert findings[0].vulnerability.cve_id == "CVE-2026-0001"
        assert findings[0].component is not None
        assert findings[0].component.name == "openssl"
        assert findings[0].asset is not None
        assert findings[0].asset.business_service == "checkout"
        assert findings[0].occurrences[0].fix_version == "3.0.9"
        assert findings[0].attack_contexts[0].source == "ctid"
        assert findings[0].attack_contexts[0].source_hash == "f" * 64
        assert findings[0].attack_contexts[0].metadata_hash == "e" * 64
        assert findings[0].attack_contexts[0].threat_context_rank == 1
        assert findings[0].explanation_json["drivers"] == ["KEV", "internet-facing asset"]
        top_contexts = repo.list_project_attack_contexts(project.id)
        assert top_contexts[0].techniques_json[0]["attack_object_id"] == "T1190"


def test_repository_upserts_reuse_existing_records() -> None:
    engine = create_sqlite_engine(":memory:")
    create_schema(engine)
    factory = create_session_factory(engine)

    with session_scope(factory) as session:
        repo = WorkbenchRepository(session)
        project = repo.create_project("upserts")
        first_asset = repo.upsert_asset(project_id=project.id, asset_id="api", owner="team-a")
        second_asset = repo.upsert_asset(project_id=project.id, asset_id="api", owner="team-b")
        first_vuln = repo.upsert_vulnerability(cve_id="CVE-2026-0002", severity="High")
        second_vuln = repo.upsert_vulnerability(cve_id="CVE-2026-0002", severity="Critical")

        assert first_asset.id == second_asset.id
        assert second_asset.owner == "team-b"
        assert first_vuln.id == second_vuln.id
        assert second_vuln.severity == "Critical"

        finding = repo.create_or_update_finding(
            project_id=project.id,
            vulnerability_id=second_vuln.id,
            cve_id=second_vuln.cve_id,
            asset_id=second_asset.id,
            priority="High",
        )
        same_finding = repo.create_or_update_finding(
            project_id=project.id,
            vulnerability_id=second_vuln.id,
            cve_id=second_vuln.cve_id,
            asset_id=second_asset.id,
            priority="Critical",
        )

        assert finding.id == same_finding.id

    with session_scope(factory) as session:
        assert session.scalar(select(Finding.priority)) == "Critical"
