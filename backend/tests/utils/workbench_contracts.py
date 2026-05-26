from __future__ import annotations

import hashlib
import json
import uuid
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from utils.report_contract_fixtures import replace
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    DEMO_CVE_XZ,
    WorkbenchApiEnv,
    create_asset,
    create_component,
    create_finding,
    create_project_via_api,
    create_vulnerability,
    local_api_headers,
)


def _layer_metadata(layer: dict[str, Any], key: str) -> str | None:
    for item in layer.get("metadata", []):
        if item.get("name") == key:
            return item.get("value")
    return None


def _technique_metadata(technique: dict[str, Any], key: str) -> str | None:
    for item in technique.get("metadata", []):
        if item.get("name") == key:
            return item.get("value")
    return None


def _configure_report_dir(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    **settings_overrides: Any,
) -> Path:
    report_dir = (tmp_path / "workbench-reports").resolve(strict=False)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    overrides = {"MAX_REPORT_MB": 50, "MAX_REPORTS_PER_RUN": 20, **settings_overrides}
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        REPORT_DIR=str(report_dir),
        **overrides,
    )
    return report_dir


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_schema(filename: str) -> dict[str, Any]:
    schema_path = _repo_root() / "docs" / "schemas" / filename
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _normalize_html_snapshot(value: str) -> str:
    lines = [line.rstrip() for line in value.replace("\r\n", "\n").splitlines() if line.strip()]
    return "\n".join(lines) + "\n"


def _replace_zip_member(bundle: bytes, member_path: str, replacement: bytes) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(BytesIO(bundle), "r") as source:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as target:
            for source_info in source.infolist():
                content = (
                    replacement
                    if source_info.filename == member_path
                    else source.read(source_info.filename)
                )
                target_info = zipfile.ZipInfo(
                    filename=source_info.filename,
                    date_time=source_info.date_time,
                )
                target_info.compress_type = source_info.compress_type
                target_info.create_system = source_info.create_system
                target_info.external_attr = source_info.external_attr
                target.writestr(target_info, content)
    return output.getvalue()


def _add_vpw051_bundle_metadata(
    workbench_api_env: WorkbenchApiEnv,
    run_id: uuid.UUID,
    tmp_path: Path,
) -> dict[str, Any]:
    app_models = workbench_api_env.app_models
    upload_path = tmp_path / "private" / "known-cves.txt"
    upload_content = f"{DEMO_CVE_XZ}\n{DEMO_CVE_LOG4SHELL}\n".encode()
    upload_path.parent.mkdir(parents=True, exist_ok=True)
    upload_path.write_bytes(upload_content)
    input_metadata = {
        "path": upload_path.name,
        "size_bytes": len(upload_content),
        "sha256": hashlib.sha256(upload_content).hexdigest(),
    }
    with Session(workbench_api_env.engine) as session:
        run = session.get(app_models.AnalysisRun, run_id)
        assert run is not None
        run.summary_json = {
            **dict(run.summary_json or {}),
            "input_sha256": input_metadata["sha256"],
            "input_upload": {
                "original_filename": upload_path.name,
                "stored_filename": upload_path.name,
                "size_bytes": input_metadata["size_bytes"],
                "sha256": input_metadata["sha256"],
                "path": str(upload_path),
                "token": "super-secret-token",
            },
        }
        run.error_json = {"authorization": "Bearer super-secret-token"}
        if run.provider_snapshot is not None:
            run.provider_snapshot.source_metadata_json = {
                **dict(run.provider_snapshot.source_metadata_json or {}),
                "source_path": str(tmp_path / "private" / "provider-snapshot.json"),
                "api_key": "provider-secret-key",
                "cache_dir": str(tmp_path / "private" / "cache"),
            }
            session.add(run.provider_snapshot)
        finding = session.exec(
            select(app_models.Finding)
            .where(app_models.Finding.project_id == run.project_id)
            .where(app_models.Finding.cve_id == DEMO_CVE_XZ)
        ).first()
        assert finding is not None
        finding.recommended_action = "Patch after using super-secret-token in the approval system."
        finding.rationale = f"Review local evidence from {tmp_path}/private/vpw-051-input.txt."
        finding.evidence_json = {
            "source": "snapshot",
            "authorization": "Bearer super-secret-token",
            "upload_path": str(upload_path),
        }
        session.add(finding)
        session.add(run)
        session.commit()
    return input_metadata


def _add_vpw060_attack_contexts(
    workbench_api_env: WorkbenchApiEnv,
    run_id: uuid.UUID,
) -> None:
    app_models_for_env = workbench_api_env.app_models
    with Session(workbench_api_env.engine) as session:
        run = session.get(app_models_for_env.AnalysisRun, run_id)
        assert run is not None
        findings = {
            finding.cve_id: finding
            for finding in session.exec(
                select(app_models_for_env.Finding).where(
                    app_models_for_env.Finding.project_id == run.project_id
                )
            ).all()
        }
        log4shell = findings[DEMO_CVE_LOG4SHELL]
        xz = findings[DEMO_CVE_XZ]
        for finding, technique_id, technique_name, tactic, confidence, review_status in (
            (
                log4shell,
                "T1190",
                "Exploit Public-Facing Application",
                "initial-access",
                "medium",
                "reviewed",
            ),
            (
                xz,
                "T1059",
                "Command and Scripting Interpreter",
                "execution",
                "low",
                "needs_review",
            ),
        ):
            finding.attack_mapped = True
            finding.explanation_json = {
                **dict(finding.explanation_json or {}),
                "attack_techniques": [technique_id],
            }
            session.add(finding)
            session.add(
                app_models_for_env.FindingAttackContext(
                    finding_id=finding.id,
                    analysis_run_id=run.id,
                    cve_id=finding.cve_id,
                    mapped=True,
                    source="local-curated",
                    review_status=review_status,
                    defensive_note="Defensive triage context only; validate before action.",
                    rationale="Reviewed local ATT&CK mapping for defensive prioritization.",
                    technique_ids_json=[technique_id],
                    tactic_ids_json=[tactic],
                    mappings_json=[
                        {
                            "technique_id": technique_id,
                            "technique_name": technique_name,
                            "attack_object_id": technique_id,
                            "attack_object_name": technique_name,
                            "tactics": [tactic],
                            "confidence": confidence,
                            "review_status": review_status,
                            "source": "local-curated",
                            "mapping_type": "exploitation",
                            "defensive_note": "Use for defensive triage and coverage review.",
                            "rationale": "Reviewed local mapping; no procedural detail included.",
                        }
                    ],
                )
            )
        session.commit()


def _seed_reportable_run(workbench_api_env: WorkbenchApiEnv, project_id: uuid.UUID) -> uuid.UUID:
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    with Session(workbench_api_env.engine) as session:
        run_repo = repositories.RunRepository(session)
        snapshot = run_repo.get_or_create_provider_snapshot(
            content_hash="sha256:vpw048-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            source_hashes_json={"provider_snapshot": "sha256:vpw048-snapshot"},
            source_metadata_json={
                "locked_provider_data": True,
                "selected_sources": ["nvd", "epss", "kev"],
                "source_path": "demo_provider_snapshot.json",
                "item_count": 2,
            },
        )
        run = run_repo.create_analysis_run(
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            input_type="cve-list",
            filename="known-cves.txt",
            status=app_models.AnalysisRunStatus.COMPLETED,
            summary_json={
                "finding_count": 2,
                "counts_by_priority": {"Critical": 1, "High": 1},
                "locked_provider_data": True,
            },
        )
        first = _seed_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            cve_id=DEMO_CVE_LOG4SHELL,
            asset_key="ops-api",
            asset_name="Ops <img src=x onerror=alert(1)> API",
            component_name="log4j-core",
            component_version="2.14.1",
            priority=app_models.FindingPriority.HIGH,
            priority_rank=2,
            operational_rank=2,
            risk_score=94.2,
            epss=0.944,
            cvss=10.0,
            in_kev=True,
            rationale="KEV-listed issue with <script>alert(1)</script> evidence.",
            action="Patch via vendor upgrade.",
            confidence="medium",
            flags=[{"code": "missing_asset_owner", "message": "Owner missing <img>"}],
        )
        second = _seed_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            cve_id=DEMO_CVE_XZ,
            asset_key="payments-api",
            asset_name="Payments <script>alert(1)</script> API",
            component_name="xz",
            component_version="5.6.0-r0",
            priority=app_models.FindingPriority.CRITICAL,
            priority_rank=1,
            operational_rank=1,
            risk_score=100.0,
            epss=0.846,
            cvss=10.0,
            in_kev=False,
            rationale="Internet-facing production asset with critical score.",
            action="Patch [open](javascript:alert(1)) now.",
            confidence="high",
            flags=[],
        )
        run_repo.add_finding_occurrence(
            finding_id=first.id,
            analysis_run_id=run.id,
            source="cve-list",
            raw_reference=DEMO_CVE_LOG4SHELL,
        )
        run_repo.add_finding_occurrence(
            finding_id=second.id,
            analysis_run_id=run.id,
            source="cve-list",
            raw_reference=DEMO_CVE_XZ,
        )
        run_id = run.id
        session.commit()
        return run_id


def _seed_formula_run(workbench_api_env: WorkbenchApiEnv, project_id: uuid.UUID) -> uuid.UUID:
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    with Session(workbench_api_env.engine) as session:
        run_repo = repositories.RunRepository(session)
        snapshot = run_repo.get_or_create_provider_snapshot(
            content_hash="sha256:vpw050-formula-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
        )
        run = run_repo.create_analysis_run(
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            input_type="generic-occurrence-csv",
            filename="formula-cells.csv",
            status=app_models.AnalysisRunStatus.COMPLETED,
            summary_json={"finding_count": 1},
        )
        finding = _seed_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            cve_id=DEMO_CVE_XZ,
            asset_key="=asset-key",
            asset_name="=asset-name",
            asset_owner="+owner",
            asset_business_service="@service",
            component_name='=HYPERLINK("https://example.invalid")',
            component_version="5.6.0",
            priority=app_models.FindingPriority.CRITICAL,
            priority_rank=1,
            operational_rank=1,
            risk_score=100.0,
            epss=0.846,
            cvss=10.0,
            in_kev=False,
            rationale="\tTabbed rationale",
            action="-Patch now",
            confidence="high",
            flags=[{"code": "\tformula_flag", "message": "flag"}],
        )
        run_repo.add_finding_occurrence(
            finding_id=finding.id,
            analysis_run_id=run.id,
            source="generic-occurrence-csv",
            raw_reference=DEMO_CVE_XZ,
        )
        run_id = run.id
        session.commit()
        return run_id


def _seed_finding(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
    cve_id: str,
    asset_key: str,
    asset_name: str,
    component_name: str,
    component_version: str,
    priority: Any,
    priority_rank: int,
    operational_rank: int,
    risk_score: float,
    epss: float,
    cvss: float,
    in_kev: bool,
    rationale: str,
    action: str,
    confidence: str,
    flags: list[dict[str, str]],
    asset_owner: str | None = None,
    asset_business_service: str | None = None,
) -> Any:
    asset = create_asset(
        session,
        app_models,
        repositories,
        project_id=project_id,
        asset_key=asset_key,
        name=asset_name,
    )
    if asset_owner is not None:
        asset.owner = asset_owner
    if asset_business_service is not None:
        asset.business_service = asset_business_service
    component = create_component(
        session,
        repositories,
        name=component_name,
        version=component_version,
    )
    vulnerability = create_vulnerability(session, repositories, cve_id=cve_id, cvss_score=cvss)
    finding = create_finding(
        session,
        app_models,
        repositories,
        project_id=project_id,
        vulnerability_id=vulnerability.id,
        component_id=component.id,
        asset_id=asset.id,
        cve_id=cve_id,
        priority=priority,
        priority_rank=priority_rank,
        operational_rank=operational_rank,
    )
    finding.risk_score = risk_score
    finding.epss = epss
    finding.cvss_base_score = cvss
    finding.in_kev = in_kev
    finding.rationale = rationale
    finding.recommended_action = action
    finding.data_quality_json = {"confidence": confidence, "flags": flags}
    finding.explanation_json = {
        "data_quality_confidence": confidence,
        "data_quality_flags": flags,
        "decision_guidance": {
            "decision_statement": (
                f"Decision Statement: remediate {cve_id} on {asset_name} with the "
                "assigned owner before the emergency SLA expires."
            ),
            "business_impact": {
                "text": (
                    f"Executive attention is warranted for {asset_name} because the "
                    f"finding combines {priority} priority with provider-backed risk signals."
                ),
            },
            "sla": {"label": "Emergency", "target_hours": 24},
        },
    }
    session.flush()
    return finding


def _seed_status_run(workbench_api_env: WorkbenchApiEnv, status: str) -> uuid.UUID:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    with Session(workbench_api_env.engine) as session:
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=uuid.UUID(project["id"]),
            input_type="cve-list",
            filename=f"{status}.txt",
            status=status,
        )
        run_id = run.id
        session.commit()
        return run_id


def _seed_secondary_project_report(
    workbench_api_env: WorkbenchApiEnv,
    secondary_project: dict[str, uuid.UUID],
) -> uuid.UUID:
    report_id = uuid.uuid4()
    with Session(workbench_api_env.engine) as session:
        workbench_api_env.repositories.ReportRepository(session).create_report(
            report_id=report_id,
            project_id=secondary_project["project_id"],
            analysis_run_id=secondary_project["run_id"],
            kind="technical-markdown",
            format="markdown",
            filename="technical-report.md",
            content_type="text/markdown; charset=utf-8",
            path="data/workbench-reports/secondary_project/technical-report.md",
            sha256="0" * 64,
            size_bytes=0,
            metadata_json={},
        )
        session.commit()
    return report_id
