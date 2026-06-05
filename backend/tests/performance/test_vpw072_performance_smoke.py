from __future__ import annotations

import json
import os
import platform
import resource
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from utils.import_contracts import drain_workflow_queue, public_run_aliases
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

PROJECT_ROOT = Path(__file__).resolve().parents[3]
ROW_COUNT = int(os.getenv("VPW_PERFORMANCE_SMOKE_ROWS", "10000"))
PAGE_SIZE = 100
DEFAULT_IMPORT_LIMIT_SECONDS = 60.0
DEFAULT_PAGE_LIMIT_SECONDS = 1.0
DEFAULT_MEMORY_LIMIT_MIB = 512.0

pytestmark = pytest.mark.performance


def test_vpw072_workbench_import_10k_occurrences_performance_smoke(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    """Exercise the VPW-072 10k import, persistence, scoring, and pagination contract."""
    if os.getenv("VPW_PERFORMANCE_SMOKE") != "1":
        pytest.skip("Set VPW_PERFORMANCE_SMOKE=1 to run the optional VPW-072 scale smoke.")

    _configure_workbench_runtime(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    import_limit_seconds = float(
        os.getenv("VPW_PERFORMANCE_IMPORT_SECONDS", str(DEFAULT_IMPORT_LIMIT_SECONDS))
    )
    page_limit_seconds = float(
        os.getenv("VPW_PERFORMANCE_PAGE_SECONDS", str(DEFAULT_PAGE_LIMIT_SECONDS))
    )
    memory_limit_mib = float(os.getenv("VPW_PERFORMANCE_MEMORY_MIB", str(DEFAULT_MEMORY_LIMIT_MIB)))

    baseline_rss_mib = _max_rss_mib()
    test_start = time.perf_counter()

    fixture_start = time.perf_counter()
    content = _synthetic_occurrence_csv(ROW_COUNT)
    fixture_seconds = time.perf_counter() - fixture_start

    import_start = time.perf_counter()
    import_response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "generic-occurrence-csv",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("vpw-072-10k-occurrences.csv", content, "text/csv")},
    )
    import_payload: dict[str, Any]
    run_detail_status_code: int | None = None
    if import_response.status_code == 200:
        queued_payload = import_response.json()
        drain_workflow_queue(workbench_api_env, max_ticks=5)
        run_detail_response = workbench_api_env.client.get(
            f"/api/v1/runs/{queued_payload['id']}",
            headers=headers,
        )
        run_detail_status_code = run_detail_response.status_code
        import_payload = (
            public_run_aliases(run_detail_response.json())
            if run_detail_response.status_code == 200
            else queued_payload
        )
    else:
        import_payload = {}
    import_seconds = time.perf_counter() - import_start

    page_offset = ROW_COUNT - PAGE_SIZE
    first_page_start = time.perf_counter()
    first_page_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"sort": "cve", "direction": "asc", "limit": PAGE_SIZE, "offset": page_offset},
    )
    first_page_payload = (
        first_page_response.json() if first_page_response.status_code == 200 else {}
    )
    first_page_seconds = time.perf_counter() - first_page_start

    repeat_page_start = time.perf_counter()
    repeat_page_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"sort": "cve", "direction": "asc", "limit": PAGE_SIZE, "offset": page_offset},
    )
    repeat_page_payload = (
        repeat_page_response.json() if repeat_page_response.status_code == 200 else {}
    )
    repeat_page_seconds = time.perf_counter() - repeat_page_start

    peak_rss_mib = _max_rss_mib()
    total_seconds = time.perf_counter() - test_start

    summary = {
        "occurrence_count": import_payload.get("occurrence_count"),
        "finding_count": import_payload.get("finding_count"),
        "created_findings": import_payload.get("created_findings"),
        "updated_findings": import_payload.get("updated_findings"),
        "dedup_summary": import_payload.get("dedup_summary") or {},
        "locked_provider_data": import_payload.get("locked_provider_data"),
    }
    first_items = list(first_page_payload.get("data") or [])
    repeat_items = list(repeat_page_payload.get("data") or [])
    metrics = {
        "vpw_id": "VPW-072",
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "thresholds": {
            "row_count": ROW_COUNT,
            "import_seconds": import_limit_seconds,
            "tail_page_seconds": page_limit_seconds,
            "peak_rss_delta_mib": memory_limit_mib,
        },
        "measurements": {
            "fixture_bytes": len(content),
            "fixture_seconds": round(fixture_seconds, 4),
            "import_seconds": round(import_seconds, 4),
            "tail_page_seconds": round(first_page_seconds, 4),
            "tail_page_repeat_seconds": round(repeat_page_seconds, 4),
            "total_seconds": round(total_seconds, 4),
            "baseline_max_rss_mib": round(baseline_rss_mib, 3),
            "peak_rss_mib": round(peak_rss_mib, 3),
            "peak_rss_delta_mib": round(max(0.0, peak_rss_mib - baseline_rss_mib), 3),
        },
        "result": {
            "import_status_code": import_response.status_code,
            "run_detail_status_code": run_detail_status_code,
            "workflow_status": (import_payload.get("workflow") or {}).get("status")
            if isinstance(import_payload.get("workflow"), dict)
            else None,
            "analysis_run_status": import_payload.get("status"),
            "occurrence_count": summary.get("occurrence_count"),
            "finding_count": summary.get("finding_count"),
            "created_findings": summary.get("created_findings"),
            "updated_findings": summary.get("updated_findings"),
            "dedup_decision_count": (summary.get("dedup_summary") or {}).get("decision_count"),
            "locked_provider_data": summary.get("locked_provider_data"),
            "tail_page_status_code": first_page_response.status_code,
            "tail_page_count": first_page_payload.get("count"),
            "tail_page_items": len(first_items),
            "tail_page_stable": _finding_ids(first_items) == _finding_ids(repeat_items),
        },
    }
    _write_metrics(metrics)

    assert import_response.status_code == 200, import_response.text
    assert run_detail_status_code == 200
    assert import_payload["workflow"]["status"] == "succeeded"
    assert summary["locked_provider_data"] is True
    assert summary["occurrence_count"] == ROW_COUNT
    assert summary["finding_count"] == ROW_COUNT
    assert summary["created_findings"] == ROW_COUNT
    assert summary["updated_findings"] == 0
    assert summary["dedup_summary"]["decision_count"] == ROW_COUNT
    assert import_seconds <= import_limit_seconds, metrics

    assert first_page_response.status_code == 200, first_page_response.text
    assert repeat_page_response.status_code == 200, repeat_page_response.text
    assert first_page_payload["count"] == ROW_COUNT
    assert len(first_items) == PAGE_SIZE
    assert _finding_ids(first_items) == _finding_ids(repeat_items)
    assert first_page_seconds <= page_limit_seconds, metrics
    assert repeat_page_seconds <= page_limit_seconds, metrics
    assert metrics["measurements"]["peak_rss_delta_mib"] <= memory_limit_mib, metrics


def _configure_workbench_runtime(workbench_api_env: WorkbenchApiEnv, tmp_path: Path) -> None:
    active_settings = workbench_api_env.client.app.state.workbench_settings
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        IMPORT_UPLOAD_DIR=str(tmp_path / "workbench-import-uploads"),
        PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data"),
        ATTACK_ARTIFACT_DIR=str(PROJECT_ROOT / "data" / "attack"),
        MAX_UPLOAD_MB=10,
    )


def _synthetic_occurrence_csv(row_count: int) -> bytes:
    cves = ("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-44487", "CVE-2024-3094")
    lines = [
        "cve_id,target_ref,raw_severity,owner,business_service,exposure,environment,criticality"
    ]
    for index in range(row_count):
        lines.append(
            ",".join(
                [
                    cves[index % len(cves)],
                    f"vpw-072-workload-{index:05d}",
                    "critical" if index % 2 == 0 else "high",
                    f"team-{index % 20:02d}",
                    f"service-{index % 50:02d}",
                    "internet-facing" if index % 3 == 0 else "internal",
                    "production",
                    "critical" if index % 5 == 0 else "high",
                ]
            )
        )
    return ("\n".join(lines) + "\n").encode()


def _finding_ids(items: list[Any]) -> list[str]:
    return [str(item["id"]) for item in items]


def _max_rss_mib() -> float:
    raw = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    bytes_value = raw if sys.platform == "darwin" else raw * 1024
    return bytes_value / 1024 / 1024


def _write_metrics(metrics: dict[str, Any]) -> None:
    output = Path(os.getenv("VPW_PERFORMANCE_SMOKE_OUTPUT", "build/vpw-072-performance-smoke.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
