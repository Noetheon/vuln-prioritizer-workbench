"""Import CSV rows through the API against the bundled demo provider snapshot."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from utils.import_contracts import completed_run_summary
from utils.workbench_env import WorkbenchApiEnv

DEMO_SNAPSHOT = (
    Path(__file__).resolve().parents[2] / "app" / "resources" / "demo_provider_snapshot.json"
)
GENERIC_CSV_HEADER = b"cve_id,target_ref,component_name,component_version\n"


def configure_demo_imports(env: WorkbenchApiEnv, tmp_path: Path) -> None:
    """Point uploads, reports, and the locked provider snapshot at ``tmp_path``."""
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(exist_ok=True)
    (snapshots / "demo.json").write_bytes(DEMO_SNAPSHOT.read_bytes())
    env.client.app.state.workbench_settings = replace(
        env.client.app.state.workbench_settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshots),
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
        REPORT_DIR=str(tmp_path / "reports"),
    )


def import_demo_rows(
    env: WorkbenchApiEnv,
    project_id: str,
    rows: list[bytes],
    *,
    input_type: str = "generic-occurrence-csv",
    resolve_missing: bool | None = None,
) -> dict[str, object]:
    """Import rows with the locked demo snapshot and return the finished run summary."""
    data = {
        "input_type": input_type,
        "provider_snapshot_file": "demo.json",
        "locked_provider_data": "true",
    }
    if resolve_missing is not None:
        data["resolve_missing"] = "true" if resolve_missing else "false"
    body = b"".join(rows) if input_type == "cve-list" else GENERIC_CSV_HEADER + b"".join(rows)
    response = env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        data=data,
        files={"file": ("scan.csv" if input_type != "cve-list" else "cves.txt", body, "text/csv")},
    )
    summary = completed_run_summary(env, response, headers={})
    assert summary["status"] == "succeeded", summary
    return summary
