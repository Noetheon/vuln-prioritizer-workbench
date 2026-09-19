"""Opt-in real Grype through HTTP upload, worker, Decision Ledger and evidence ZIP."""

from __future__ import annotations

import json
import os
import zipfile
from dataclasses import replace
from io import BytesIO
from pathlib import Path

import pytest
from paths import REPO_ROOT
from utils.import_contracts import completed_run_payload, configure_upload_dir
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers


@pytest.mark.skipif(
    not os.environ.get("VPW_TEST_GRYPE_BINARY") or not os.environ.get("VPW_TEST_GRYPE_DB"),
    reason="Set VPW_TEST_GRYPE_BINARY and VPW_TEST_GRYPE_DB for the real local scanner gate.",
)
@pytest.mark.parametrize(
    "name,input_type",
    [
        ("vulnerable.cdx.json", "cyclonedx-json"),
        ("vulnerable.spdx.json", "spdx-json"),
        ("zero.cdx.json", "cyclonedx-json"),
    ],
)
def test_real_grype_upload_worker_and_evidence(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    name: str,
    input_type: str,
) -> None:
    env = workbench_api_env
    configure_upload_dir(env, tmp_path)
    cache = tmp_path / "provider-cache"
    cache.mkdir()
    (cache / "grype").symlink_to(
        Path(os.environ["VPW_TEST_GRYPE_DB"]).resolve(), target_is_directory=True
    )
    env.client.app.state.workbench_settings = replace(
        env.client.app.state.workbench_settings,
        SBOM_GRYPE_EXECUTABLE=str(Path(os.environ["VPW_TEST_GRYPE_BINARY"]).resolve()),
        PROVIDER_CACHE_DIR=str(cache),
    )
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)
    source = (REPO_ROOT / "docs/examples" / f"sbom-{name}").read_bytes()
    response = env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": input_type,
            "sbom_scanner": "grype",
            "sbom_target_ref": "real-example@1",
            "sbom_db_update": "false",
        },
        files={"file": (name, source, "application/json")},
    )
    run = completed_run_payload(env, response, headers=headers)
    assert run["status"] == "succeeded", json.dumps(run, indent=2)
    assessment = run["evidence"]["sbom_assessment"]
    assert assessment["scanner_version"]
    assert assessment["database_sha256"]
    if name.startswith("vulnerable"):
        assert run["evidence"]["counts"]["finding_count"] > 0
    # Zero is a DB-dependent observation, not a timeless claim about this package.
    download = env.client.get(f"/api/v1/runs/{run['id']}/sbom-evidence", headers=headers)
    assert download.status_code == 200, download.text
    with zipfile.ZipFile(BytesIO(download.content)) as bundle:
        assert bundle.read("sbom.json") == source
        assert (
            json.loads(bundle.read("assessment.json"))["output_sha256"]
            == assessment["output_sha256"]
        )
    if output := os.environ.get("VPW_SBOM_VALIDATION_OUTPUT"):
        directory = Path(output)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{name}.api-result.json").write_text(json.dumps(run, indent=2))
        (directory / f"{name}.evidence.zip").write_bytes(download.content)
