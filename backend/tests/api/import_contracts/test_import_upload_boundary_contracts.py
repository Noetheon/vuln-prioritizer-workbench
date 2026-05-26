from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from utils.import_contracts import (
    run_upload_size_guard as _run_upload_size_guard,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
)

from app.domain.import_asset_context import (
    canonicalize_asset_criticality_value,
    canonicalize_asset_environment_value,
    canonicalize_asset_exposure_value,
)
from app.services import import_uploads as upload_helpers
from app.services.import_errors import ImportServiceError
from app.services.workbench_capabilities import (
    SIDE_CAR_UPLOAD_CAPABILITIES,
    allowed_upload_mime_hints,
    allowed_upload_suffixes,
)


def test_import_asset_context_adapter_reuses_core_alias_canonicalization() -> None:
    assert canonicalize_asset_exposure_value("private") == "internal"
    assert canonicalize_asset_exposure_value("internal") == "internal"
    assert canonicalize_asset_environment_value("qa") == "test"
    assert canonicalize_asset_environment_value("test") == "test"
    assert canonicalize_asset_criticality_value("crit") == "critical"
    assert canonicalize_asset_criticality_value("critical") == "critical"


def test_import_upload_helper_rejects_oversized_chunks(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    class ChunkedUpload:
        def __init__(self, chunks: list[bytes]) -> None:
            self.chunks = chunks

        async def read(self, size: int = -1) -> bytes:
            return self.chunks.pop(0) if self.chunks else b""

    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
        MAX_UPLOAD_MB=1,
    )

    assert (
        asyncio.run(
            upload_helpers.read_bounded_upload(
                ChunkedUpload([b"hello", b"world"]),
                settings=active_settings,
                max_bytes=16,
            )
        )
        == b"helloworld"
    )
    with pytest.raises(ImportServiceError, match="Upload exceeds configured limit"):
        asyncio.run(
            upload_helpers.read_bounded_upload(
                ChunkedUpload([b"abc", b"def"]),
                settings=active_settings,
                max_bytes=5,
            )
        )


def test_upload_middleware_rejects_streaming_body_without_content_length() -> None:
    response = asyncio.run(
        _run_upload_size_guard(
            [
                {
                    "type": "http.request",
                    "body": b"A" * (1024 * 1024),
                    "more_body": True,
                },
                {
                    "type": "http.request",
                    "body": b"B" * (128 * 1024),
                    "more_body": False,
                },
            ],
        )
    )

    assert response.status_code == 413


def test_upload_middleware_allows_streaming_body_within_limit() -> None:
    response = asyncio.run(
        _run_upload_size_guard(
            [
                {
                    "type": "http.request",
                    "body": b"CVE-2024-3094\n",
                    "more_body": False,
                },
            ],
        )
    )

    assert response.status_code == 200


def test_upload_middleware_rejects_oversized_non_upload_api_body() -> None:
    response = asyncio.run(
        _run_upload_size_guard(
            [
                {
                    "type": "http.request",
                    "body": b"A" * (1024 * 1024 + 1),
                    "more_body": False,
                },
            ],
            max_request_body_mb=1,
            route_suffix="/waivers/",
        )
    )

    assert response.status_code == 413
    payload = json.loads(response.body)
    assert payload["code"] == "request_body_too_large"
    assert payload["detail"] == "Request body exceeds configured limit."


def test_upload_middleware_rejects_streaming_body_with_custom_api_prefix() -> None:
    response = asyncio.run(
        _run_upload_size_guard(
            [
                {
                    "type": "http.request",
                    "body": b"A" * (1024 * 1024),
                    "more_body": True,
                },
                {
                    "type": "http.request",
                    "body": b"B" * (128 * 1024),
                    "more_body": False,
                },
            ],
            api_prefix="/api/custom",
        )
    )

    assert response.status_code == 413


def test_upload_middleware_rejects_asset_import_with_custom_api_prefix() -> None:
    response = asyncio.run(
        _run_upload_size_guard(
            [
                {
                    "type": "http.request",
                    "body": b"A" * (1024 * 1024),
                    "more_body": True,
                },
                {
                    "type": "http.request",
                    "body": b"B" * (128 * 1024),
                    "more_body": False,
                },
            ],
            api_prefix="/api/custom",
            route_suffix="/assets/import",
        )
    )

    assert response.status_code == 413


def test_import_upload_helper_edge_validations_and_safe_names(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
        MAX_UPLOAD_MB=1,
    )

    with pytest.raises(ImportServiceError, match="Upload exceeds configured limit"):
        upload_helpers.validate_aggregate_upload_size(
            settings=active_settings,
            payloads=[b"x" * active_settings.max_upload_bytes, b"y"],
        )
    upload_helpers.validate_asset_context_upload("context.csv", "application/octet-stream")
    upload_helpers.validate_vex_upload("openvex.json", "")
    assert (
        upload_helpers.sanitize_context_filename(
            "input.txt",
            reserved_filename="input.txt",
        )
        == "asset_context_input.txt"
    )
    assert (
        upload_helpers.sanitize_vex_filename(
            "input.txt",
            reserved_filenames={"input.txt", None},
        )
        == "vex_input.txt"
    )
    assert upload_helpers.ignored_line_count("cve-list", b"\xff\xfe") == 0
    upload_helpers.validate_mime_hint("application/octet-stream", input_type="trivy-json")
    with pytest.raises(ImportServiceError, match="Upload filename is not allowed"):
        upload_helpers.reject_unsafe_upload_filename("bad\x00name.txt")
    with pytest.raises(ImportServiceError, match="input_type is required"):
        upload_helpers.normalize_input_type("   ")


def test_upload_validation_constants_are_derived_from_capabilities() -> None:
    assert upload_helpers.ALLOWED_UPLOAD_SUFFIXES == allowed_upload_suffixes()
    assert upload_helpers.ALLOWED_UPLOAD_MIME_HINTS == allowed_upload_mime_hints()
    assert upload_helpers.SIDE_CAR_UPLOADS_BY_ID == {
        capability.id: capability for capability in SIDE_CAR_UPLOAD_CAPABILITIES
    }


def test_import_upload_store_rejects_escape_and_cleans_failed_write(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
    )
    project_id = uuid.uuid4()
    run_id = uuid.uuid4()

    with pytest.raises(ImportServiceError, match="Upload path is not allowed"):
        upload_helpers.store_upload(
            active_settings,
            project_id=project_id,
            run_id=run_id,
            filename="../../../escape.txt",
            content=b"blocked",
        )

    target_dir = active_settings.import_upload_dir_path / str(project_id) / str(run_id)
    with pytest.raises(IsADirectoryError):
        upload_helpers.store_upload(
            active_settings,
            project_id=project_id,
            run_id=run_id,
            filename=".",
            content=b"cannot write to directory",
        )
    assert not target_dir.exists()
