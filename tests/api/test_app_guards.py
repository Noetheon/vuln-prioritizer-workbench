from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from vuln_prioritizer.api import app as app_module
from vuln_prioritizer.api import routes as api_routes
from vuln_prioritizer.workbench_config import WorkbenchSettings


def test_upload_size_guard_rejects_oversized_import_upload() -> None:
    async def _exercise() -> None:
        request = _request(
            path="/api/projects/project-1/imports",
            method="POST",
            content_length=str((1 * 1024 * 1024) + (64 * 1024) + 1),
        )

        response = await app_module._upload_size_guard(  # noqa: SLF001
            request,
            _ok_response,
        )

        assert response.status_code == 413
        payload = json.loads(response.body)
        assert payload["detail"] == "Upload exceeds configured limit."
        assert payload["error"]["code"] == "payload_too_large"
        assert payload["error"]["details"]["max_upload_bytes"] == 1024 * 1024

    asyncio.run(_exercise())


def test_upload_size_guard_ignores_invalid_content_length_and_non_import_paths() -> None:
    async def _exercise() -> None:
        invalid_length_request = _request(
            path="/api/projects/project-1/imports",
            method="POST",
            content_length="not-an-int",
        )
        non_import_request = _request(path="/api/projects/project-1", method="POST")

        invalid_length_response = await app_module._upload_size_guard(  # noqa: SLF001
            invalid_length_request,
            _ok_response,
        )
        non_import_response = await app_module._upload_size_guard(  # noqa: SLF001
            non_import_request,
            _ok_response,
        )

        assert invalid_length_response.status_code == 200
        assert non_import_response.status_code == 200

    asyncio.run(_exercise())


def test_error_handlers_keep_additive_error_envelope() -> None:
    async def _exercise() -> None:
        unexpected = await app_module._unexpected_error_handler(  # noqa: SLF001
            _request(path="/api/debug"),
            RuntimeError("boom"),
        )
        non_http = await app_module._http_error_handler(  # noqa: SLF001
            _request(path="/api/debug"),
            RuntimeError("boom"),
        )
        http = await app_module._http_error_handler(  # noqa: SLF001
            _request(path="/api/debug"),
            HTTPException(status_code=403, detail={"reason": "csrf"}),
        )
        validation = await app_module._validation_error_handler(  # noqa: SLF001
            _request(path="/api/debug"),
            RequestValidationError(
                [{"loc": ("query", "limit"), "msg": "bad value", "type": "value_error"}]
            ),
        )
        non_validation = await app_module._validation_error_handler(  # noqa: SLF001
            _request(path="/api/debug"),
            RuntimeError("boom"),
        )

        assert unexpected.status_code == 500
        assert json.loads(unexpected.body)["error"]["code"] == "internal_error"
        assert json.loads(non_http.body)["error"]["code"] == "internal_error"
        assert http.status_code == 403
        assert json.loads(http.body)["error"]["code"] == "forbidden"
        assert json.loads(http.body)["error"]["details"] == {"reason": "csrf"}
        assert validation.status_code == 422
        assert json.loads(validation.body)["error"]["code"] == "validation_error"
        assert json.loads(non_validation.body)["error"]["code"] == "internal_error"

    asyncio.run(_exercise())


def test_web_error_handlers_render_workbench_error_pages() -> None:
    async def _exercise() -> None:
        http = await app_module._http_error_handler(  # noqa: SLF001
            _request(path="/projects"),
            HTTPException(status_code=409, detail="Project already exists."),
        )
        validation = await app_module._validation_error_handler(  # noqa: SLF001
            _request(path="/projects/new"),
            RequestValidationError(
                [{"loc": ("form", "name"), "msg": "missing", "type": "missing"}]
            ),
        )

        http_body = http.body.decode()
        validation_body = validation.body.decode()
        assert http.status_code == 409
        assert http.headers["content-type"].startswith("text/html")
        assert "409 Conflict" in http_body
        assert "Project already exists." in http_body
        assert "conflict" in http_body
        assert validation.status_code == 422
        assert validation.headers["content-type"].startswith("text/html")
        assert "422 Validation error" in validation_body
        assert "Request validation failed." in validation_body

    asyncio.run(_exercise())


def test_http_error_code_and_import_path_helpers_cover_public_codes() -> None:
    assert app_module._is_import_upload_path("/api/projects/p/imports") is True  # noqa: SLF001
    assert app_module._is_import_upload_path("/web/projects/p/imports") is True  # noqa: SLF001
    assert app_module._is_import_upload_path("/api/projects/p/runs") is False  # noqa: SLF001
    requires_token = app_module._requires_api_token_check  # noqa: SLF001
    assert requires_token(_request(path="/api/projects", method="POST")) is True
    assert requires_token(_request(path="/web/projects/p/imports", method="POST")) is True
    assert requires_token(_request(path="/projects", method="POST")) is True
    assert requires_token(_request(path="/projects/new", method="GET")) is False
    assert app_module._http_error_code(404) == "not_found"  # noqa: SLF001
    assert app_module._http_error_code(401) == "unauthorized"  # noqa: SLF001
    assert app_module._http_error_code(409) == "conflict"  # noqa: SLF001
    assert app_module._http_error_code(413) == "payload_too_large"  # noqa: SLF001
    assert app_module._http_error_code(422) == "validation_error"  # noqa: SLF001
    assert app_module._http_error_code(403) == "forbidden"  # noqa: SLF001
    assert app_module._http_error_code(418) == "http_error"  # noqa: SLF001
    assert app_module._http_status_title(409) == "Conflict"  # noqa: SLF001
    assert app_module._http_status_title(401) == "Unauthorized"  # noqa: SLF001
    assert app_module._http_status_title(418) == "Request failed"  # noqa: SLF001


def test_main_delegates_to_uvicorn_factory(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(*args: object, **kwargs: object) -> None:
        captured["args"] = args
        captured["kwargs"] = kwargs

    monkeypatch.setattr(app_module.uvicorn, "run", fake_run)

    app_module.main(host="0.0.0.0", port=9001)

    assert captured["args"] == ("vuln_prioritizer.api.app:create_app",)
    assert captured["kwargs"] == {"factory": True, "host": "0.0.0.0", "port": 9001}


def test_get_engine_rejects_unconfigured_app() -> None:
    app = FastAPI()
    app.state.db_engine = object()

    with pytest.raises(RuntimeError, match="database engine is not configured"):
        app_module.get_engine(app)


def test_artifact_resolution_rejects_symlinks_outside_allowed_roots(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshots"
    cache_root = tmp_path / "cache"
    attack_root = tmp_path / "attack"
    outside_root = tmp_path / "outside"
    snapshot_root.mkdir()
    cache_root.mkdir()
    attack_root.mkdir()
    outside_root.mkdir()
    outside_file = outside_root / "outside.json"
    outside_file.write_text("{}", encoding="utf-8")
    snapshot_file = snapshot_root / "snapshot.json"
    attack_file = attack_root / "attack.json"
    snapshot_file.write_text("{}", encoding="utf-8")
    attack_file.write_text("{}", encoding="utf-8")
    try:
        (snapshot_root / "escape.json").symlink_to(outside_file)
        (attack_root / "escape.json").symlink_to(outside_file)
    except OSError as exc:
        pytest.skip(f"filesystem does not support symlinks: {exc}")

    settings = WorkbenchSettings(
        provider_snapshot_dir=snapshot_root,
        provider_cache_dir=cache_root,
        attack_artifact_dir=attack_root,
    )

    assert (
        api_routes._resolve_provider_snapshot_path(  # noqa: SLF001
            "snapshot.json",
            settings=settings,
        )
        == snapshot_file.resolve()
    )
    assert (
        api_routes._resolve_attack_artifact_path(  # noqa: SLF001
            "attack.json",
            settings=settings,
        )
        == attack_file.resolve()
    )
    with pytest.raises(HTTPException, match="Provider snapshot file does not exist"):
        api_routes._resolve_provider_snapshot_path("escape.json", settings=settings)  # noqa: SLF001
    with pytest.raises(HTTPException, match="ATT&CK artifact file does not exist"):
        api_routes._resolve_attack_artifact_path("escape.json", settings=settings)  # noqa: SLF001


async def _ok_response(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


async def _empty_receive() -> dict[str, object]:
    return {"type": "http.request", "body": b"", "more_body": False}


def _request(
    *,
    path: str,
    method: str = "GET",
    content_length: str | None = None,
) -> Request:
    headers = []
    if content_length is not None:
        headers.append((b"content-length", content_length.encode("ascii")))
    app = FastAPI()
    app.state.workbench_settings = WorkbenchSettings(max_upload_mb=1)
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": headers,
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("testclient", 50000),
            "app": app,
        },
        receive=_empty_receive,
    )
