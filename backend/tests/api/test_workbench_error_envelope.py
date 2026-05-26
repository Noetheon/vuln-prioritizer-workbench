from __future__ import annotations

import asyncio
import json

import pytest
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from app.api.errors import (
    error_response_content,
    http_exception_handler,
    production_safe_settings,
    validation_error_handler,
)
from app.core.config import Settings


def _request(headers: dict[str, str] | None = None) -> Request:
    raw_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in (headers or {}).items()
    ]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/test",
            "headers": raw_headers,
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
            "client": ("testclient", 50000),
        }
    )


def test_error_response_content_preserves_stable_fields_and_trace_id() -> None:
    content = error_response_content(
        status_code=409,
        detail={
            "code": "project_conflict",
            "message": "Project already exists.",
            "details": {"name": "Demo"},
            "path": "/Users/alice/.vpw/token-secret.txt",
        },
        request=_request({"x-request-id": "trace-123"}),
    )

    assert content["code"] == "project_conflict"
    assert content["message"] == "Project already exists."
    assert content["details"] == {"name": "Demo"}
    assert content["detail"]["code"] == "project_conflict"
    assert content["detail"]["details"] == {"name": "Demo"}
    assert content["trace_id"] == "trace-123"
    assert "/Users/" not in json.dumps(content)
    assert "token-secret" not in json.dumps(content)


def test_error_response_content_maps_lists_to_validation_details() -> None:
    content = error_response_content(
        status_code=422,
        detail=[
            {
                "loc": ["body", "project_id"],
                "msg": "Input should be a valid UUID.",
            }
        ],
    )

    assert content["code"] == "validation_error"
    assert content["message"] == "Request validation failed."
    assert content["details"]["errors"][0]["loc"] == ["body", "project_id"]
    assert content["detail"][0]["msg"] == "Input should be a valid UUID."


def test_error_response_content_maps_exact_messages_to_codes() -> None:
    content = error_response_content(
        status_code=413,
        detail="Upload exceeds configured limit.",
    )

    assert content["code"] == "upload_too_large"
    assert content["message"] == "Upload exceeds configured limit."
    assert content["detail"] == "Upload exceeds configured limit."


def test_error_response_content_maps_request_body_limit_to_stable_code() -> None:
    content = error_response_content(
        status_code=413,
        detail="Request body exceeds configured limit.",
    )

    assert content["code"] == "request_body_too_large"
    assert content["message"] == "Request body exceeds configured limit."


@pytest.mark.parametrize(
    ("active_settings", "expected"),
    [
        (Settings(), False),
        (
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY="production-runtime-secret-0123456789abcdef",
                FRONTEND_HOST="https://workbench.example.com",
                ALLOWED_HOSTS=("workbench.example.com",),
            ),
            True,
        ),
        (object(), False),
    ],
)
def test_production_safe_settings_only_matches_non_local_settings_objects(
    active_settings: object,
    expected: bool,
) -> None:
    assert production_safe_settings(active_settings) is expected


def test_http_exception_handler_falls_back_to_internal_error_for_wrong_exception() -> None:
    response = asyncio.run(http_exception_handler(_request(), RuntimeError("boom")))

    assert response.status_code == 500
    assert json.loads(response.body)["code"] == "internal_server_error"


def test_http_exception_handler_uses_stable_envelope_for_starlette_errors() -> None:
    response = asyncio.run(
        http_exception_handler(
            _request({"x-correlation-id": "corr-123"}),
            StarletteHTTPException(status_code=404, detail="Finding not found"),
        )
    )

    payload = json.loads(response.body)
    assert response.status_code == 404
    assert payload["code"] == "not_found"
    assert payload["message"] == "Finding not found"
    assert payload["trace_id"] == "corr-123"


def test_validation_handler_falls_back_to_internal_error_for_wrong_exception() -> None:
    response = asyncio.run(validation_error_handler(_request(), RuntimeError("boom")))

    assert response.status_code == 500
    assert json.loads(response.body)["message"] == "Internal server error."
