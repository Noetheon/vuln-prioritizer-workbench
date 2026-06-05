"""Request-safe API error envelope and public payload redaction helpers."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from app.core.config import Settings
from app.domain.engine.security_redaction import redact_text, redact_value

DEFAULT_ERROR_MESSAGES = {
    400: "Bad request.",
    401: "Unauthorized request.",
    403: "Request forbidden.",
    404: "Resource not found.",
    409: "Request conflict.",
    413: "Upload exceeds configured limit.",
    422: "Request validation failed.",
    429: "Too many requests.",
}

EXACT_MESSAGE_CODES = {
    "Asset context parsing failed.": "import_asset_context_parse_failed",
    "Import analysis failed.": "import_analysis_failed",
    "Import parsing failed.": "import_parse_failed",
    "Report artifact checksum mismatch": "report_artifact_checksum_mismatch",
    "Report artifact not found": "report_artifact_not_found",
    "Report is not an evidence bundle": "report_not_evidence_bundle",
    "Request body exceeds configured limit.": "request_body_too_large",
    "Too many requests.": "rate_limited",
    "Upload exceeds configured limit.": "upload_too_large",
    "VEX parsing failed.": "import_vex_parse_failed",
}

STATUS_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    413: "payload_too_large",
    422: "validation_error",
    429: "rate_limited",
}

API_ERROR_ENVELOPE_SCHEMA: dict[str, Any] = {
    "title": "ApiErrorEnvelope",
    "type": "object",
    "required": ["code", "message", "details", "detail"],
    "properties": {
        "code": {
            "type": "string",
            "description": "Stable machine-readable error code.",
        },
        "message": {
            "type": "string",
            "description": "Request-safe human-readable error message.",
        },
        "details": {
            "type": "object",
            "additionalProperties": True,
            "description": "Structured, request-safe error details.",
        },
        "detail": {
            "description": "FastAPI-compatible detail field for standard error clients.",
            "anyOf": [
                {"type": "string"},
                {"type": "object", "additionalProperties": True},
                {"type": "array", "items": {}},
                {"type": "null"},
            ],
        },
        "trace_id": {
            "type": "string",
            "description": "Optional request/correlation identifier echoed from request headers.",
        },
    },
    "additionalProperties": False,
}
API_ERROR_ENVELOPE_SCHEMA_REF = {"$ref": "#/components/schemas/ApiErrorEnvelope"}
FASTAPI_VALIDATION_SCHEMA_REFS = {
    "#/components/schemas/HTTPValidationError",
    "#/components/schemas/ValidationError",
}


def error_response_content(
    *,
    status_code: int,
    detail: Any = None,
    code: str | None = None,
    message: str | None = None,
    request: Request | None = None,
) -> dict[str, Any]:
    """Build the stable API error envelope plus FastAPI ``detail`` compatibility."""
    safe_detail = redact_request_safe_value(detail)
    resolved_message = _resolve_message(status_code, safe_detail, message)
    resolved_details = _resolve_details(safe_detail)
    resolved_code = code or _resolve_code(status_code, safe_detail, resolved_message)

    content: dict[str, Any] = {
        "code": resolved_code,
        "message": resolved_message,
        "details": resolved_details,
        "detail": _fastapi_detail(
            safe_detail,
            code=resolved_code,
            details=resolved_details,
            message=resolved_message,
        ),
    }
    trace_id = _trace_id(request)
    if trace_id:
        content["trace_id"] = trace_id
    return content


def install_error_openapi_schema(app: FastAPI) -> None:
    """Document FastAPI validation errors with the runtime error envelope."""
    original_openapi = app.openapi

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema

        schema = original_openapi()
        components = schema.setdefault("components", {}).setdefault("schemas", {})
        components["ApiErrorEnvelope"] = deepcopy(API_ERROR_ENVELOPE_SCHEMA)
        _replace_fastapi_validation_error_schemas(schema)
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]


def redact_request_safe_value(value: Any) -> Any:
    """Redact secrets and absolute local paths from request-facing payloads."""
    if isinstance(value, str):
        return redact_text(value)
    redacted, _paths = redact_value(jsonable_encoder(value))
    return redacted


def redact_public_payload(value: Any) -> Any:
    """Redact secrets and local absolute paths from public API payload fragments."""
    redacted, _paths = redact_value(jsonable_encoder(value))
    return redacted


def production_safe_settings(active_settings: object) -> bool:
    """Return whether diagnostics should use the production-safe projection."""
    return isinstance(active_settings, Settings) and active_settings.ENVIRONMENT != "local"


def _replace_fastapi_validation_error_schemas(schema: dict[str, Any]) -> None:
    paths = schema.get("paths")
    if not isinstance(paths, Mapping):
        return

    for path_item in paths.values():
        if not isinstance(path_item, Mapping):
            continue
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            responses = operation.get("responses")
            if not isinstance(responses, Mapping):
                continue
            for response in responses.values():
                if not isinstance(response, dict):
                    continue
                content = response.get("content")
                if not isinstance(content, Mapping):
                    continue
                json_content = content.get("application/json")
                if not isinstance(json_content, dict):
                    continue
                if _is_fastapi_validation_error_schema(json_content.get("schema")):
                    json_content["schema"] = dict(API_ERROR_ENVELOPE_SCHEMA_REF)


def _is_fastapi_validation_error_schema(response_schema: Any) -> bool:
    if not isinstance(response_schema, Mapping):
        return False
    schema_ref = response_schema.get("$ref")
    if isinstance(schema_ref, str) and schema_ref in FASTAPI_VALIDATION_SCHEMA_REFS:
        return True
    for composite_key in ("anyOf", "oneOf", "allOf"):
        nested_schemas = response_schema.get(composite_key)
        if isinstance(nested_schemas, list) and any(
            _is_fastapi_validation_error_schema(nested_schema) for nested_schema in nested_schemas
        ):
            return True
    return False


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a stable JSON envelope for FastAPI/Starlette HTTP exceptions."""
    if not isinstance(exc, StarletteHTTPException):
        return internal_error_response(request)
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response_content(
            status_code=exc.status_code,
            detail=exc.detail,
            request=request,
        ),
        headers=exc.headers,
    )


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a stable JSON envelope for request validation failures."""
    if not isinstance(exc, RequestValidationError):
        return internal_error_response(request)
    return JSONResponse(
        status_code=422,
        content=error_response_content(
            status_code=422,
            code="request_validation_failed",
            message="Request validation failed.",
            detail={"errors": jsonable_encoder(exc.errors())},
            request=request,
        ),
    )


async def unhandled_exception_handler(request: Request, _exc: Exception) -> JSONResponse:
    """Hide implementation details for uncaught backend failures."""
    return internal_error_response(request)


def internal_error_response(request: Request | None = None) -> JSONResponse:
    """Return a generic 500 error envelope."""
    return JSONResponse(
        status_code=500,
        content=error_response_content(
            status_code=500,
            code="internal_server_error",
            message="Internal server error.",
            detail={},
            request=request,
        ),
    )


def _resolve_message(status_code: int, detail: Any, explicit: str | None) -> str:
    if explicit:
        return redact_text(explicit)
    if isinstance(detail, Mapping):
        candidate = detail.get("message")
        if isinstance(candidate, str) and candidate.strip():
            return redact_text(candidate)
    if isinstance(detail, str) and detail.strip():
        return redact_text(detail)
    return DEFAULT_ERROR_MESSAGES.get(status_code, "Internal server error.")


def _resolve_details(detail: Any) -> dict[str, Any]:
    if isinstance(detail, Mapping):
        nested = detail.get("details")
        if isinstance(nested, Mapping):
            return dict(nested)
        return {str(key): value for key, value in detail.items() if key not in {"code", "message"}}
    if isinstance(detail, list):
        return {"errors": detail}
    return {}


def _resolve_code(status_code: int, detail: Any, message: str) -> str:
    if isinstance(detail, Mapping):
        candidate = detail.get("code")
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    if message in EXACT_MESSAGE_CODES:
        return EXACT_MESSAGE_CODES[message]
    if "not found" in message.lower():
        return "not_found"
    return STATUS_CODES.get(status_code, "internal_server_error")


def _fastapi_detail(
    detail: Any,
    *,
    code: str,
    details: dict[str, Any],
    message: str,
) -> Any:
    if isinstance(detail, Mapping):
        fastapi_detail = dict(detail)
        fastapi_detail.setdefault("message", message)
        fastapi_detail.setdefault("code", code)
        fastapi_detail.setdefault("details", details)
        return fastapi_detail
    return detail if detail not in (None, "") else message


def _trace_id(request: Request | None) -> str | None:
    if request is None:
        return None
    value = request.headers.get("x-request-id") or request.headers.get("x-correlation-id")
    if not value:
        return None
    return redact_text(value.strip())[:128] or None
