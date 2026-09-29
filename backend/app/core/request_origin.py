"""Reject browser requests that a different site initiated against the local API."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.errors import error_response_content

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CROSS_SITE_REQUEST_DETAIL = "Cross-site requests to the Workbench API are not allowed."
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


class CrossSiteRequestGuard:
    """
    Block state-changing HTTP requests and WebSocket handshakes from other sites.

    The local Workbench has no login session, so a page on another site could
    otherwise submit form posts (multipart uploads are CORS "simple" requests)
    or open WebSockets against the loopback API. Browsers always attach
    ``Origin`` to such requests; non-browser clients (CLI, scripts) send none
    and stay unaffected.
    """

    def __init__(self, app: ASGIApp, *, allowed_origins: Iterable[str] = ()) -> None:
        """Store the wrapped application and explicitly trusted browser origins."""
        self.app = app
        self.allowed_origins = frozenset(
            normalized
            for origin in allowed_origins
            if (normalized := _normalized_origin(origin)) is not None
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Reject cross-site mutations before they reach routing."""
        guarded = scope["type"] == "websocket" or (
            scope["type"] == "http" and scope["method"] in STATE_CHANGING_METHODS
        )
        if guarded and not self._request_is_same_site(Headers(scope=scope)):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            response = JSONResponse(
                status_code=403,
                content=error_response_content(
                    status_code=403,
                    detail=CROSS_SITE_REQUEST_DETAIL,
                    code="cross_site_request_rejected",
                    request=Request(scope),
                ),
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _request_is_same_site(self, headers: Headers) -> bool:
        origin = headers.get("origin")
        if origin is None:
            return headers.get("sec-fetch-site", "").lower() != "cross-site"
        normalized = _normalized_origin(origin)
        if normalized is None:
            return False
        if normalized in self.allowed_origins:
            return True
        host = headers.get("host")
        return host is not None and _origin_host(normalized) == _normalized_host(
            host, scheme=normalized.split("://", 1)[0]
        )


def _normalized_origin(origin: str) -> str | None:
    value = origin.strip().rstrip("/")
    if not value or value.lower() == "null":
        return None
    parts = urlsplit(value)
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    effective_port = port if port is not None else _DEFAULT_PORTS[parts.scheme]
    return f"{parts.scheme}://{_bracketed(parts.hostname)}:{effective_port}"


def _origin_host(normalized_origin: str) -> str:
    return normalized_origin.split("://", 1)[1]


def _normalized_host(host: str, *, scheme: str) -> str | None:
    parts = urlsplit(f"{scheme}://{host.strip()}")
    if not parts.hostname:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    effective_port = port if port is not None else _DEFAULT_PORTS[scheme]
    return f"{_bracketed(parts.hostname)}:{effective_port}"


def _bracketed(hostname: str) -> str:
    lowered = hostname.lower()
    return f"[{lowered}]" if ":" in lowered else lowered
