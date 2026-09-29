"""Dependency helpers for the active local Workbench runtime."""

from __future__ import annotations

from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, WebSocket, WebSocketException, status
from sqlmodel import Session

from app.core.app_state import workbench_engine, workbench_settings
from app.core.local_actor import LocalWorkbenchActor, configured_local_actor
from app.core.proxy_identity import ProxyIdentityError, proxy_actor


def get_db(request: Request) -> Generator[Session, None, None]:
    """Yield a SQLModel session for active API routes."""
    with Session(workbench_engine(request)) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]


def get_local_actor(request: Request) -> LocalWorkbenchActor:
    """
    Return the Workbench principal for this request.

    Local mode serves one trusted operator without login, RBAC, token scopes,
    or session cookies. Team mode (``AUTH_MODE=proxy``) delegates sign-in to a
    reverse proxy and rejects requests it has not attributed to a user; every
    non-public API route depends on this function, which the router asserts at
    startup.
    """
    active_settings = workbench_settings(request, required=False)
    if active_settings.AUTH_MODE == "proxy":
        client_host = request.client.host if request.client else None
        try:
            return proxy_actor(active_settings, client_host, request.headers)
        except ProxyIdentityError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Sign-in required. {exc}",
            ) from exc
    return configured_local_actor(active_settings)


LocalActor = Annotated[LocalWorkbenchActor, Depends(get_local_actor)]


def get_websocket_local_actor(websocket: WebSocket) -> LocalWorkbenchActor:
    """Return the Workbench principal for WebSocket routes, as for HTTP routes."""
    active_settings = workbench_settings(websocket, required=False)
    if active_settings.AUTH_MODE == "proxy":
        client_host = websocket.client.host if websocket.client else None
        try:
            return proxy_actor(active_settings, client_host, websocket.headers)
        except ProxyIdentityError as exc:
            raise WebSocketException(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Sign-in required.",
            ) from exc
    return configured_local_actor(active_settings)


WebSocketLocalActor = Annotated[LocalWorkbenchActor, Depends(get_websocket_local_actor)]
