"""Team mode: accept the user a trusted login proxy has already signed in."""

from __future__ import annotations

from starlette.datastructures import Headers

from app.core.config import Settings
from app.core.local_actor import LocalWorkbenchActor, local_actor_id
from app.core.trusted_proxy import is_trusted_proxy_host

MAX_IDENTITY_LENGTH = 320
MAX_DISPLAY_NAME_LENGTH = 200


class ProxyIdentityError(Exception):
    """Raised when a team-mode request cannot be attributed to a signed-in user."""


def proxy_actor(
    active_settings: Settings,
    client_host: str | None,
    headers: Headers,
) -> LocalWorkbenchActor:
    """
    Return the user the login proxy asserted for this request.

    Only a direct peer inside ``TRUSTED_PROXY_CIDRS`` may assert an identity,
    and the identity header must appear exactly once: a proxy that appends
    its value to a client-supplied header would otherwise let the client pick
    the user.
    """
    if client_host is None or not is_trusted_proxy_host(
        client_host, active_settings.TRUSTED_PROXY_CIDRS
    ):
        raise ProxyIdentityError("Requests must come through the configured login proxy.")
    identity = _single_header_value(
        headers,
        active_settings.AUTH_PROXY_USER_HEADER,
        max_length=MAX_IDENTITY_LENGTH,
    )
    if identity is None:
        raise ProxyIdentityError(
            f"The login proxy did not send one valid {active_settings.AUTH_PROXY_USER_HEADER} "
            "header."
        )
    display_name = (
        _single_header_value(
            headers,
            active_settings.AUTH_PROXY_NAME_HEADER,
            max_length=MAX_DISPLAY_NAME_LENGTH,
        )
        if active_settings.AUTH_PROXY_NAME_HEADER
        else None
    )
    return LocalWorkbenchActor(
        id=local_actor_id(identity),
        email=identity,
        full_name=display_name or identity,
    )


def _single_header_value(headers: Headers, name: str, *, max_length: int) -> str | None:
    values = headers.getlist(name)
    if len(values) != 1:
        return None
    value = values[0].strip()
    if not value or len(value) > max_length:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    return value
