"""Template-style dependency helpers for the migration backend shell."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError

from app.core import security
from app.core.config import settings
from app.models import TokenPayload, UserPublic

reusable_oauth2 = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")

TokenDep = Annotated[str, Depends(reusable_oauth2)]


def configured_superuser() -> UserPublic:
    """Return the configured local-first superuser until DB-backed users land."""
    return UserPublic(
        id=settings.FIRST_SUPERUSER,
        email=settings.FIRST_SUPERUSER,
        is_active=True,
        is_superuser=True,
    )


def get_current_user(token: TokenDep) -> UserPublic:
    """Validate the bearer token and resolve the configured template-shell user."""
    try:
        payload = security.decode_access_token(token)
        token_data = TokenPayload(**payload)
    except (security.TokenDecodeError, ValidationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        ) from exc

    if token_data.sub != settings.FIRST_SUPERUSER:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return configured_superuser()


CurrentUser = Annotated[UserPublic, Depends(get_current_user)]
