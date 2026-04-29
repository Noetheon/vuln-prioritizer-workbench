"""Template-style dependency helpers for the migration backend shell."""

from __future__ import annotations

from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from sqlmodel import Session

from app.core import security
from app.core.config import settings
from app.core.db import engine, ensure_configured_superuser
from app.models import TokenPayload, User

reusable_oauth2 = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")

TokenDep = Annotated[str, Depends(reusable_oauth2)]


def get_db() -> Generator[Session, None, None]:
    """Yield a SQLModel session for template-backed API routes."""
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]


def get_current_user(session: SessionDep, token: TokenDep) -> User:
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
    user = ensure_configured_superuser(session)
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_active_superuser(current_user: CurrentUser) -> User:
    """Require the configured user to be active and superuser."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges")
    return current_user
