"""Minimal template login routes for the migration backend shell."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import CurrentUser
from app.core import security
from app.core.config import settings
from app.models import Token, User, UserPublic

router = APIRouter(tags=["login"])


@router.post("/login/access-token")
def login_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """OAuth2 compatible token login for the configured template-shell user."""
    if (
        form_data.username != settings.FIRST_SUPERUSER
        or form_data.password != settings.FIRST_SUPERUSER_PASSWORD
    ):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(
        access_token=security.create_access_token(
            settings.FIRST_SUPERUSER,
            expires_delta=access_token_expires,
        )
    )


@router.post("/login/test-token", response_model=UserPublic)
def test_token(current_user: CurrentUser) -> User:
    """Test access token."""
    return current_user
