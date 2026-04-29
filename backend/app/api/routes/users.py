"""Minimal template user routes for the migration backend shell."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import CurrentUser
from app.models import User, UserPublic

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserPublic)
def read_user_me(current_user: CurrentUser) -> User:
    """Get current user."""
    return current_user
