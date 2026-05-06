"""User and password lifecycle routes for the active backend runtime."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from sqlmodel import Session

from app.api.deps import CurrentUser, ScopedAdminUser, SessionDep
from app.core import security
from app.models import User, UserPasswordChange, UserPasswordReset, UserPublic
from app.repositories import AuthSessionRepository
from app.services.audit import record_audit_event

router = APIRouter(prefix="/users", tags=["users"])
INSECURE_USER_PASSWORDS = {"", "changethis"}


@router.get("/me", response_model=UserPublic)
def read_user_me(current_user: CurrentUser) -> User:
    """Get current user."""
    return current_user


@router.post("/me/password", response_model=UserPublic)
def rotate_current_user_password(
    payload: UserPasswordChange,
    session: SessionDep,
    current_user: CurrentUser,
) -> User:
    """Rotate the current user's persisted password hash and revoke sessions."""
    if not security.verify_password(payload.current_password, current_user.hashed_password):
        record_audit_event(
            session,
            action="user.password.rotate",
            resource_type="user",
            resource_id=current_user.id,
            status="failure",
            actor=current_user,
            detail={"reason": "current_password_mismatch"},
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )
    _set_user_password(
        session,
        current_user,
        payload.new_password,
        actor=current_user,
        action="user.password.rotate",
    )
    return current_user


@router.post("/{user_id}/password-reset", response_model=UserPublic)
def reset_user_password(
    user_id: uuid.UUID,
    payload: UserPasswordReset,
    session: SessionDep,
    current_user: ScopedAdminUser,
) -> User:
    """Reset a user's persisted password hash and revoke that user's sessions."""
    user = _get_user_or_404(session, user_id)
    _set_user_password(
        session,
        user,
        payload.new_password,
        actor=current_user,
        action="user.password.reset",
    )
    return user


@router.post("/{user_id}/deactivate", response_model=UserPublic)
def deactivate_user(
    user_id: uuid.UUID,
    session: SessionDep,
    current_user: ScopedAdminUser,
) -> User:
    """Deactivate a user and revoke every active session for that account."""
    user = _get_user_or_404(session, user_id)
    user.is_active = False
    session.add(user)
    revoked_sessions = AuthSessionRepository(session).revoke_user_sessions(user.id)
    record_audit_event(
        session,
        action="user.deactivate",
        resource_type="user",
        resource_id=user.id,
        actor=current_user,
        detail={"revoked_sessions": revoked_sessions},
    )
    session.commit()
    session.refresh(user)
    return user


@router.post("/{user_id}/activate", response_model=UserPublic)
def activate_user(
    user_id: uuid.UUID,
    session: SessionDep,
    current_user: ScopedAdminUser,
) -> User:
    """Reactivate a persisted user account."""
    user = _get_user_or_404(session, user_id)
    user.is_active = True
    session.add(user)
    record_audit_event(
        session,
        action="user.activate",
        resource_type="user",
        resource_id=user.id,
        actor=current_user,
    )
    session.commit()
    session.refresh(user)
    return user


def _set_user_password(
    session: Session,
    user: User,
    new_password: str,
    *,
    actor: User,
    action: str,
) -> None:
    _validate_new_password(new_password)
    user.hashed_password = security.get_password_hash(new_password)
    session.add(user)
    revoked_sessions = AuthSessionRepository(session).revoke_user_sessions(user.id)
    record_audit_event(
        session,
        action=action,
        resource_type="user",
        resource_id=user.id,
        actor=actor,
        detail={"revoked_sessions": revoked_sessions},
    )
    session.commit()
    session.refresh(user)


def _validate_new_password(new_password: str) -> None:
    if new_password.strip().lower() in INSECURE_USER_PASSWORDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must not use the default Workbench secret.",
        )


def _get_user_or_404(session: Session, user_id: uuid.UUID) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user
