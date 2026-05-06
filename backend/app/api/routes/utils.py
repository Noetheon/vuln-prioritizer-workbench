"""Workbench utility routes for backend readiness checks."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/utils", tags=["utils"])


@router.get("/health-check/")
async def health_check() -> bool:
    """Return whether the Workbench backend shell is reachable."""
    return True
