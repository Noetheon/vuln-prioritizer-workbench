"""Versioned API router for the template-aligned backend shell."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import workbench

api_router = APIRouter()
api_router.include_router(workbench.router)
