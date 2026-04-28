"""Versioned API router for the template-aligned backend shell."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import assets, findings, login, projects, runs, users, utils, workbench

api_router = APIRouter()
api_router.include_router(login.router)
api_router.include_router(projects.router)
api_router.include_router(assets.router)
api_router.include_router(runs.router)
api_router.include_router(findings.router)
api_router.include_router(users.router)
api_router.include_router(utils.router)
api_router.include_router(workbench.router)
