"""Versioned API router for the template-aligned backend shell."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    api_tokens,
    assets,
    findings,
    github_issues,
    imports,
    login,
    projects,
    providers,
    reports,
    runs,
    users,
    utils,
    waivers,
    workbench,
)

api_router = APIRouter()
api_router.include_router(login.router)
api_router.include_router(api_tokens.router)
api_router.include_router(projects.router)
api_router.include_router(assets.router)
api_router.include_router(providers.router)
api_router.include_router(runs.router)
api_router.include_router(reports.router)
api_router.include_router(imports.router)
api_router.include_router(findings.router)
api_router.include_router(github_issues.router)
api_router.include_router(waivers.router)
api_router.include_router(users.router)
api_router.include_router(utils.router)
api_router.include_router(workbench.router)
