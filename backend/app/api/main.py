"""Versioned API router for the Workbench backend shell."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    api_tokens,
    assets,
    audit,
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

PUBLIC_API_ROUTE_PATHS = frozenset(
    {
        "/api/v1/login/access-token",
        "/api/v1/workbench/health",
        "/api/v1/utils/health-check/",
    }
)

api_router = APIRouter()
api_router.include_router(login.router)
api_router.include_router(api_tokens.router)
api_router.include_router(audit.router)
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
