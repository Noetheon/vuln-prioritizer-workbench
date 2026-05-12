"""Versioned API router for the Workbench backend shell."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from app.api.deps import get_local_actor
from app.api.routes import (
    assets,
    audit,
    findings,
    github_issues,
    imports,
    projects,
    providers,
    reports,
    runs,
    utils,
    waivers,
    workbench,
)

PUBLIC_API_ROUTE_SUFFIXES = frozenset(
    {
        "/workbench/health",
        "/workbench/status",
        "/utils/health-check/",
    }
)
PUBLIC_API_ROUTE_PATHS = frozenset(f"/api/v1{path}" for path in PUBLIC_API_ROUTE_SUFFIXES)

api_router = APIRouter()
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
api_router.include_router(utils.router)
api_router.include_router(workbench.router)


def assert_api_local_actor_policy(api_prefix: str) -> None:
    """Fail fast if a non-public API route lacks the local principal dependency."""
    public_paths = {
        *PUBLIC_API_ROUTE_SUFFIXES,
        *(f"{api_prefix}{path}" for path in PUBLIC_API_ROUTE_SUFFIXES),
    }
    missing: list[str] = []
    for route in api_router.routes:
        if not isinstance(route, APIRoute):
            continue
        paths = {route.path, f"{api_prefix}{route.path}"}
        if paths & public_paths:
            continue
        if not _dependant_has_local_actor_dependency(route.dependant):
            methods = ",".join(sorted(route.methods or ()))
            missing.append(f"{methods} {api_prefix}{route.path}")
    if missing:
        joined = "; ".join(missing)
        raise RuntimeError(f"Non-public API routes must declare a local principal: {joined}")


def _dependant_has_local_actor_dependency(dependant: Dependant) -> bool:
    for dependency in dependant.dependencies:
        call = dependency.call
        if call is get_local_actor:
            return True
        if _dependant_has_local_actor_dependency(dependency):
            return True
    return False
