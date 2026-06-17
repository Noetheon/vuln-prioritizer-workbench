"""Versioned API router for the Workbench backend shell."""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter
from fastapi.dependencies.models import Dependant

from app.api.deps import get_local_actor, get_websocket_local_actor
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
    workflows,
)

PUBLIC_API_ROUTE_SUFFIXES = frozenset(
    {
        "/workbench/health",
        "/workbench/status",
        "/utils/health-check/",
    }
)


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
api_router.include_router(workflows.router)


def assert_api_local_actor_policy(api_prefix: str, routes: Iterable[object]) -> None:
    """Fail fast if a non-public API route lacks the local principal dependency."""
    registered_paths: set[str] = set()
    registered_suffixes: set[str] = set()
    missing: list[str] = []
    for route in _api_policy_route_candidates(routes):
        route_path = getattr(route, "path", None)
        dependant = getattr(route, "dependant", None)
        if not isinstance(route_path, str) or not isinstance(dependant, Dependant):
            continue
        registered_paths.add(route_path)
        route_suffix = _api_route_suffix(route_path, api_prefix)
        registered_suffixes.add(route_suffix)
        if route_suffix in PUBLIC_API_ROUTE_SUFFIXES:
            continue
        if not _dependant_has_local_actor_dependency(dependant):
            route_methods = getattr(route, "methods", ()) or ()
            methods = ",".join(sorted(str(method) for method in route_methods))
            missing.append(f"{methods} {_api_route_display_path(route_path, api_prefix)}")
    if not registered_paths:
        raise RuntimeError("API local actor policy cannot be validated without registered routes")
    missing_public_paths = sorted(PUBLIC_API_ROUTE_SUFFIXES - registered_suffixes)
    if missing_public_paths:
        joined = "; ".join(f"{api_prefix}{path}" for path in missing_public_paths)
        raise RuntimeError(f"Public API route allowlist references missing routes: {joined}")
    if missing:
        joined = "; ".join(missing)
        raise RuntimeError(f"Non-public API routes must declare a local principal: {joined}")


def _dependant_has_local_actor_dependency(dependant: Dependant) -> bool:
    for dependency in dependant.dependencies:
        call = dependency.call
        if call in {get_local_actor, get_websocket_local_actor}:
            return True
        if _dependant_has_local_actor_dependency(dependency):
            return True
    return False


def _api_policy_route_candidates(routes: Iterable[object]) -> Iterable[object]:
    for route in routes:
        yield route
        effective_route_contexts = getattr(route, "effective_route_contexts", None)
        if callable(effective_route_contexts):
            yield from effective_route_contexts()


def _api_route_suffix(route_path: str, api_prefix: str) -> str:
    if route_path.startswith(api_prefix):
        return route_path[len(api_prefix) :] or "/"
    return route_path


def _api_route_display_path(route_path: str, api_prefix: str) -> str:
    if route_path.startswith(api_prefix):
        return route_path
    return f"{api_prefix}{route_path}"
