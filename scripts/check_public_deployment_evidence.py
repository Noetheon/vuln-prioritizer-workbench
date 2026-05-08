"""Validate public deployment evidence docs and Compose/TLS topology contracts."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.yml"
TRAEFIK_COMPOSE = ROOT / "compose.traefik.yml"
PRODUCTION_SMOKE_COMPOSE = ROOT / "compose.production-smoke.yml"
DEPLOYMENT_DOC = ROOT / "docs" / "workbench-public-deployment.md"
LEDGER = ROOT / "docs" / "public-production-release-evidence-ledger.md"


def main() -> int:
    failures: list[str] = []
    compose = _yaml(COMPOSE)
    traefik = _yaml(TRAEFIK_COMPOSE)
    production_smoke = _yaml(PRODUCTION_SMOKE_COMPOSE)
    failures.extend(_check_traefik_service(traefik))
    failures.extend(_check_app_labels(compose))
    failures.extend(_check_production_smoke(production_smoke))
    failures.extend(_check_docs())

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("public deployment evidence contract: OK")
    return 0


def _yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a YAML mapping.")
    return payload


def _check_traefik_service(compose: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    services = _mapping(compose.get("services"))
    traefik = _mapping(services.get("traefik"))
    labels = _string_list(traefik.get("labels"))
    command = _string_list(traefik.get("command"))
    ports = _string_list(traefik.get("ports"))
    volumes = _string_list(traefik.get("volumes"))

    required_commands = {
        "--providers.docker",
        "--providers.docker.exposedbydefault=false",
        "--entrypoints.http.address=:80",
        "--entrypoints.https.address=:443",
        "--certificatesresolvers.le.acme.tlschallenge=true",
        "--accesslog",
    }
    for item in sorted(required_commands):
        if item not in command:
            failures.append(f"compose.traefik.yml traefik command is missing {item!r}.")
    if "80:80" not in ports or "443:443" not in ports:
        failures.append("compose.traefik.yml must expose public HTTP and HTTPS ports.")
    if "/var/run/docker.sock:/var/run/docker.sock:ro" not in volumes:
        failures.append("compose.traefik.yml must mount Docker socket read-only.")
    if not any("/certificates" in volume for volume in volumes):
        failures.append("compose.traefik.yml must persist ACME certificates.")

    required_labels = {
        "traefik.enable=${TRAEFIK_DASHBOARD_ENABLED:-false}",
        "traefik.http.routers.traefik-dashboard-https.tls=true",
        "traefik.http.routers.traefik-dashboard-https.middlewares=traefik-dashboard-ipallowlist",
        "traefik.http.routers.traefik-dashboard-http.middlewares=https-redirect",
    }
    for item in sorted(required_labels):
        if item not in labels:
            failures.append(f"compose.traefik.yml traefik label is missing {item!r}.")
    return failures


def _check_app_labels(compose: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    services = _mapping(compose.get("services"))
    backend_labels = _string_list(_mapping(services.get("backend")).get("labels"))
    frontend_labels = _string_list(_mapping(services.get("frontend")).get("labels"))

    for service_name, labels in {"backend": backend_labels, "frontend": frontend_labels}.items():
        if "traefik.enable=${TRAEFIK_APP_ENABLED:-false}" not in labels:
            failures.append(f"compose.yml {service_name} must keep Traefik app routing opt-in.")
        if not any(label.endswith(".tls=true") for label in labels):
            failures.append(f"compose.yml {service_name} HTTPS router must enable TLS.")
        if not any("entrypoints=http" in label for label in labels):
            failures.append(f"compose.yml {service_name} must define HTTP router for redirect.")
        if not any("entrypoints=https" in label for label in labels):
            failures.append(f"compose.yml {service_name} must define HTTPS router.")

    if not any("workbench-upload-limit" in label for label in backend_labels):
        failures.append("compose.yml backend route must keep upload-limit middleware.")
    if not any("api.${DOMAIN" in label for label in backend_labels):
        failures.append("compose.yml backend direct API route must remain explicit for review.")
    if not any("Host(`${DOMAIN" in label for label in frontend_labels):
        failures.append("compose.yml frontend route must bind to the public Workbench host.")
    return failures


def _check_production_smoke(compose: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    services = _mapping(compose.get("services"))
    backend = _mapping(services.get("backend"))
    frontend = _mapping(services.get("frontend"))
    backend_env = _mapping(backend.get("environment"))
    frontend_build = _mapping(frontend.get("build"))
    frontend_args = _mapping(frontend_build.get("args"))

    expected_backend_env = {
        "ENVIRONMENT": "production",
        "FRONTEND_HOST": "https://workbench.example.test",
        "BACKEND_CORS_ORIGINS": "https://workbench.example.test",
        "API_DOCS_ENABLED": "false",
    }
    for key, value in expected_backend_env.items():
        if backend_env.get(key) != value:
            failures.append(f"compose.production-smoke.yml backend {key} must be {value!r}.")
    if frontend_args.get("VITE_API_URL") != "":
        failures.append("compose.production-smoke.yml frontend must build same-origin API calls.")
    if "127.0.0.1:5180:80" not in _string_list(frontend.get("ports")):
        failures.append("compose.production-smoke.yml must bind frontend smoke to localhost.")
    return failures


def _check_docs() -> list[str]:
    failures: list[str] = []
    deployment_doc = DEPLOYMENT_DOC.read_text(encoding="utf-8")
    ledger = LEDGER.read_text(encoding="utf-8")
    required_deployment_phrases = (
        "Public TLS Evidence Checklist",
        "same-origin API routing",
        "Optional direct API route for automation",
        "curl -I https://${DOMAIN}/",
        "curl -I https://api.${DOMAIN}/api/v1/workbench/health",
        "Do not include secrets",
    )
    for phrase in required_deployment_phrases:
        if phrase not in deployment_doc:
            failures.append(f"workbench public deployment runbook is missing {phrase!r}.")

    required_ledger_phrases = (
        "Public TLS and Traefik evidence",
        "archive binary evidence manifest",
        "scripts/check_public_deployment_evidence.py",
        "scripts/check_archive_evidence_manifest.py",
    )
    for phrase in required_ledger_phrases:
        if phrase not in ledger:
            failures.append(f"public production ledger is missing {phrase!r}.")
    return failures


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


if __name__ == "__main__":
    raise SystemExit(main())
