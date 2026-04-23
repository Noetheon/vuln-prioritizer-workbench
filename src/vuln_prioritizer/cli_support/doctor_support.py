"""Doctor-focused CLI helpers used by command modules."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import requests
import typer
from pydantic import ValidationError
from rich.table import Table

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import (
    DEFAULT_NVD_API_KEY_ENV,
    EPSS_API_URL,
    KEV_FEED_URL,
    KEV_MIRROR_URL,
    NVD_API_URL,
)
from vuln_prioritizer.models import DoctorCheck, DoctorReport, DoctorSummary
from vuln_prioritizer.runtime_config import collect_referenced_files
from vuln_prioritizer.services.waivers import load_waiver_rules, summarize_waiver_rules
from vuln_prioritizer.utils import iso_utc_now

from .attack_support import validate_attack_inputs
from .common import runtime_config as get_runtime_config


def build_doctor_report(
    ctx: typer.Context,
    *,
    live: bool,
    cache_dir: Path,
    cache_ttl_hours: int,
    waiver_file: Path | None,
    offline_kev_file: Path | None,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
) -> DoctorReport:
    checks: list[DoctorCheck] = []
    loaded = get_runtime_config(ctx)

    python_ok = sys.version_info >= (3, 11)
    checks.append(
        doctor_check(
            "runtime.python",
            name="python",
            category="runtime",
            status="ok" if python_ok else "error",
            detail=f"Python {sys.version.split()[0]}",
            hint="Use Python 3.11 or newer." if not python_ok else None,
        )
    )
    checks.append(
        doctor_check(
            "runtime.config",
            name="runtime_config",
            category="config",
            status="ok",
            detail=(
                str(loaded.path)
                if loaded is not None
                else "No runtime config discovered; using built-in defaults."
            ),
        )
    )

    referenced_files = list(collect_referenced_files(loaded)) if loaded is not None else []
    if waiver_file is not None:
        referenced_files.append(("Waiver file", waiver_file))
    if offline_kev_file is not None:
        referenced_files.append(("Offline KEV file", offline_kev_file))
    if attack_mapping_file is not None:
        referenced_files.append(("ATT&CK mapping file", attack_mapping_file))
    if attack_technique_metadata_file is not None:
        referenced_files.append(("ATT&CK technique metadata file", attack_technique_metadata_file))
    if not any(label == "Cache directory" for label, _ in referenced_files):
        referenced_files.append(("Cache directory", cache_dir))

    for label, path in unique_path_entries(referenced_files):
        category = "cache" if label == "Cache directory" else "path"
        if label == "Cache directory":
            status = "ok"
            detail = (
                f"{path} exists."
                if path.exists()
                else f"{path} does not exist yet and will be created on demand."
            )
            hint = None
        else:
            status = "ok" if path.exists() else "error"
            detail = f"{path} exists." if path.exists() else f"{path} does not exist."
            hint = (
                None
                if path.exists()
                else "Check the configured path or supply the file explicitly."
            )
        checks.append(
            doctor_check(
                doctor_check_id(label),
                name=doctor_check_name(label),
                category=category,
                status=status,
                detail=detail,
                hint=hint,
            )
        )

    cache = FileCache(cache_dir, cache_ttl_hours)
    for namespace in ("nvd", "epss", "kev"):
        cache_status = cache.inspect_namespace(namespace)
        status = "ok"
        if cache_status["invalid_count"]:
            status = "error"
        elif cache_status["expired_count"]:
            status = "degraded"
        checks.append(
            doctor_check(
                f"cache.{namespace}",
                name=f"cache_{namespace}",
                category="cache",
                status=status,
                detail=(
                    f"{cache_status['file_count']} files, {cache_status['valid_count']} valid, "
                    f"{cache_status['expired_count']} expired, "
                    f"{cache_status['invalid_count']} invalid."
                ),
                hint=(
                    "Refresh the cache with `data update` or clear invalid cache files."
                    if status != "ok"
                    else None
                ),
            )
        )

    effective_attack_mapping_file = attack_mapping_file
    effective_attack_metadata_file = attack_technique_metadata_file
    effective_waiver_file = waiver_file
    if effective_attack_mapping_file is None and loaded is not None:
        defaults = loaded.document.defaults
        if defaults.waiver_file and effective_waiver_file is None:
            effective_waiver_file = Path(defaults.waiver_file)
        if defaults.attack_mapping_file:
            effective_attack_mapping_file = Path(defaults.attack_mapping_file)
        if defaults.attack_technique_metadata_file:
            effective_attack_metadata_file = Path(defaults.attack_technique_metadata_file)

    if effective_waiver_file is not None:
        try:
            waiver_rules = load_waiver_rules(effective_waiver_file)
            waiver_summary = summarize_waiver_rules(waiver_rules)
            if waiver_summary.expired_count:
                status = "error"
            elif waiver_summary.review_due_count:
                status = "degraded"
            else:
                status = "ok"
            detail = (
                f"{waiver_summary.total_rules} rules, {waiver_summary.active_count} active, "
                f"{waiver_summary.review_due_count} review due, "
                f"{waiver_summary.expired_count} expired."
            )
        except ValueError as exc:
            status = "error"
            detail = str(exc)
        checks.append(
            doctor_check(
                "waiver.health",
                name="waiver_health",
                category="waiver",
                status=status,
                detail=detail,
                hint=(
                    "Review expired or review-due waivers and update the waiver file."
                    if status != "ok"
                    else None
                ),
            )
        )

    if effective_attack_mapping_file is not None:
        try:
            result = validate_attack_inputs(
                attack_source="ctid-json",
                attack_mapping_file=effective_attack_mapping_file,
                attack_technique_metadata_file=effective_attack_metadata_file,
            )
            status = "degraded" if result["warnings"] else "ok"
            detail = (
                f"{result['unique_cves']} CVEs, {result['mapping_count']} mapping objects, "
                f"{result['technique_count']} technique metadata entries."
            )
        except (OSError, ValidationError, ValueError) as exc:
            status = "error"
            detail = str(exc)
        checks.append(
            doctor_check(
                "attack.validation",
                name="attack_validation",
                category="attack",
                status=status,
                detail=detail,
                hint=(
                    "Run `attack validate` directly to inspect ATT&CK mapping issues."
                    if status != "ok"
                    else None
                ),
            )
        )

    if live:
        nvd_api_key = os.getenv(DEFAULT_NVD_API_KEY_ENV)
        checks.append(
            doctor_check(
                "auth.nvd_api_key",
                name="nvd_api_key",
                category="auth",
                status="ok" if nvd_api_key else "degraded",
                detail=(
                    f"{DEFAULT_NVD_API_KEY_ENV} is configured."
                    if nvd_api_key
                    else (
                        f"{DEFAULT_NVD_API_KEY_ENV} is not configured; live checks and NVD "
                        "enrichment will use anonymous rate limits."
                    )
                ),
                hint=(
                    f"Set {DEFAULT_NVD_API_KEY_ENV} for higher NVD rate limits."
                    if not nvd_api_key
                    else None
                ),
            )
        )
        checks.extend(run_live_doctor_checks())

    doctor_summary = summarize_doctor_checks(checks)
    return DoctorReport(
        generated_at=iso_utc_now(),
        live=live,
        config_file=str(loaded.path) if loaded is not None else None,
        summary=doctor_summary,
        checks=checks,
    )


def render_doctor_table(report: DoctorReport) -> Table:
    table = Table(title="Doctor Checks", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("ID")
    table.add_column("Scope")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")
    for check in report.checks:
        table.add_row(
            check.name,
            check.check_id,
            check.scope,
            check.category,
            check.status.upper(),
            check.detail if check.hint is None else f"{check.detail} Hint: {check.hint}",
        )
    return table


def run_live_doctor_checks() -> list[DoctorCheck]:
    return [
        probe_live_source(
            "nvd_api",
            NVD_API_URL,
            params={"cveId": "CVE-2021-44228"},
        ),
        probe_live_source(
            "epss_api",
            EPSS_API_URL,
            params={"cve": "CVE-2021-44228"},
        ),
        probe_kev_live_source(),
    ]


def probe_live_source(
    name: str,
    url: str,
    *,
    params: dict[str, str] | None = None,
) -> DoctorCheck:
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:
        return doctor_check(
            f"live.{name}",
            name=name,
            scope="live",
            category="connectivity",
            status="error",
            detail=str(exc),
            hint="Check network reachability, proxy configuration, and source availability.",
        )
    return doctor_check(
        f"live.{name}",
        name=name,
        scope="live",
        category="connectivity",
        status="ok",
        detail=f"{url} reachable ({response.status_code}).",
    )


def probe_kev_live_source() -> DoctorCheck:
    primary = probe_live_source("kev_feed", KEV_FEED_URL)
    if primary.status == "ok":
        return primary
    mirror = probe_live_source("kev_mirror", KEV_MIRROR_URL)
    if mirror.status == "ok":
        return doctor_check(
            "live.kev_feed",
            name="kev_feed",
            scope="live",
            category="connectivity",
            status="degraded",
            detail="Primary KEV feed unreachable; mirror endpoint reachable.",
            hint="Prefer the primary feed when possible; mirror fallback is active.",
        )
    return doctor_check(
        "live.kev_feed",
        name="kev_feed",
        scope="live",
        category="connectivity",
        status="error",
        detail=f"Primary and mirror KEV endpoints failed: {primary.detail} / {mirror.detail}",
        hint="Check outbound connectivity and KEV source availability.",
    )


def unique_path_entries(entries: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    unique: list[tuple[str, Path]] = []
    seen: set[tuple[str, Path]] = set()
    for label, path in entries:
        key = (label, path)
        if key in seen:
            continue
        seen.add(key)
        unique.append((label, path))
    return unique


def doctor_check_name(label: str) -> str:
    normalized = label.lower().replace("att&ck", "attack")
    normalized = normalized.replace(" ", "_").replace("&", "and")
    return normalized


def doctor_check_id(label: str) -> str:
    normalized = doctor_check_name(label)
    if normalized == "cache_directory":
        return "cache.directory"
    return f"path.{normalized}"


def doctor_check(
    check_id: str,
    *,
    name: str,
    status: str,
    detail: str,
    scope: str = "local",
    category: str = "general",
    hint: str | None = None,
) -> DoctorCheck:
    return DoctorCheck(
        check_id=check_id,
        name=name,
        scope=scope,
        category=category,
        status=status,
        detail=detail,
        hint=hint,
    )


def summarize_doctor_checks(checks: list[DoctorCheck]) -> DoctorSummary:
    ok_count = sum(1 for check in checks if check.status == "ok")
    degraded_count = sum(1 for check in checks if check.status == "degraded")
    error_count = sum(1 for check in checks if check.status == "error")
    if error_count:
        overall_status = "error"
    elif degraded_count:
        overall_status = "degraded"
    else:
        overall_status = "ok"
    return DoctorSummary(
        overall_status=overall_status,
        ok_count=ok_count,
        degraded_count=degraded_count,
        error_count=error_count,
    )
