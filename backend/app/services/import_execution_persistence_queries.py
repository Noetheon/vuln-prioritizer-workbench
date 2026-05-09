"""Batch lookup helpers for Workbench import persistence."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session, col, select

from app.models import Asset, Finding, Vulnerability


def _existing_findings_by_dedup_key(
    *,
    session: Session,
    project_id: uuid.UUID,
    dedup_keys: list[str],
) -> dict[str, Finding]:
    """Load existing project findings for a bulk import without per-row lookups."""
    if not dedup_keys:
        return {}
    findings: dict[str, Finding] = {}
    for chunk in _chunks(sorted(set(dedup_keys)), size=500):
        statement = select(Finding).where(
            Finding.project_id == project_id,
            col(Finding.dedup_key).in_(chunk),
        )
        for finding in session.exec(statement).all():
            findings[finding.dedup_key] = finding
    return findings


def _existing_assets_by_key(
    *,
    session: Session,
    project_id: uuid.UUID,
    asset_keys: list[str],
) -> dict[str, Asset]:
    if not asset_keys:
        return {}
    assets: dict[str, Asset] = {}
    for chunk in _chunks(sorted(set(asset_keys)), size=500):
        statement = select(Asset).where(
            Asset.project_id == project_id,
            col(Asset.asset_key).in_(chunk),
        )
        for asset in session.exec(statement).all():
            assets[asset.asset_key] = asset
    return assets


def _existing_vulnerabilities_by_cve(
    *,
    session: Session,
    cves: list[str],
) -> dict[str, Vulnerability]:
    if not cves:
        return {}
    vulnerabilities: dict[str, Vulnerability] = {}
    for chunk in _chunks(sorted(set(cves)), size=500):
        statement = select(Vulnerability).where(col(Vulnerability.cve_id).in_(chunk))
        for vulnerability in session.exec(statement).all():
            vulnerabilities[vulnerability.cve_id] = vulnerability
    return vulnerabilities


def _chunks(values: list[str], *, size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _chunks_any(values: list[dict[str, Any]], *, size: int) -> list[list[dict[str, Any]]]:
    return [values[index : index + size] for index in range(0, len(values), size)]
