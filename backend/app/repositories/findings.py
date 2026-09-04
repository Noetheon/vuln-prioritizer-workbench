"""Finding repository for Workbench persistence."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import unquote

from packageurl import PackageURL
from sqlalchemy.orm import QueryableAttribute, selectinload
from sqlmodel import Session, col, func, select

from app.domain.component_identity import (
    canonicalize_package_url,
    component_scope_identity,
    component_storage_key,
)
from app.models import (
    Asset,
    Component,
    Finding,
    FindingAttackContext,
    FindingCurrentProjection,
    FindingStatus,
    Vulnerability,
)
from app.models.base import get_datetime_utc
from app.repositories.finding_attack_query import (
    list_project_attack_contexts as _list_project_attack_contexts,
)

_MANUAL_WORKFLOW_STATUSES = {
    FindingStatus.IN_REVIEW,
    FindingStatus.REMEDIATING,
}


@dataclass(frozen=True, slots=True)
class ComponentPersistenceIdentity:
    """Stable component values shared by repository lookup and import caching."""

    name: str
    version: str | None
    purl: str | None
    ecosystem: str | None
    package_type: str | None
    scope_key: str
    storage_key: str


class FindingIdentityInvariantError(RuntimeError):
    """Raised when a dedup hit conflicts with immutable finding identity."""


class ComponentIdentityInvariantError(RuntimeError):
    """Raised when legacy component rows have an ambiguous canonical identity."""


class FindingRepository:
    """Finding, component, and vulnerability persistence helpers."""

    def __init__(self, session: Session) -> None:
        """Initialize a new instance of FindingRepository."""
        self.session = session
        self._components_by_storage_key: dict[str, Component] = {}

    def upsert_component(
        self,
        *,
        name: str | None,
        version: str | None = None,
        purl: str | None = None,
        ecosystem: str | None = None,
        package_type: str | None = None,
        existing_component: Component | None = None,
        lookup_existing: bool = True,
        flush: bool = True,
    ) -> Component:
        """Create or update a shared component identity."""
        identity = normalize_component_persistence_identity(
            name=name,
            version=version,
            purl=purl,
            ecosystem=ecosystem,
            package_type=package_type,
        )
        component = existing_component
        if component is not None and component.identity_material != identity.scope_key:
            raise ComponentIdentityInvariantError(
                "Component identity hash resolved to contradictory canonical material."
            )
        if component is None and lookup_existing:
            component = self._component_by_identity(identity)
        if component is None:
            component = Component(
                name=identity.name,
                version=identity.version,
                purl=identity.purl,
                ecosystem=identity.ecosystem,
                identity_key=identity.storage_key,
                identity_material=identity.scope_key,
            )
            self.session.add(component)
        else:
            component.name = identity.name
            component.version = identity.version
            component.purl = identity.purl
            component.ecosystem = identity.ecosystem

        component.package_type = identity.package_type
        component.identity_key = identity.storage_key
        component.identity_material = identity.scope_key
        self._remember_component_identity(component, identity)
        if flush:
            self.session.flush()
        return component

    def _component_by_identity(
        self,
        identity: ComponentPersistenceIdentity,
    ) -> Component | None:
        """Resolve one indexed canonical component and verify its hash material."""
        component = self._components_by_storage_key.get(identity.storage_key)
        if component is None:
            component = self.session.exec(
                select(Component).where(Component.identity_key == identity.storage_key)
            ).first()
        if component is not None and component.identity_material != identity.scope_key:
            raise ComponentIdentityInvariantError(
                "Component identity hash resolved to contradictory canonical material."
            )
        if component is not None:
            self._components_by_storage_key[identity.storage_key] = component
        return component

    def _remember_component_identity(
        self,
        component: Component,
        identity: ComponentPersistenceIdentity,
    ) -> None:
        """Keep the session-local component identity index coherent after an upsert."""
        previous = self._components_by_storage_key.get(identity.storage_key)
        if previous is not None and previous is not component and previous.id != component.id:
            raise ComponentIdentityInvariantError(
                "Multiple component rows resolved to one indexed canonical identity."
            )
        self._components_by_storage_key[identity.storage_key] = component

    def upsert_vulnerability(
        self,
        *,
        cve_id: str,
        source_id: str | None = None,
        title: str | None = None,
        description: str | None = None,
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        severity: str | None = None,
        cwe: str | None = None,
        published_at: str | None = None,
        modified_at: str | None = None,
        provider_json: dict[str, Any] | None = None,
        existing_vulnerability: Vulnerability | None = None,
        lookup_existing: bool = True,
        flush: bool = True,
    ) -> Vulnerability:
        """Create or update a CVE/provider record by CVE id."""
        vulnerability = existing_vulnerability
        if vulnerability is not None and vulnerability.cve_id != cve_id:
            raise ValueError("Existing vulnerability does not match the requested CVE ID.")
        if vulnerability is None and lookup_existing:
            statement = select(Vulnerability).where(Vulnerability.cve_id == cve_id)
            vulnerability = self.session.exec(statement).first()
        if vulnerability is None:
            vulnerability = Vulnerability(cve_id=cve_id)
            self.session.add(vulnerability)

        vulnerability.source_id = source_id
        vulnerability.title = title
        vulnerability.description = description
        vulnerability.cvss_score = cvss_score
        vulnerability.cvss_vector = cvss_vector
        vulnerability.severity = severity
        vulnerability.cwe = cwe
        vulnerability.published_at = published_at
        vulnerability.modified_at = modified_at
        vulnerability.provider_json = provider_json or {}
        if flush:
            self.session.flush()
        return vulnerability

    def create_or_update_finding(
        self,
        *,
        project_id: uuid.UUID,
        vulnerability_id: uuid.UUID,
        cve_id: str,
        dedup_key: str | None = None,
        component_id: uuid.UUID | None = None,
        asset_id: uuid.UUID | None = None,
        status: FindingStatus | str = FindingStatus.OPEN,
        existing_finding: Finding | None = None,
        lookup_existing: bool = True,
        allow_asset_rebind: bool = False,
        flush: bool = True,
    ) -> Finding:
        """Create or update a finding by project/vulnerability/component/asset identity."""
        finding = existing_finding
        if finding is None and lookup_existing and dedup_key is not None:
            finding = self.get_project_finding_by_dedup_key(
                project_id=project_id,
                dedup_key=dedup_key,
            )
        if finding is None and lookup_existing:
            finding = self.get_project_finding_by_identity(
                project_id=project_id,
                vulnerability_id=vulnerability_id,
                component_id=component_id,
                asset_id=asset_id,
            )
        if finding is not None:
            _ensure_reused_finding_identity(
                finding,
                dedup_key=dedup_key,
                project_id=project_id,
                cve_id=cve_id,
                vulnerability_id=vulnerability_id,
                component_id=component_id,
                asset_id=asset_id,
                allow_asset_rebind=allow_asset_rebind,
            )
            if allow_asset_rebind and finding.asset_id != asset_id:
                if asset_id is None:
                    raise FindingIdentityInvariantError(
                        "Explicit asset rebinding cannot detach a finding from its asset."
                    )
                # Import persistence deliberately batches flushes. A newly
                # created replacement asset can therefore still be pending
                # while this invariant is checked.
                target_asset = next(
                    (
                        pending
                        for pending in self.session.new
                        if isinstance(pending, Asset) and pending.id == asset_id
                    ),
                    None,
                ) or self.session.get(Asset, asset_id)
                if target_asset is None or target_asset.project_id != project_id:
                    raise FindingIdentityInvariantError(
                        "Explicit asset rebinding requires an asset in the same project."
                    )
                finding.asset_id = asset_id
        if finding is None:
            finding = Finding(
                project_id=project_id,
                vulnerability_id=vulnerability_id,
                component_id=component_id,
                asset_id=asset_id,
                cve_id=cve_id,
                dedup_key=dedup_key or str(uuid.uuid4()),
                status=FindingStatus(status),
            )
            self.session.add(finding)

        if dedup_key is not None:
            finding.dedup_key = dedup_key
        finding.cve_id = cve_id
        finding.status = _import_status_for_finding(
            current=FindingStatus(finding.status),
            imported=FindingStatus(status),
        )
        finding.last_seen_at = get_datetime_utc()
        if flush:
            self.session.flush()
        return finding

    def get_project_finding_by_dedup_key(
        self,
        *,
        project_id: uuid.UUID,
        dedup_key: str,
    ) -> Finding | None:
        """Return a project finding by its stable import dedup key."""
        statement = select(Finding).where(
            Finding.project_id == project_id,
            Finding.dedup_key == dedup_key,
        )
        return self.session.exec(statement).first()

    def get_project_finding_by_identity(
        self,
        *,
        project_id: uuid.UUID,
        vulnerability_id: uuid.UUID,
        component_id: uuid.UUID | None = None,
        asset_id: uuid.UUID | None = None,
    ) -> Finding | None:
        """Return a finding by project/vulnerability/component/asset identity."""
        filters: list[Any] = [
            Finding.project_id == project_id,
            Finding.vulnerability_id == vulnerability_id,
        ]
        filters.append(
            col(Finding.component_id).is_(None)
            if component_id is None
            else Finding.component_id == component_id
        )
        filters.append(
            col(Finding.asset_id).is_(None) if asset_id is None else Finding.asset_id == asset_id
        )
        return self.session.exec(select(Finding).where(*filters)).first()

    def get_finding(self, finding_id: uuid.UUID) -> Finding | None:
        """Return a finding by primary key."""
        return self.session.get(Finding, finding_id)

    def list_project_findings(self, project_id: uuid.UUID) -> list[Finding]:
        """Return project findings ordered by operational priority."""
        asset_relationship = cast(QueryableAttribute[Any], Finding.asset)
        component_relationship = cast(QueryableAttribute[Any], Finding.component)
        statement = (
            select(Finding)
            .outerjoin(
                FindingCurrentProjection,
                col(FindingCurrentProjection.finding_id) == col(Finding.id),
            )
            .where(Finding.project_id == project_id)
            .options(
                selectinload(asset_relationship),
                selectinload(component_relationship),
            )
            .order_by(
                func.coalesce(
                    func.nullif(FindingCurrentProjection.operational_rank, 0),
                    999_999,
                ),
                func.coalesce(FindingCurrentProjection.priority_rank, 99),
                Finding.cve_id,
                col(Finding.id),
            )
        )
        return list(self.session.exec(statement).all())

    def count_project_findings(self, project_id: uuid.UUID) -> int:
        """Return the project finding count without materializing finding rows."""
        statement = (
            select(func.count()).select_from(Finding).where(Finding.project_id == project_id)
        )
        return int(self.session.exec(statement).one())

    def _count_project_findings_where(self, project_id: uuid.UUID, *criteria: Any) -> int:
        """Count project findings matching additional SQL identity criteria."""
        statement = (
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.project_id == project_id,
                *criteria,
            )
        )
        return int(self.session.exec(statement).one())

    def list_project_attack_contexts(self, project_id: uuid.UUID) -> list[FindingAttackContext]:
        """Return ATT&CK contexts for findings in one project, newest rows first."""
        return _list_project_attack_contexts(self.session, project_id)


def _import_status_for_finding(
    *,
    current: FindingStatus,
    imported: FindingStatus,
) -> FindingStatus:
    """Keep analyst workflow status unless import evidence moves the finding elsewhere."""
    if imported == FindingStatus.OPEN and current in _MANUAL_WORKFLOW_STATUSES:
        return current
    return imported


def normalize_component_persistence_identity(
    *,
    name: str | None,
    version: str | None = None,
    purl: str | None = None,
    ecosystem: str | None = None,
    package_type: str | None = None,
) -> ComponentPersistenceIdentity:
    """Normalize component storage with the same identity rules as scope keys."""
    normalized_purl = canonicalize_package_url(purl)
    # Preserve a useful, source-provided display label while deriving the
    # case-insensitive identity below. Storage normalization must not leak into
    # reports or silently rewrite the operator-facing component name.
    normalized_name = _normalized_component_text(name, collapse_whitespace=True)
    normalized_version = _normalized_component_text(version)
    if normalized_purl is not None:
        try:
            purl_version = PackageURL.from_string(normalized_purl).version
        except ValueError:
            purl_version = None
        if purl_version is not None:
            # The package version encoded by a valid PURL is the canonical
            # stored value. Scanner-level upstream versions may legitimately
            # omit distro-specific release suffixes.
            normalized_version = purl_version
    normalized_package_type = _normalized_component_text(
        package_type,
        casefold=True,
        collapse_whitespace=True,
    )
    normalized_ecosystem = (
        _normalized_component_text(
            ecosystem,
            casefold=True,
            collapse_whitespace=True,
        )
        or normalized_package_type
    )

    if normalized_purl is not None:
        normalized_name = normalized_name or _component_name_from_purl(normalized_purl)
        scope_key = component_scope_identity(
            component_name=normalized_name,
            component_version=normalized_version,
            purl=normalized_purl,
            package_type=normalized_package_type,
        )
    elif normalized_name is not None:
        scope_key = component_scope_identity(
            component_name=normalized_name,
            component_version=normalized_version,
            # Legacy rows often persisted only ``ecosystem`` while current
            # imports populate ``package_type``. Both describe the same
            # non-PURL coordinate namespace and must therefore share one key.
            package_type=normalized_package_type or normalized_ecosystem,
        )
    else:
        raise ValueError("A component requires either a non-blank name or PURL.")
    if scope_key is None:
        raise ValueError("A component requires a stable persistence identity.")

    return ComponentPersistenceIdentity(
        name=normalized_name,
        version=normalized_version,
        purl=normalized_purl,
        ecosystem=normalized_ecosystem,
        package_type=normalized_package_type,
        scope_key=scope_key,
        storage_key=component_storage_key(scope_key),
    )


def _normalized_component_text(
    value: str | None,
    *,
    casefold: bool = False,
    collapse_whitespace: bool = False,
) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if collapse_whitespace:
        normalized = " ".join(normalized.split())
    return normalized.casefold() if casefold else normalized


def _component_name_from_purl(purl: str) -> str:
    """Derive a bounded display name when a valid PURL is the only component field."""
    normalized = purl.split("?", 1)[0].split("#", 1)[0]
    tail = normalized.rsplit("/", 1)[-1]
    candidate = unquote(tail.split("@", 1)[0]).strip()
    return (candidate or purl)[:300]


def _ensure_reused_finding_identity(
    finding: Finding,
    *,
    dedup_key: str | None,
    project_id: uuid.UUID,
    cve_id: str,
    vulnerability_id: uuid.UUID,
    component_id: uuid.UUID | None,
    asset_id: uuid.UUID | None,
    allow_asset_rebind: bool,
) -> None:
    """Reject reuse before mutable finding state can be changed."""
    expected_identity = {
        "project_id": project_id,
        "cve_id": cve_id,
        "vulnerability_id": vulnerability_id,
        "component_id": component_id,
    }
    if not allow_asset_rebind:
        expected_identity["asset_id"] = asset_id
    mismatches = [
        field_name
        for field_name, expected_value in expected_identity.items()
        if getattr(finding, field_name) != expected_value
    ]
    if mismatches:
        fields = ", ".join(mismatches)
        raise FindingIdentityInvariantError(
            f"Finding resolved by dedup_key {dedup_key!r} has conflicting "
            f"immutable identity fields: {fields}."
        )
