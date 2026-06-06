from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.repositories.findings import _finding_page_sort_key


def test_finding_page_operational_sort_key_stabilizes_equal_rank_ties() -> None:
    query = SimpleNamespace(sort="operational")
    tied_views = [
        _view("payments", "team-payments", "pay-api-01"),
        _view("identity", "team-identity", "id-admin-01"),
        _view("catalog", "team-catalog", "catalog-api-01"),
    ]

    sorted_views = sorted(tied_views, key=lambda view: _finding_page_sort_key(view, query))

    assert [_service(view) for view in sorted_views] == [
        "catalog",
        "identity",
        "payments",
    ]


def _view(business_service: str, owner: str, asset_key: str) -> SimpleNamespace:
    asset = SimpleNamespace(
        asset_key=asset_key,
        business_service=business_service,
        owner=owner,
    )
    component = SimpleNamespace(name="log4j-core", version="2.14.1")
    finding = SimpleNamespace(asset=asset, component=component, id=uuid.uuid4())
    return SimpleNamespace(
        cve_id="CVE-2021-44228",
        finding=finding,
        operational_rank=1,
        priority_rank=1,
    )


def _service(view: SimpleNamespace) -> str:
    return str(view.finding.asset.business_service)
