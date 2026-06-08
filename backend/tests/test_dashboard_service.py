from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.services.dashboard import _remediation_queue_sort_key


def test_remediation_queue_sort_key_stabilizes_equal_score_ties() -> None:
    tied_views = [
        _view("payments", "team-payments", "payments-api"),
        _view("fulfillment", "team-fulfillment", "fulfillment-api"),
        _view("catalog", "team-catalog", "catalog-api"),
    ]

    sorted_views = sorted(tied_views, key=_remediation_queue_sort_key)

    assert [_service(view) for view in sorted_views] == [
        "catalog",
        "fulfillment",
        "payments",
    ]


def test_remediation_queue_sort_key_keeps_risk_score_ahead_of_text_ties() -> None:
    sorted_views = sorted(
        [
            _view("catalog", "team-catalog", "catalog-api", risk_score=80.0),
            _view("payments", "team-payments", "payments-api", risk_score=100.0),
        ],
        key=_remediation_queue_sort_key,
    )

    assert [_service(view) for view in sorted_views] == ["payments", "catalog"]


def _view(
    business_service: str,
    owner: str,
    asset_key: str,
    *,
    risk_score: float = 100.0,
) -> SimpleNamespace:
    asset = SimpleNamespace(
        asset_key=asset_key,
        business_service=business_service,
        owner=owner,
    )
    component = SimpleNamespace(name="log4j-core")
    finding = SimpleNamespace(asset=asset, component=component, id=uuid.uuid4())
    return SimpleNamespace(
        cve_id="CVE-2021-44228",
        finding=finding,
        operational_rank=1,
        priority_rank=1,
        risk_score=risk_score,
    )


def _service(view: SimpleNamespace) -> str:
    return str(view.finding.asset.business_service)
