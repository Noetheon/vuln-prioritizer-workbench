from __future__ import annotations

from datetime import date

import pytest

from vuln_prioritizer.models import (
    FindingProvenance,
    InputOccurrence,
    PrioritizedFinding,
    WaiverRule,
)
from vuln_prioritizer.services.waivers import (
    _normalized_set,
    apply_waivers,
    load_waiver_rules,
    summarize_waiver_rules,
)


def _finding(cve_id: str) -> PrioritizedFinding:
    return PrioritizedFinding(
        cve_id=cve_id,
        priority_label="High",
        priority_rank=2,
        rationale="High EPSS with a visible remediation path.",
        recommended_action="Patch immediately.",
    )


def test_summarize_waiver_rules_counts_active_review_due_and_expired() -> None:
    summary = summarize_waiver_rules(
        [
            WaiverRule(
                id="active",
                cve_id="CVE-2024-0001",
                owner="team-a",
                reason="Accepted for now.",
                expires_on="2026-05-30",
            ),
            WaiverRule(
                id="review-due",
                cve_id="CVE-2024-0002",
                owner="team-b",
                reason="Needs review.",
                expires_on="2026-04-28",
            ),
            WaiverRule(
                id="expired",
                cve_id="CVE-2024-0003",
                owner="team-c",
                reason="Expired already.",
                expires_on="2026-04-01",
            ),
        ],
        today=date(2026, 4, 21),
    )

    assert summary.total_rules == 3
    assert summary.active_count == 1
    assert summary.review_due_count == 1
    assert summary.expired_count == 1


def test_apply_waivers_marks_review_due_and_expired_findings() -> None:
    findings, warnings = apply_waivers(
        [_finding("CVE-2024-0001"), _finding("CVE-2024-0002")],
        [
            WaiverRule(
                id="review-due",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Deferred until the next maintenance window.",
                expires_on="2026-04-25",
                review_on="2026-04-20",
                approval_ref="CAB-42",
                ticket_url="https://tickets.example/CAB-42",
            ),
            WaiverRule(
                id="expired",
                cve_id="CVE-2024-0002",
                owner="risk-review",
                reason="Past the approved window.",
                expires_on="2026-04-01",
            ),
        ],
        today=date(2026, 4, 21),
    )

    by_cve = {finding.cve_id: finding for finding in findings}

    assert by_cve["CVE-2024-0001"].waived is True
    assert by_cve["CVE-2024-0001"].waiver_status == "review_due"
    assert by_cve["CVE-2024-0001"].waiver_days_remaining == 4
    assert by_cve["CVE-2024-0001"].waiver_id == "review-due"
    assert by_cve["CVE-2024-0001"].waiver_matched_scope == "global"
    assert by_cve["CVE-2024-0001"].waiver_approval_ref == "CAB-42"
    assert by_cve["CVE-2024-0001"].waiver_ticket_url == "https://tickets.example/CAB-42"
    assert by_cve["CVE-2024-0002"].waived is False
    assert by_cve["CVE-2024-0002"].waiver_status == "expired"
    assert by_cve["CVE-2024-0002"].waiver_days_remaining == -20
    assert any("review due" in warning for warning in warnings)
    assert any("expired waiver" in warning for warning in warnings)


def test_load_waiver_rules_rejects_duplicate_ids_case_insensitively(tmp_path) -> None:
    waiver_file = tmp_path / "waivers.yml"
    waiver_file.write_text(
        "\n".join(
            [
                "waivers:",
                "  - id: accepted-risk",
                "    cve_id: CVE-2024-0001",
                "    owner: team-a",
                "    reason: Accepted temporarily.",
                "    expires_on: 2026-05-01",
                "  - id: ACCEPTED-RISK",
                "    cve_id: CVE-2024-0002",
                "    owner: team-b",
                "    reason: Accepted temporarily.",
                "    expires_on: 2026-05-02",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate waiver id"):
        load_waiver_rules(waiver_file)


def test_load_waiver_rules_rejects_scalar_scope_fields(tmp_path) -> None:
    waiver_file = tmp_path / "waivers.yml"
    waiver_file.write_text(
        "\n".join(
            [
                "waivers:",
                "  - id: scalar-scope",
                "    cve_id: CVE-2024-0001",
                "    owner: team-a",
                "    reason: Accepted temporarily.",
                "    expires_on: 2026-05-01",
                "    asset_ids: asset-api",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid asset_ids"):
        load_waiver_rules(waiver_file)


def test_load_waiver_rules_rejects_missing_file(tmp_path) -> None:
    missing_file = tmp_path / "missing-waivers.yml"

    with pytest.raises(ValueError, match="Waiver file does not exist"):
        load_waiver_rules(missing_file)


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ("waivers: [\n", "not valid YAML"),
        ("- item\n", "top-level YAML object"),
        ("waivers: nope\n", "top-level `waivers` list"),
        ("waivers:\n  - scalar\n", "must be a YAML object"),
        (
            "\n".join(
                [
                    "waivers:",
                    "  - cve_id: not-a-cve",
                    "    owner: team-a",
                    "    reason: Accepted temporarily.",
                    "    expires_on: 2026-05-01",
                ]
            )
            + "\n",
            "invalid CVE identifier",
        ),
        (
            "\n".join(
                [
                    "waivers:",
                    "  - cve_id: CVE-2024-0001",
                    "    reason: Missing owner.",
                    "    expires_on: 2026-05-01",
                ]
            )
            + "\n",
            "is invalid",
        ),
        (
            "\n".join(
                [
                    "waivers:",
                    "  - cve_id: CVE-2024-0001",
                    "    owner: team-a",
                    "    reason: Accepted temporarily.",
                    "    expires_on: not-a-date",
                ]
            )
            + "\n",
            "invalid expires_on date",
        ),
        (
            "\n".join(
                [
                    "waivers:",
                    "  - cve_id: CVE-2024-0001",
                    "    owner: team-a",
                    "    reason: Accepted temporarily.",
                    "    expires_on: 2026-05-01",
                    "    review_on: not-a-date",
                ]
            )
            + "\n",
            "invalid review_on date",
        ),
        (
            "\n".join(
                [
                    "waivers:",
                    "  - cve_id: CVE-2024-0001",
                    "    owner: team-a",
                    "    reason: Accepted temporarily.",
                    "    expires_on: 2026-05-01",
                    "    review_on: 2026-05-02",
                ]
            )
            + "\n",
            "review_on after expires_on",
        ),
    ],
)
def test_load_waiver_rules_rejects_invalid_shapes_and_dates(
    tmp_path,
    body: str,
    match: str,
) -> None:
    waiver_file = tmp_path / "waivers.yml"
    waiver_file.write_text(body, encoding="utf-8")

    with pytest.raises(ValueError, match=match):
        load_waiver_rules(waiver_file)


def test_load_waiver_rules_normalizes_scope_values_and_yaml_dates(tmp_path) -> None:
    waiver_file = tmp_path / "waivers.yml"
    waiver_file.write_text(
        "\n".join(
            [
                "waivers:",
                "  - cve_id: cve-2024-0001",
                "    owner: team-a",
                "    reason: Accepted temporarily.",
                "    expires_on: 2026-05-01",
                "    review_on: 2026-04-01",
                "    asset_ids:",
                "      - asset-a",
                "      - null",
                "      - asset-a",
                "    targets:",
                "      - service:api",
                "      - service:api",
                "    services:",
                "      - payments",
                "      - ''",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    rules = load_waiver_rules(waiver_file)

    assert len(rules) == 1
    assert rules[0].cve_id == "CVE-2024-0001"
    assert rules[0].expires_on == "2026-05-01"
    assert rules[0].review_on == "2026-04-01"
    assert rules[0].asset_ids == ["asset-a"]
    assert rules[0].targets == ["service:api"]
    assert rules[0].services == ["payments"]
    assert _normalized_set("not-a-list") == set()


def test_waiver_scope_matching_normalizes_asset_target_and_service_values() -> None:
    finding = _finding("CVE-2024-0001").model_copy(
        update={
            "provenance": FindingProvenance(
                asset_ids=[" Asset-API "],
                targets=["repository:Backend/Requirements.txt"],
                occurrences=[
                    InputOccurrence(
                        cve_id="CVE-2024-0001",
                        target_kind="repository",
                        target_ref="Backend/Requirements.txt",
                        asset_business_service="Identity",
                    )
                ],
            )
        }
    )

    findings, warnings = apply_waivers(
        [finding],
        [
            WaiverRule(
                id="scoped",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Scoped acceptance.",
                expires_on="2026-05-30",
                asset_ids=["asset-api"],
                targets=["REPOSITORY:backend/requirements.txt"],
                services=["identity"],
            )
        ],
        today=date(2026, 4, 21),
    )

    assert warnings == []
    assert findings[0].waived is True
    assert findings[0].waiver_id == "scoped"
    assert findings[0].waiver_matched_scope is not None
    assert "asset-api" in findings[0].waiver_matched_scope


def test_apply_waivers_warns_for_multiple_active_matches_and_unmatched_rules() -> None:
    findings, warnings = apply_waivers(
        [_finding("CVE-2024-0001")],
        [
            WaiverRule(
                id="active-a",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Scoped acceptance.",
                expires_on="2026-06-01",
            ),
            WaiverRule(
                id="active-b",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Second acceptance.",
                expires_on="2026-07-01",
            ),
            WaiverRule(
                id="unmatched",
                cve_id="CVE-2024-9999",
                owner="risk-review",
                reason="Does not match this run.",
                expires_on="2026-07-01",
            ),
        ],
        today=date(2026, 4, 21),
    )

    assert findings[0].waived is True
    assert findings[0].waiver_id == "active-a"
    assert any("Multiple active waivers matched CVE-2024-0001" in warning for warning in warnings)
    assert any("Waiver unmatched did not match any finding" in warning for warning in warnings)


def test_apply_waivers_warns_for_multiple_expired_matches() -> None:
    findings, warnings = apply_waivers(
        [_finding("CVE-2024-0001")],
        [
            WaiverRule(
                id="expired-a",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Past the first approved window.",
                expires_on="2026-04-01",
            ),
            WaiverRule(
                id="expired-b",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Past the second approved window.",
                expires_on="2026-04-02",
            ),
        ],
        today=date(2026, 4, 21),
    )

    assert findings[0].waived is False
    assert findings[0].waiver_id == "expired-a"
    assert any("Multiple expired waivers matched CVE-2024-0001" in warning for warning in warnings)


def test_apply_waivers_leaves_findings_when_scoped_rules_do_not_match() -> None:
    finding = _finding("CVE-2024-0001").model_copy(
        update={
            "provenance": FindingProvenance(
                asset_ids=["asset-api"],
                targets=["service:api"],
                occurrences=[
                    InputOccurrence(
                        cve_id="CVE-2024-0001",
                        target_kind="service",
                        target_ref="api",
                        asset_business_service="payments",
                    )
                ],
            )
        }
    )

    findings, warnings = apply_waivers(
        [finding],
        [
            WaiverRule(
                id="asset-mismatch",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Wrong asset.",
                expires_on="2026-06-01",
                asset_ids=["other-asset"],
            ),
            WaiverRule(
                id="target-mismatch",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Wrong target.",
                expires_on="2026-06-01",
                targets=["service:other"],
            ),
            WaiverRule(
                id="service-mismatch",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Wrong service.",
                expires_on="2026-06-01",
                services=["identity"],
            ),
        ],
        today=date(2026, 4, 21),
    )

    assert findings == [finding]
    assert all("did not match any finding" in warning for warning in warnings)
