from __future__ import annotations

from vuln_prioritizer.models import (
    RollupBucket,
    RollupCandidate,
    RollupMetadata,
    SnapshotDiffItem,
    SnapshotDiffMetadata,
    SnapshotDiffSummary,
)
from vuln_prioritizer.reporting_snapshot import (
    generate_rollup_markdown,
    generate_snapshot_diff_markdown,
    render_rollup_table,
    render_snapshot_diff_table,
)


def test_snapshot_diff_renderers_include_summary_and_escape_markdown() -> None:
    items = [
        SnapshotDiffItem(
            cve_id="CVE-2026-0001",
            category="context|changed",
            before_priority=None,
            after_priority="High",
            context_change_fields=["service|owner", "target"],
        )
    ]
    summary = SnapshotDiffSummary(added=1, priority_up=1, context_changed=1)
    metadata = SnapshotDiffMetadata(
        generated_at="2026-05-01T12:00:00Z",
        before_path="before.json",
        after_path="after.json",
        include_unchanged=True,
    )

    table = render_snapshot_diff_table(items, summary, metadata)
    markdown = generate_snapshot_diff_markdown(items, summary, metadata)

    assert table.title == "Snapshot Diff"
    assert "Added: 1" in str(table.caption)
    assert "Context changed: 1" in str(table.caption)
    assert "- Include unchanged: `yes`" in markdown
    assert (
        "| CVE-2026-0001 | context\\|changed | N.A. | High | service\\|owner, target |" in markdown
    )


def test_rollup_renderers_include_candidates_actions_and_empty_fallbacks() -> None:
    buckets = [
        RollupBucket(
            bucket="service|payments",
            dimension="service",
            remediation_rank=1,
            finding_count=3,
            actionable_count=2,
            critical_count=1,
            kev_count=1,
            waived_count=1,
            internet_facing_count=1,
            production_count=1,
            highest_priority="Critical",
            context_hints=["owner|platform"],
            owners=["team|platform"],
            recommended_actions=["Patch now|notify owner"],
            top_candidates=[
                RollupCandidate(
                    cve_id="CVE-2026-0002",
                    priority_label="Critical",
                    in_kev=True,
                    recommended_action="Patch immediately.",
                    rank_reason="Critical|KEV",
                )
            ],
        ),
        RollupBucket(
            bucket="service:empty",
            dimension="service",
            finding_count=1,
            actionable_count=0,
            highest_priority="Low",
        ),
    ]
    metadata = RollupMetadata(
        generated_at="2026-05-01T12:00:00Z",
        input_path="analysis.json",
        input_kind="analysis",
        dimension="service",
        bucket_count=2,
        top=3,
    )

    table = render_rollup_table(buckets, metadata)
    markdown = generate_rollup_markdown(buckets, metadata)

    assert table.title == "Service Rollup"
    assert "# Service Rollup" in markdown
    assert "- Top remediation candidates per bucket: 3" in markdown
    assert "service\\|payments" in markdown
    assert "team\\|platform" in markdown
    assert "CVE-2026-0002 (Critical\\|KEV)" in markdown
    assert "Patch now\\|notify owner" in markdown
    assert (
        "| 0 | service:empty | Low | 0/1 | 0 | 0 | 0 | N.A. | N.A. | All findings waived | N.A. |"
        in markdown
    )
