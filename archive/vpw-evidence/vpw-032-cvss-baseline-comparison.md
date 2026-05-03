# VPW-032 CVSS-only Baseline Comparison Evidence

VPW-032 adds a Workbench project API and report summary for comparing the
current enriched priority policy against a deterministic CVSS-only baseline.

## API

Endpoint:

```text
GET /api/projects/{project_id}/baseline-comparison?limit=10
```

Response shape:

- `counts.cvss_only` and `counts.enriched` show Critical, High, Medium, and Low totals.
- `summary` shows total, changed, up, down, and unchanged counts.
- `top_changes[]` includes CVE ID, old/new priority, old/new rank, delta, direction, and reason.
- `comparisons[]` includes the full machine-readable comparison rows.
- `methodology.limitations` states that the comparison is decision support, not an absolute truth.

Example response:

```json
{
  "project_id": "project-1",
  "summary": {
    "total": 3,
    "changed": 2,
    "up": 1,
    "down": 1,
    "unchanged": 1
  },
  "top_changes": [
    {
      "cve_id": "CVE-2026-0001",
      "old_priority": "Medium",
      "old_rank": 3,
      "new_priority": "Critical",
      "new_rank": 1,
      "reason": "KEV membership raises this CVE from the CVSS-only Medium baseline to Critical."
    }
  ]
}
```

Full example artifact: `docs/examples/example_baseline_comparison.json`.

## Report Excerpt

Analysis Markdown and Workbench Markdown summaries now include:

```text
## CVSS-only Baseline Comparison
- Changed rows: 2
- Up: 1
- Down: 1
- Unchanged: 1
- Method limit: This comparison is a decision-support view, not an absolute truth.
```

The analysis JSON payload includes `baseline_comparison` with the same summary
and top-change data used by the Markdown report.

## Validation Targets

- Unit tests cover counts, up/down/unchanged totals, top changes, old/new ranks,
  reasons, and report-sized payloads without full rows.
- Workbench API tests cover the project comparison endpoint and report payload.
- Schema tests validate the additive `baseline_comparison` analysis contract.
- Generated client: this endpoint belongs to the existing legacy Workbench API
  mounted by `vuln_prioritizer.api.app`; the generated React client currently
  targets `backend/app/main.py` (`/api/v1`). The client generation check should
  still be run to prove no unintended template-client drift.
