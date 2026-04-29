"""Workbench helpers for the executive report view."""

from __future__ import annotations

from typing import Any

from vuln_prioritizer.reporting_executive import build_executive_report_model


class WorkbenchExecutiveReportError(RuntimeError):
    """Raised when an analysis run cannot be rendered as an executive report."""


def build_run_executive_report_model(
    *,
    repo: Any,
    run: Any,
    project: Any | None = None,
) -> dict[str, Any]:
    """Build the executive report model for a persisted Workbench analysis run."""
    payload = run.summary_json if isinstance(run.summary_json, dict) else {}
    if "metadata" not in payload or "findings" not in payload:
        raise WorkbenchExecutiveReportError("Analysis run does not contain a report payload.")
    return build_executive_report_model(
        payload,
        project_name=getattr(project, "name", None),
        project_id=getattr(project, "id", None),
        run_id=getattr(run, "id", None),
        input_filename=getattr(run, "input_filename", None),
        reports=list(repo.list_run_reports(run.id)),
        evidence_bundles=list(repo.list_run_evidence_bundles(run.id)),
        provider_snapshot=getattr(run, "provider_snapshot", None),
    )
