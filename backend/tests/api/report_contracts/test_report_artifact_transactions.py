from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import update
from sqlmodel import Session, col, select
from utils.workbench_env import WorkbenchApiEnv, seed_domain_graph

from app.models import AnalysisRun, AuditEvent, Project, Report
from app.services.report_service_persistence import persist_text_report


@pytest.mark.parametrize(
    "end_transaction",
    ["rollback", "close", "savepoint_rollback", "savepoint_commit_outer_rollback"],
)
def test_report_retention_rollback_preserves_published_files_and_discards_new_artifacts(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    end_transaction: str,
) -> None:
    env = file_backed_workbench_api_env
    graph = seed_domain_graph(env.engine, env.app_models, env.repositories)
    settings = replace(
        env.client.app.state.workbench_settings,
        REPORT_DIR=str(tmp_path / "reports"),
        MAX_REPORTS_PER_RUN=1,
    )

    def create(session: Session, content: str) -> Report:
        run = session.get(AnalysisRun, graph.run_id)
        project = session.get(Project, graph.project_id)
        assert run is not None and project is not None
        return persist_text_report(
            session,
            settings,
            run=run,
            project=project,
            generated_at=datetime.now(UTC),
            finding_count=1,
            provider_snapshot_id=None,
            content=content,
            kind="technical-markdown",
            report_format="markdown",
            filename="report.md",
            content_type="text/markdown",
        )

    with Session(env.engine) as session:
        old_report = create(session, "Published report")
        old_id, old_path = old_report.id, Path(old_report.path)
        session.commit()
    assert old_path.read_text() == "Published report"

    with Session(env.engine) as session:
        # Establish SQLite's real outer transaction before opening a savepoint.
        session.connection().execute(
            update(Project)
            .where(col(Project.id) == graph.project_id)
            .values(name=col(Project.name))
        )
        savepoint = session.begin_nested() if end_transaction.startswith("savepoint") else None
        new_report = create(session, "Unpublished report")
        new_path = Path(new_report.path)
        assert session.get(Report, old_id) is None
        assert old_path.read_text() == "Published report"
        assert new_path.read_text() == "Unpublished report"
        if end_transaction == "savepoint_rollback":
            assert savepoint is not None
            savepoint.rollback()
            session.commit()
        elif end_transaction == "savepoint_commit_outer_rollback":
            assert savepoint is not None
            savepoint.commit()
            assert old_path.exists()
            session.rollback()
        elif end_transaction == "rollback":
            session.rollback()
        else:
            session.close()

    assert old_path.read_text() == "Published report"
    assert not new_path.exists()
    with Session(env.engine) as observer:
        reports = observer.exec(select(Report).where(Report.analysis_run_id == graph.run_id)).all()
        assert [item.id for item in reports] == [old_id]
        assert not observer.exec(
            select(AuditEvent).where(AuditEvent.action == "report.retention.delete")
        ).all()
