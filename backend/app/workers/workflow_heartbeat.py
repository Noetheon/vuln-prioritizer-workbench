"""Independent, attempt-fenced lease renewal while a handler computes."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session

from app.repositories.runtime import RuntimeHeartbeatRepository
from app.repositories.workflows import WorkflowLeaseLostError, WorkflowRepository

WORKFLOW_WORKER_SERVICE_NAME = "workflow-worker"


@contextmanager
def maintain_workflow_lease(
    *,
    engine: Engine,
    workflow_id: uuid.UUID,
    worker_id: str,
    attempt_count: int,
    lease_seconds: int,
) -> Iterator[None]:
    """Keep slow computation leased without extending its domain transaction."""
    stop = threading.Event()

    def renew() -> None:
        interval = max(0.1, min(30.0, lease_seconds / 3))
        while not stop.wait(interval):
            with Session(engine) as session:
                try:
                    WorkflowRepository(session).record_worker_heartbeat(
                        workflow_id,
                        worker_id=worker_id,
                        attempt_count=attempt_count,
                        lease_seconds=lease_seconds,
                    )
                    RuntimeHeartbeatRepository(session).record_heartbeat(
                        service_name=WORKFLOW_WORKER_SERVICE_NAME,
                        instance_id=worker_id,
                    )
                    session.commit()
                except WorkflowLeaseLostError:
                    return
                except SQLAlchemyError:
                    # A short final publication can hold SQLite's writer lock.
                    # A subsequent renewal is still fenced by the lease expiry.
                    session.rollback()

    thread = threading.Thread(target=renew, name="vpw-workflow-lease", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=31.0)
