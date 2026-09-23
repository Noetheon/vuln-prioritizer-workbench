"""Single storage boundary for lossless shared immutable finding evidence."""

from __future__ import annotations

import uuid
import zlib
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection

from app.decision_core.evidence_storage import (
    decode_section,
    join_payload,
    section_references,
    split_payload,
)
from app.models.evidence import EvidenceSection, FindingDecisionEvidence


class EvidencePayloadStore:
    """Batch section I/O without session-global caches or implicit model queries."""

    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self.table = getattr(EvidenceSection, "__table__")

    def store_payloads(
        self, project_id: uuid.UUID, payloads: Iterable[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Persist shared sections in the caller's transaction; return compact documents."""
        documents: list[dict[str, Any]] = []
        sections: dict[str, bytes] = {}
        for payload in payloads:
            document, extracted = split_payload(payload)
            documents.append(document)
            sections.update(extracted)
        digests = list(sections)
        for offset in range(0, len(digests), 500):
            batch = digests[offset : offset + 500]
            existing = set(
                self.connection.execute(
                    sa.select(self.table.c.sha256).where(
                        self.table.c.project_id == project_id, self.table.c.sha256.in_(batch)
                    )
                ).scalars()
            )
            values = [
                {
                    "project_id": project_id,
                    "sha256": digest,
                    "decoded_size": len(sections[digest]),
                    "payload_zlib": zlib.compress(sections[digest]),
                }
                for digest in batch
                if digest not in existing
            ]
            if not values:
                continue
            # Both supported databases can race to insert identical immutable
            # sections. The unique key arbitrates; no existing content is updated.
            insert = (
                postgres_insert if self.connection.dialect.name == "postgresql" else sqlite_insert
            )
            self.connection.execute(
                insert(self.table).on_conflict_do_nothing(index_elements=["project_id", "sha256"]),
                values,
            )
        return documents

    def load(self, record: FindingDecisionEvidence) -> dict[str, Any]:
        """Read one immutable payload, including legacy unencoded contracts."""
        return self.load_documents([(record.project_id, record.payload_json)])[0]

    def load_records(
        self, records: Iterable[FindingDecisionEvidence]
    ) -> dict[uuid.UUID, dict[str, Any]]:
        """Batch shared facts once for all supplied records."""
        rows = list(records)
        payloads = self.load_documents([(row.project_id, row.payload_json) for row in rows])
        return {row.id: payload for row, payload in zip(rows, payloads, strict=True)}

    def load_documents(
        self, documents: list[tuple[uuid.UUID, dict[str, Any]]]
    ) -> list[dict[str, Any]]:
        """Hydrate storage documents; also used by reversible data migrations."""
        needed: dict[uuid.UUID, set[str]] = defaultdict(set)
        for project_id, document in documents:
            needed[project_id].update(ref["sha256"] for ref in section_references(document))
        sections: dict[uuid.UUID, dict[str, Any]] = defaultdict(dict)
        for project_id, digests in needed.items():
            keys = list(digests)
            for offset in range(0, len(keys), 500):
                rows = self.connection.execute(
                    sa.select(self.table).where(
                        self.table.c.project_id == project_id,
                        self.table.c.sha256.in_(keys[offset : offset + 500]),
                    )
                ).mappings()
                for row in rows:
                    sections[project_id][row["sha256"]] = decode_section(
                        row["payload_zlib"], row["decoded_size"], row["sha256"]
                    )
        return [join_payload(document, sections[project_id]) for project_id, document in documents]
