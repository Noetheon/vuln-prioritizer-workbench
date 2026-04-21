"""Optional local SQLite state store for imported snapshot artifacts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vuln_prioritizer.utils import iso_utc_now

STATE_SCHEMA_VERSION = "1"


class SQLiteStateStore:
    """Small optional SQLite store for snapshot history and governance views."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def initialize(self) -> None:
        """Create the SQLite schema if it does not exist yet."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS state_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_sha256 TEXT NOT NULL UNIQUE,
                    imported_at TEXT NOT NULL,
                    snapshot_generated_at TEXT NOT NULL,
                    snapshot_path TEXT NOT NULL,
                    input_path TEXT,
                    input_format TEXT NOT NULL,
                    findings_count INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS snapshot_findings (
                    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                    cve_id TEXT NOT NULL,
                    priority_label TEXT NOT NULL,
                    priority_rank INTEGER NOT NULL,
                    in_kev INTEGER NOT NULL,
                    attack_mapped INTEGER NOT NULL,
                    attack_relevance TEXT NOT NULL,
                    waived INTEGER NOT NULL,
                    waiver_status TEXT,
                    waiver_owner TEXT,
                    waiver_expires_on TEXT,
                    waiver_review_on TEXT,
                    waiver_days_remaining INTEGER,
                    services_json TEXT NOT NULL,
                    asset_ids_json TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    PRIMARY KEY (snapshot_id, cve_id)
                );

                CREATE INDEX IF NOT EXISTS idx_snapshot_findings_cve
                    ON snapshot_findings(cve_id);
                CREATE INDEX IF NOT EXISTS idx_snapshot_findings_waiver_status
                    ON snapshot_findings(waiver_status);
                CREATE INDEX IF NOT EXISTS idx_snapshots_generated_at
                    ON snapshots(snapshot_generated_at);
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO state_meta(key, value) VALUES (?, ?)",
                ("schema_version", STATE_SCHEMA_VERSION),
            )
            connection.execute(
                "INSERT OR IGNORE INTO state_meta(key, value) VALUES (?, ?)",
                ("created_at", iso_utc_now()),
            )

    def import_snapshot(self, *, snapshot_path: Path, payload: dict[str, Any]) -> dict[str, Any]:
        """Import a validated snapshot JSON document into the local SQLite store."""
        self.initialize()
        raw_bytes = snapshot_path.read_bytes()
        snapshot_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        metadata = payload["metadata"]
        findings = payload["findings"]
        imported_at = iso_utc_now()
        snapshot_generated_at = self._normalize_timestamp(metadata.get("generated_at"))

        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT id, snapshot_generated_at, findings_count
                FROM snapshots
                WHERE snapshot_sha256 = ?
                """,
                (snapshot_sha256,),
            ).fetchone()
            if existing is not None:
                return {
                    "imported": False,
                    "snapshot_id": int(existing["id"]),
                    "snapshot_generated_at": str(existing["snapshot_generated_at"]),
                    "finding_count": int(existing["findings_count"]),
                }

            cursor = connection.execute(
                """
                INSERT INTO snapshots(
                    snapshot_sha256,
                    imported_at,
                    snapshot_generated_at,
                    snapshot_path,
                    input_path,
                    input_format,
                    findings_count,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_sha256,
                    imported_at,
                    snapshot_generated_at,
                    str(snapshot_path),
                    self._string_or_none(metadata.get("input_path")),
                    str(metadata.get("input_format")),
                    len(findings),
                    json.dumps(metadata, sort_keys=True),
                ),
            )
            if cursor.lastrowid is None:
                raise sqlite3.IntegrityError("SQLite did not return a snapshot id.")
            snapshot_id = int(cursor.lastrowid)

            for finding in findings:
                services = self._finding_services(finding)
                asset_ids = finding.get("provenance", {}).get("asset_ids", [])
                connection.execute(
                    """
                    INSERT INTO snapshot_findings(
                        snapshot_id,
                        cve_id,
                        priority_label,
                        priority_rank,
                        in_kev,
                        attack_mapped,
                        attack_relevance,
                        waived,
                        waiver_status,
                        waiver_owner,
                        waiver_expires_on,
                        waiver_review_on,
                        waiver_days_remaining,
                        services_json,
                        asset_ids_json,
                        finding_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        str(finding.get("cve_id")),
                        str(finding.get("priority_label")),
                        int(finding.get("priority_rank", 99)),
                        1 if finding.get("in_kev") else 0,
                        1 if finding.get("attack_mapped") else 0,
                        str(finding.get("attack_relevance", "Unmapped")),
                        1 if finding.get("waived") else 0,
                        self._string_or_none(finding.get("waiver_status")),
                        self._string_or_none(finding.get("waiver_owner")),
                        self._string_or_none(finding.get("waiver_expires_on")),
                        self._string_or_none(finding.get("waiver_review_on")),
                        self._int_or_none(finding.get("waiver_days_remaining")),
                        json.dumps(services, sort_keys=True),
                        json.dumps(asset_ids, sort_keys=True),
                        json.dumps(finding, sort_keys=True),
                    ),
                )

        return {
            "imported": True,
            "snapshot_id": snapshot_id,
            "snapshot_generated_at": snapshot_generated_at,
            "finding_count": len(findings),
        }

    def cve_history(self, *, cve_id: str) -> list[dict[str, Any]]:
        """Return the imported snapshot history for one CVE."""
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    s.snapshot_generated_at,
                    s.snapshot_path,
                    s.input_path,
                    f.priority_label,
                    f.priority_rank,
                    f.in_kev,
                    f.waived,
                    f.waiver_status,
                    f.waiver_owner,
                    f.services_json,
                    f.asset_ids_json
                FROM snapshot_findings AS f
                JOIN snapshots AS s ON s.id = f.snapshot_id
                WHERE f.cve_id = ?
                ORDER BY s.snapshot_generated_at DESC, s.id DESC
                """,
                (cve_id,),
            ).fetchall()

        return [
            {
                "snapshot_generated_at": str(row["snapshot_generated_at"]),
                "snapshot_path": str(row["snapshot_path"]),
                "input_path": row["input_path"],
                "priority_label": str(row["priority_label"]),
                "priority_rank": int(row["priority_rank"]),
                "in_kev": bool(row["in_kev"]),
                "waived": bool(row["waived"]),
                "waiver_status": row["waiver_status"],
                "waiver_owner": row["waiver_owner"],
                "services": json.loads(str(row["services_json"])),
                "asset_ids": json.loads(str(row["asset_ids_json"])),
            }
            for row in rows
        ]

    def waiver_entries(
        self,
        *,
        status_filter: str,
        latest_only: bool,
    ) -> list[dict[str, Any]]:
        """Return waiver entries from the latest generated snapshot or full imported history."""
        self.initialize()
        with self._connect() as connection:
            latest_snapshot_id: int | None = None
            if latest_only:
                latest = connection.execute(
                    """
                    SELECT id
                    FROM snapshots
                    ORDER BY snapshot_generated_at DESC, id DESC
                    LIMIT 1
                    """
                ).fetchone()
                latest_snapshot_id = None if latest is None else int(latest["id"])
                if latest_snapshot_id is None:
                    return []

            query = """
                SELECT
                    s.snapshot_generated_at,
                    s.snapshot_path,
                    f.cve_id,
                    f.priority_label,
                    f.waiver_status,
                    f.waiver_owner,
                    f.waiver_expires_on,
                    f.waiver_review_on,
                    f.waiver_days_remaining
                FROM snapshot_findings AS f
                JOIN snapshots AS s ON s.id = f.snapshot_id
                WHERE (f.waived = 1 OR f.waiver_status IS NOT NULL)
            """
            params: list[Any] = []
            if latest_snapshot_id is not None:
                query += " AND s.id = ?"
                params.append(latest_snapshot_id)

            if status_filter != "all":
                if status_filter == "active":
                    query += " AND COALESCE(f.waiver_status, 'active') = 'active'"
                else:
                    query += " AND f.waiver_status = ?"
                    params.append(status_filter)

            query += " ORDER BY s.snapshot_generated_at DESC, f.priority_rank ASC, f.cve_id ASC"
            rows = connection.execute(query, tuple(params)).fetchall()

        return [
            {
                "snapshot_generated_at": str(row["snapshot_generated_at"]),
                "snapshot_path": str(row["snapshot_path"]),
                "cve_id": str(row["cve_id"]),
                "priority_label": str(row["priority_label"]),
                "waiver_status": str(row["waiver_status"] or "active"),
                "waiver_owner": row["waiver_owner"],
                "waiver_expires_on": row["waiver_expires_on"],
                "waiver_review_on": row["waiver_review_on"],
                "waiver_days_remaining": row["waiver_days_remaining"],
            }
            for row in rows
        ]

    def top_services(
        self,
        *,
        days: int,
        priority_filter: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Return repeated service counts from recent imported snapshots."""
        self.initialize()
        cutoff = (datetime.now(UTC) - timedelta(days=days)).replace(microsecond=0).isoformat()
        with self._connect() as connection:
            if priority_filter == "all":
                rows = connection.execute(
                    """
                    SELECT
                        s.id AS snapshot_id,
                        s.snapshot_generated_at,
                        f.cve_id,
                        f.in_kev,
                        f.services_json
                    FROM snapshot_findings AS f
                    JOIN snapshots AS s ON s.id = f.snapshot_id
                    WHERE s.snapshot_generated_at >= ?
                    ORDER BY s.snapshot_generated_at DESC, f.priority_rank ASC
                    """,
                    (cutoff,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT
                        s.id AS snapshot_id,
                        s.snapshot_generated_at,
                        f.cve_id,
                        f.in_kev,
                        f.services_json
                    FROM snapshot_findings AS f
                    JOIN snapshots AS s ON s.id = f.snapshot_id
                    WHERE s.snapshot_generated_at >= ? AND f.priority_label = ?
                    ORDER BY s.snapshot_generated_at DESC, f.priority_rank ASC
                    """,
                    (cutoff, priority_filter.title()),
                ).fetchall()

        by_service: dict[str, dict[str, Any]] = {}
        for row in rows:
            services = json.loads(str(row["services_json"]))
            service_names = services if services else ["Unmapped"]
            for service in service_names:
                entry = by_service.setdefault(
                    service,
                    {
                        "service": service,
                        "occurrence_count": 0,
                        "distinct_cves": set(),
                        "snapshot_ids": set(),
                        "kev_count": 0,
                        "latest_seen": None,
                    },
                )
                entry["occurrence_count"] += 1
                entry["distinct_cves"].add(str(row["cve_id"]))
                entry["snapshot_ids"].add(int(row["snapshot_id"]))
                if bool(row["in_kev"]):
                    entry["kev_count"] += 1
                latest_seen = str(row["snapshot_generated_at"])
                if entry["latest_seen"] is None or latest_seen > entry["latest_seen"]:
                    entry["latest_seen"] = latest_seen

        ordered = sorted(
            by_service.values(),
            key=lambda item: (
                -int(item["occurrence_count"]),
                -len(item["distinct_cves"]),
                -int(item["kev_count"]),
                str(item["service"]),
            ),
        )
        return [
            {
                "service": entry["service"],
                "occurrence_count": int(entry["occurrence_count"]),
                "distinct_cves": len(entry["distinct_cves"]),
                "snapshot_count": len(entry["snapshot_ids"]),
                "kev_count": int(entry["kev_count"]),
                "latest_seen": entry["latest_seen"],
            }
            for entry in ordered[:limit]
        ]

    def snapshot_count(self) -> int:
        """Return the number of imported snapshots."""
        self.initialize()
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM snapshots").fetchone()
        return 0 if row is None else int(row["count"])

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _finding_services(finding: dict[str, Any]) -> list[str]:
        services = sorted(
            {
                occurrence.get("asset_business_service")
                for occurrence in finding.get("provenance", {}).get("occurrences", [])
                if occurrence.get("asset_business_service")
            }
        )
        return services

    @staticmethod
    def _int_or_none(value: Any) -> int | None:
        if value is None:
            return None
        return int(value)

    @staticmethod
    def _string_or_none(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _normalize_timestamp(value: Any) -> str:
        if value is None:
            return iso_utc_now()
        text = str(value).strip()
        if not text:
            return iso_utc_now()
        normalized = text.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).astimezone(UTC).replace(microsecond=0).isoformat()
