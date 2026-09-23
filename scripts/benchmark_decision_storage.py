"""Reproduce decision-storage workload on disposable SQLite, with offline providers."""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import logging
import os
import platform
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--rows", type=int, default=1000)
parser.add_argument("--output", type=Path, default=ROOT / "build/decision-storage")
arguments = parser.parse_args()
if arguments.rows < 100:
    parser.error("--rows must be at least 100")
OUT = arguments.output.resolve()
OUT.mkdir(parents=True, exist_ok=True)
ROWS = arguments.rows
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "backend/tests")]


def main():
    """Execute the fixed workload and retain measurements and input identities."""
    with tempfile.TemporaryDirectory(prefix="vpw-decision-storage-") as directory:
        temporary = Path(directory)
        for key, value in {
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{temporary / 'global.db'}",
            "IMPORT_UPLOAD_DIR": str(temporary / "imports"),
            "REPORT_DIR": str(temporary / "reports"),
            "PROVIDER_CACHE_DIR": str(temporary / "cache"),
            "PROVIDER_SNAPSHOT_DIR": str(temporary / "snapshots"),
            "ATTACK_ARTIFACT_DIR": str(temporary / "attack"),
        }.items():
            os.environ[key] = value
        import requests

        def block_network(*args, **kwargs):
            raise RuntimeError("Benchmark forbids provider network access")

        requests.sessions.Session.request = block_network
        from app.decision_core.evaluation import ScopeEvaluationInput, evaluate_scope
        from app.domain.engine.services.decision_guidance import DecisionGuidanceService
        from app.domain.engine.services.prioritization_ranking import global_operational_sort_key
        from app.repositories.assets import AssetRepository
        from app.repositories.evidence_payloads import EvidencePayloadStore
        from sqlalchemy import event
        from sqlmodel import Session
        from utils.import_contracts import drain_workflow_queue
        from utils.workbench_env import (
            create_project_via_api,
            create_workbench_api_env,
            local_api_headers,
        )

        logging.getLogger("httpx").setLevel(logging.WARNING)
        (temporary / "snapshots").mkdir()
        shutil.copyfile(
            ROOT / "data/demo_provider_snapshot.json",
            temporary / "snapshots/demo_provider_snapshot.json",
        )
        env, cleanup = create_workbench_api_env(database_path=temporary / "workbench.db")
        counters = Counter()
        original_history = AssetRepository._iter_asset_occurrence_evidence

        def history(self, asset_id):
            counters["asset_history_calls"] += 1
            for value in original_history(self, asset_id):
                counters["asset_history_rows"] += 1
                yield value

        AssetRepository._iter_asset_occurrence_evidence = history

        def statement(conn, cursor, sql, params, context, many):
            kind = sql.lstrip().split(None, 1)[0].upper()
            counters[kind] += 1
            if kind == "UPDATE" and "finding_current_projection" in sql:
                field = (
                    "projection_overlay_updates"
                    if "lifecycle_overlay_json=" in sql.replace(" ", "")
                    else "projection_compact_updates"
                )
                counters[field] += len(params) if many else 1

        event.listen(env.engine, "before_cursor_execute", statement)
        result = {
            "head": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "tracked_diff_sha256": hashlib.sha256(
                subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)
            ).hexdigest(),
            "snapshot_sha256": hashlib.sha256(
                (ROOT / "data/demo_provider_snapshot.json").read_bytes()
            ).hexdigest(),
            "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "rows": ROWS,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "method": (
                "FastAPI TestClient + actual workflow worker, disposable SQLite WAL, "
                "Locked snapshot, no provider network. Single run per step; not an SLO."
            ),
            "steps": [],
        }

        def save():
            (OUT / f"results-{ROWS}.json").write_text(
                json.dumps(result, indent=2, ensure_ascii=False) + "\n"
            )

        def db_state():
            with env.engine.connect() as conn:
                out = {
                    "allocated_bytes": conn.exec_driver_sql("PRAGMA page_count").scalar()
                    * conn.exec_driver_sql("PRAGMA page_size").scalar(),
                    "free_pages": conn.exec_driver_sql("PRAGMA freelist_count").scalar(),
                }
                for table, field in [
                    ("finding_decision_evidence", "payload_json"),
                    ("finding_current_projection", "lifecycle_overlay_json"),
                    ("finding_occurrence", "evidence_json"),
                ]:
                    count, size, average = conn.exec_driver_sql(
                        f"SELECT count(*), coalesce(sum(length(cast({field} as blob))),0), "
                        f"avg(length(cast({field} as blob))) FROM {table}"
                    ).one()
                    out[table] = {"count": count, "json_bytes": size, "average_json_bytes": average}
                count, size = conn.exec_driver_sql(
                    "SELECT count(*), coalesce(sum(length(payload_zlib)),0) FROM evidence_section"
                ).one()
                out["evidence_section"] = {"count": count, "compressed_bytes": size}
                return out

        def measured(name, fn):
            gc.collect()
            counters.clear()
            before_cpu = resource.getrusage(resource.RUSAGE_SELF)
            load_before = os.getloadavg()
            start = time.perf_counter()
            value = fn()
            elapsed = time.perf_counter() - start
            after_cpu = resource.getrusage(resource.RUSAGE_SELF)
            counts = dict(counters)
            entry = {
                "name": name,
                "seconds": round(elapsed, 4),
                "process_cpu_seconds": round(
                    after_cpu.ru_utime
                    + after_cpu.ru_stime
                    - before_cpu.ru_utime
                    - before_cpu.ru_stime,
                    4,
                ),
                "system_load_average_before": load_before,
                "sql_and_history_counts": counts,
                "db": db_state(),
                "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                / (1024**2 if sys.platform == "darwin" else 1024),
            }
            if isinstance(value, dict):
                entry["result"] = value
            result["steps"].append(entry)
            save()
            print(
                json.dumps(
                    {
                        "name": name,
                        "seconds": entry["seconds"],
                        "db_mib": round(entry["db"]["allocated_bytes"] / 1024**2, 2),
                        "result": value if isinstance(value, dict) else None,
                    }
                ),
                flush=True,
            )
            return value

        try:
            env.client.app.state.workbench_settings = replace(
                env.client.app.state.workbench_settings, DEMO_PROVIDER_SNAPSHOT_ENABLED=True
            )
            headers = local_api_headers(env.client)
            project = create_project_via_api(env.client, headers)
            prefix = f"/api/v1/projects/{project['id']}"
            csv_header = (
                "cve_id,target_ref,raw_severity,owner,business_service,"
                "exposure,environment,criticality"
            )
            cves = ("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-44487", "CVE-2024-3094")
            lines = [csv_header] + [
                ",".join(
                    [
                        cves[i % 4],
                        f"review-workload-{i:05d}",
                        "critical" if i % 2 == 0 else "high",
                        f"team-{i % 20:02d}",
                        f"service-{i % 50:02d}",
                        "internet-facing" if i % 3 == 0 else "internal",
                        "production",
                        "critical" if i % 5 == 0 else "high",
                    ]
                )
                for i in range(ROWS)
            ]
            content = ("\n".join(lines) + "\n").encode()
            result["input_sha256"] = hashlib.sha256(content).hexdigest()

            def upload(data):
                response = env.client.post(
                    prefix + "/imports",
                    headers=headers,
                    data={
                        "input_type": "generic-occurrence-csv",
                        "provider_snapshot_file": "demo_provider_snapshot.json",
                        "locked_provider_data": "true",
                    },
                    files={"file": ("review.csv", data, "text/csv")},
                )
                assert response.status_code == 200, response.text
                run_id = response.json()["id"]
                drain_workflow_queue(env, max_ticks=5)
                detail = env.client.get(f"/api/v1/runs/{run_id}", headers=headers)
                assert detail.status_code == 200, detail.text
                payload = detail.json()
                assert payload["status"] == "succeeded", payload
                return {
                    "run_id": run_id,
                    "status": payload["status"],
                    "counts": payload.get("counts"),
                }

            first = measured("initial_import", lambda: upload(content))
            measured("same_import_2", lambda: upload(content))
            measured("same_import_3", lambda: upload(content))
            sections = [step["db"]["evidence_section"] for step in result["steps"][:3]]
            assert sections[0] == sections[1] == sections[2], sections
            with env.engine.connect() as conn:
                sample_id = conn.exec_driver_sql(
                    "SELECT finding_id FROM finding_current_projection ORDER BY "
                    "operational_rank LIMIT 1"
                ).scalar()
                payloads = [
                    json.loads(row[0])
                    for row in conn.exec_driver_sql(
                        (
                            "SELECT payload_json FROM finding_decision_evidence WHERE "
                            "finding_id = ? ORDER BY created_at"
                        ),
                        (sample_id,),
                    )
                ]
                payloads = EvidencePayloadStore(conn).load_documents(
                    [(uuid.UUID(project["id"]), payload) for payload in payloads]
                )
                sizes = {k: len(json.dumps(v).encode()) for k, v in payloads[0].items()}

            def flatten(value, prefix=""):
                if isinstance(value, dict):
                    return {
                        k2: v2
                        for k, v in value.items()
                        for k2, v2 in flatten(v, prefix + "." + k).items()
                    }
                if isinstance(value, list):
                    return {
                        k2: v2
                        for i, v in enumerate(value)
                        for k2, v2 in flatten(v, prefix + f"[{i}]").items()
                    }
                return {prefix: value}

            left, right = flatten(payloads[0]), flatten(payloads[1])
            result["evidence_sample"] = {
                "leaf_fields": len(left),
                "changed_leaf_paths": [
                    k for k in left.keys() | right.keys() if left.get(k) != right.get(k)
                ],
                "top_level_bytes": dict(sorted(sizes.items(), key=lambda p: -p[1])),
            }

            def get_payload(suffix, params=None):
                response = env.client.get(prefix + suffix, headers=headers, params=params)
                assert response.status_code == 200, response.text
                payload = response.json()
                return {
                    "status": response.status_code,
                    "response_bytes": len(response.content),
                    "count": payload.get("count"),
                    "evidence_bytes": sum(
                        len(json.dumps(row.get("evidence")).encode())
                        for row in payload.get("data", [])
                    ),
                }

            measured("findings_page_100", lambda: get_payload("/findings/", {"limit": 100}))
            measured("dashboard", lambda: get_payload("/dashboard"))
            measured("dashboard_repeat", lambda: get_payload("/dashboard"))

            def compact_counts():
                with env.engine.connect() as conn:
                    rows = conn.exec_driver_sql(
                        "SELECT priority,status,count(*),sum(risk_score),avg(risk_score) "
                        "FROM finding_current_projection GROUP BY priority,status"
                    ).all()
                    return {
                        "aggregate_rows": len(rows),
                        "finding_count": sum(row[2] for row in rows),
                        "scope": "partial aggregate experiment only",
                    }

            measured("compact_sql_aggregate_experiment", compact_counts)
            start = time.perf_counter()
            with env.engine.connect() as conn:
                storage_rows = (
                    conn.exec_driver_sql(
                        "SELECT e.payload_json FROM finding_current_projection p JOIN "
                        "finding_decision_evidence e ON e.id=p.source_finding_evidence_id"
                    )
                    .scalars()
                    .all()
                )
                hydrated = EvidencePayloadStore(conn).load_documents(
                    [(uuid.UUID(project["id"]), json.loads(value)) for value in storage_rows]
                )
                encoded_inputs = [json.dumps(item["evaluation_input"]) for item in hydrated]
                del storage_rows, hydrated
            fetch = time.perf_counter() - start
            start = time.perf_counter()
            inputs = [ScopeEvaluationInput.model_validate_json(value) for value in encoded_inputs]
            parse = time.perf_counter() - start
            start = time.perf_counter()
            decisions = [evaluate_scope(item) for item in inputs]
            evaluated = time.perf_counter() - start
            start = time.perf_counter()
            ranked = sorted(
                zip(inputs, decisions),
                key=lambda pair: global_operational_sort_key(
                    pair[1], (pair[0].cve_id, pair[0].observations[0].target_ref or "")
                ),
            )
            guidance = DecisionGuidanceService()
            for rank, (_, decision) in enumerate(ranked, 1):
                guidance.build(decision.model_copy(update={"operational_rank": rank}))
            result["pure_evaluator_experiment"] = {
                "count": len(inputs),
                "fetch_embedded_inputs_seconds": fetch,
                "parse_inputs_seconds": parse,
                "evaluate_seconds": evaluated,
                "global_sort_and_guidance_seconds": time.perf_counter() - start,
                "scope": (
                    "already validated inputs; operational key plus CVE/target tie-break; "
                    "no API payload or cache publication"
                ),
            }
            del inputs, decisions, ranked, encoded_inputs
            save()
            with env.engine.connect() as conn:
                previous = {
                    row[0]: row[1:]
                    for row in conn.exec_driver_sql(
                        "SELECT "
                        "finding_id,revision,lifecycle_overlay_json,source_finding_evidence_id "
                        "FROM finding_current_projection"
                    ).all()
                }
            extra = (
                csv_header
                + (
                    "\nCVE-2021-44228,000-added,critical,team-00,service-00,"
                    "internet-facing,production,critical\n"
                )
            ).encode()
            measured("one_additional_finding", lambda: upload(extra))
            with env.engine.connect() as conn:
                current = {
                    row[0]: row[1:]
                    for row in conn.exec_driver_sql(
                        "SELECT "
                        "finding_id,revision,lifecycle_overlay_json,source_finding_evidence_id "
                        "FROM finding_current_projection"
                    ).all()
                }
            result["additional_finding_changed_existing_ranks"] = sum(
                current[k][0] != v[0] for k, v in previous.items()
            )
            assert all(current[k][1:] == value[1:] for k, value in previous.items()), (
                "Peer evidence changed when adding a scope"
            )

            def waiver():
                response = env.client.post(
                    prefix + "/waivers/",
                    headers=headers,
                    json={
                        "finding_id": str(uuid.UUID(sample_id)),
                        "owner": "review",
                        "reason": "Isolated benchmark waiver for exactly one finding",
                        "expires_at": "2099-12-31",
                        "approval_ref": "REVIEW",
                    },
                )
                assert response.status_code == 200, response.text
                return {
                    "matched_findings": response.json()["matched_findings"],
                    "status": response.json()["status"],
                }

            before = db_state()["finding_decision_evidence"]["count"]
            measured("waiver_exactly_one_finding", waiver)
            result["one_finding_waiver_new_evidence_rows"] = (
                db_state()["finding_decision_evidence"]["count"] - before
            )
            assert result["one_finding_waiver_new_evidence_rows"] == 1
            measured("same_import_with_waiver", lambda: upload(content))

            def stale_day():
                with env.engine.begin() as conn:
                    conn.exec_driver_sql("UPDATE project SET waiver_evaluated_on='2000-01-01'")

            stale_day()

            def pending_read():
                response = env.client.get(
                    prefix + "/findings/", headers=headers, params={"limit": 1}
                )
                assert response.status_code == 503, response.text
                assert response.json()["detail"]["code"] == "decision_refresh_pending"
                assert not any(counters.get(kind) for kind in ("INSERT", "UPDATE", "DELETE")), (
                    counters
                )
                return {
                    "status": 503,
                    "response_bytes": len(response.content),
                    "decision_writes": 0,
                }

            measured("first_get_after_day_change", pending_read)
            measured("worker_day_maintenance", lambda: drain_workflow_queue(env, max_ticks=2))
            measured("same_day_get", lambda: get_payload("/findings/", {"limit": 1}))

            def report(report_format):
                response = env.client.post(
                    f"/api/v1/runs/{first['run_id']}/report-jobs",
                    headers=headers,
                    json={"format": report_format},
                )
                assert response.status_code == 200, response.text
                workflow_id = response.json()["id"]
                drain_workflow_queue(env, max_ticks=6)
                with Session(env.engine) as session:
                    workflow = session.get(env.app_models.WorkflowRun, uuid.UUID(workflow_id))
                    return {
                        k: getattr(workflow, k, None)
                        for k in (
                            "status",
                            "error_message",
                            "error_code",
                            "attempt_count",
                            "result_json",
                            "result_ref_json",
                        )
                    }

            measured("json_report", lambda: report("json"))
            compressed = measured("json_gzip_report", lambda: report("json-gzip"))
            assert compressed["status"] == "succeeded", compressed
            result["final_state"] = db_state()
            save()
        finally:
            AssetRepository._iter_asset_occurrence_evidence = original_history
            cleanup()


if __name__ == "__main__":
    main()
