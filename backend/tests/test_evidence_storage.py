"""Lossless storage, corruption rejection and bounded sharing contracts."""

from __future__ import annotations

import hashlib
import json
import uuid
import zlib
from copy import deepcopy

import pytest
from sqlmodel import Session, select
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api

from app.decision_core.evidence_storage import (
    STORAGE_KEY,
    decode_section,
    join_payload,
    section_references,
    split_payload,
)
from app.decision_core.ledger import DecisionLedgerInvariantError, canonical_payload_sha256
from app.models import EvidenceSection
from app.repositories.evidence_payloads import EvidencePayloadStore


def _payload() -> dict:
    facts = {"cve_id": "CVE-2026-1234", "advisory": "Größe 東京 🛡️\u0000" * 1000}
    return {
        "analysis_run_id": "original",
        "evaluation": {"evaluated_at": "2026-09-23"},
        "provider": {"provider_evidence": facts, "hash": "provider snapshot"},
        "priority_evidence": {
            "raw": {"provider_evidence": facts, "explanation": [None, 2**256, 0.12345678912345678]},
        },
        "evaluation_input": {
            "provider_evidence": facts,
            "observations": [{"asset_id": "asset1", "text": "observation" * 300}],
        },
        "remediation": {"raw": {"guidance": "patch " * 1000}},
    }


def test_sections_share_provider_facts_and_preserve_exact_independent_payloads() -> None:
    payload = _payload()
    original = deepcopy(payload)
    document, sections = split_payload(payload)
    refs = section_references(document)
    facts = [ref["sha256"] for ref in refs if ref["path"][-1] == "provider_evidence"]
    assert len(facts) == 3 and len(set(facts)) == 1
    values = {digest: json.loads(encoded) for digest, encoded in sections.items()}
    hydrated = join_payload(document, values)
    assert hydrated == payload == original
    assert canonical_payload_sha256(hydrated) == document[STORAGE_KEY]["sha256"]
    hydrated["provider"]["provider_evidence"]["advisory"] = "reader mutation"
    assert join_payload(document, values) == original
    assert payload == original
    assert len(json.dumps(document).encode()) < 3000


@pytest.mark.parametrize("corruption", ["missing", "section", "root", "overlap", "version", "path"])
def test_storage_corruption_never_produces_a_silently_changed_decision(corruption: str) -> None:
    document, sections = split_payload(_payload())
    values = {digest: json.loads(encoded) for digest, encoded in sections.items()}
    ref = document[STORAGE_KEY]["refs"][0]
    if corruption == "missing":
        del values[ref["sha256"]]
    elif corruption == "section":
        values[ref["sha256"]]["advisory"] = "changed"
    elif corruption == "root":
        document["analysis_run_id"] = "changed"
    elif corruption == "overlap":
        document["evaluation_input"] = {"provider_evidence": {}}
    elif corruption == "version":
        document[STORAGE_KEY]["version"] = "future.v999"
    else:
        ref["path"] = [{"not": "a string"}]
    with pytest.raises(DecisionLedgerInvariantError):
        join_payload(document, values)


@pytest.mark.parametrize("corruption", ["truncated", "trailing", "size", "hash", "invalid"])
def test_compressed_section_length_and_hash_are_verified(corruption: str) -> None:
    encoded = b'{"evidence":"' + b"x" * 2000 + b'"}'
    digest = hashlib.sha256(encoded).hexdigest()
    compressed, size = zlib.compress(encoded), len(encoded)
    if corruption == "truncated":
        compressed = compressed[:-2]
    elif corruption == "trailing":
        compressed += b"unexpected"
    elif corruption == "size":
        size -= 1
    elif corruption == "hash":
        digest = "0" * 64
    else:
        compressed = b"invalid zlib"
    with pytest.raises(DecisionLedgerInvariantError, match="Corrupt immutable"):
        decode_section(compressed, size, digest)


def test_repeated_import_storage_reuses_sections_and_rolls_back_atomically(
    file_backed_workbench_api_env: WorkbenchApiEnv,
) -> None:
    env = file_backed_workbench_api_env
    project = create_project_via_api(env.client, {})
    project_id = uuid.UUID(project["id"])
    first = _payload()
    second = deepcopy(first)
    second["analysis_run_id"] = "next import"
    second["evaluation"]["evaluated_at"] = "2026-09-24"
    with Session(env.engine) as session:
        store = EvidencePayloadStore(session.connection())
        first_document = store.store_payloads(project_id, [first])[0]
        session.commit()
    with Session(env.engine) as session:
        store = EvidencePayloadStore(session.connection())
        original_sections = list(session.exec(select(EvidenceSection)).all())
        second_document = store.store_payloads(project_id, [second])[0]
        sections = list(session.exec(select(EvidenceSection)).all())
        assert {row.sha256 for row in sections} == {row.sha256 for row in original_sections}
        assert store.load_documents(
            [(project_id, first_document), (project_id, second_document)]
        ) == [first, second]
        changed = deepcopy(first)
        changed["remediation"]["raw"]["guidance"] = "changed " * 1000
        store.store_payloads(project_id, [changed])
        assert len(session.exec(select(EvidenceSection)).all()) > len(sections)
        session.rollback()
    with Session(env.engine) as session:
        sections = list(session.exec(select(EvidenceSection)).all())
        assert len(sections) == len(original_sections)
        stored_bytes = sum(len(row.payload_zlib) for row in sections) + sum(
            len(json.dumps(document).encode()) for document in (first_document, second_document)
        )
        assert stored_bytes < (len(json.dumps(first)) + len(json.dumps(second))) / 15
        # A different project cannot resolve these references, even with identical hashes.
        with pytest.raises(DecisionLedgerInvariantError, match="Missing immutable"):
            EvidencePayloadStore(session.connection()).load_documents(
                [(uuid.uuid4(), first_document)]
            )
    deleted = env.client.delete(f"/api/v1/projects/{project_id}")
    assert deleted.status_code == 204, deleted.text
    with Session(env.engine) as session:
        assert session.exec(select(EvidenceSection)).all() == []
