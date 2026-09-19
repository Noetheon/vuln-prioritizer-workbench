"""Durable import options shared by every upload and replay entrypoint."""

from __future__ import annotations

import uuid

from app.services.import_execution_types import ProjectImportUploadRequest


def import_queue_payload(
    upload: ProjectImportUploadRequest, *, run_id: uuid.UUID
) -> dict[str, object]:
    """Persist scanner, source-time, and provider options for worker retries."""
    return {
        "run_id": str(run_id),
        "input_type": upload.input_type,
        "provider_snapshot_file": upload.provider_snapshot_file,
        "locked_provider_data": upload.locked_provider_data,
        "attack_source": upload.attack_source,
        "attack_mapping_file": upload.attack_mapping_file,
        "attack_technique_metadata_file": upload.attack_technique_metadata_file,
        "sbom_scanner": upload.sbom_scanner,
        "sbom_target_ref": upload.sbom_target_ref,
        "sbom_db_update": upload.sbom_db_update,
        "sbom_source_run_id": upload.sbom_source_run_id,
        "sbom_observed_at": upload.sbom_observed_at,
    }
