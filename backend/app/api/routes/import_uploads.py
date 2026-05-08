"""Upload normalization helpers for the Workbench import route."""

from __future__ import annotations

from fastapi import UploadFile

from app.core.config import Settings
from app.services.import_execution import ImportUploadContent, ProjectImportUploadRequest
from app.services.import_uploads import has_optional_upload, read_bounded_upload


async def build_project_import_upload_request(
    *,
    settings: Settings,
    input_type: str,
    file: UploadFile,
    asset_context_file: UploadFile | None,
    vex_file: UploadFile | None,
    provider_snapshot_file: str | None,
    locked_provider_data: bool,
    attack_source: str,
    attack_mapping_file: str | None,
    attack_technique_metadata_file: str | None,
) -> ProjectImportUploadRequest:
    primary_content = await read_bounded_upload(file, settings=settings)
    remaining_bytes = settings.max_upload_bytes - len(primary_content)
    asset_context_content = await _read_optional_upload(
        asset_context_file,
        settings=settings,
        remaining_bytes=remaining_bytes,
    )
    if asset_context_content is not None:
        remaining_bytes -= len(asset_context_content.content)
    vex_content = await _read_optional_upload(
        vex_file,
        settings=settings,
        remaining_bytes=remaining_bytes,
    )
    return ProjectImportUploadRequest(
        input_type=input_type,
        file=ImportUploadContent(
            filename=file.filename,
            content_type=file.content_type,
            content=primary_content,
        ),
        asset_context_file=asset_context_content,
        vex_file=vex_content,
        provider_snapshot_file=provider_snapshot_file,
        locked_provider_data=locked_provider_data,
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )


async def _read_optional_upload(
    upload: UploadFile | None,
    *,
    settings: Settings,
    remaining_bytes: int,
) -> ImportUploadContent | None:
    if upload is None or not has_optional_upload(upload.filename):
        return None
    content = await read_bounded_upload(upload, settings=settings, max_bytes=remaining_bytes)
    return ImportUploadContent(
        filename=upload.filename,
        content_type=upload.content_type,
        content=content,
    )
