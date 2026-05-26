import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "@/api-client"
import { objectRecord, stringValue } from "./imports-workbench-records.ts"

export function importRunTimelineItems(
  run: AnalysisRunPublic | null,
  summary: AnalysisRunSummaryPublic | null,
) {
  if (!summary) return []

  const inputUpload = objectRecord(summary.input_upload ?? run?.input_upload)
  const items: string[] = []

  if (summary.started_at || run?.started_at) {
    items.push("Import started")
  }

  if (
    summary.filename ||
    run?.filename ||
    hasStringRecordValue(inputUpload, [
      "original_filename",
      "stored_filename",
      "filename",
      "storage_ref",
    ])
  ) {
    items.push("File uploaded")
  }

  if (hasParserEvidence(summary)) {
    items.push(
      (summary.parse_errors ?? []).length > 0
        ? "Parser diagnostics recorded"
        : "Data parsed",
    )
  }

  if (hasProviderEvidence(run, summary, inputUpload)) {
    items.push("Provider data applied")
  }

  if (hasOptionalContextEvidence(summary, inputUpload)) {
    items.push("Optional context applied")
  }

  if (
    numberValue(summary.created_findings, run?.created_findings) +
      numberValue(summary.updated_findings, run?.updated_findings) >
    0
  ) {
    items.push("Findings created or updated")
  }

  if (summary.finished_at || run?.finished_at) {
    items.push("Import completed")
  }

  return items
}

function hasParserEvidence(summary: AnalysisRunSummaryPublic) {
  const terminal =
    summary.status === "succeeded" ||
    summary.status === "completed" ||
    summary.status === "completed_with_errors" ||
    summary.status === "failed" ||
    summary.status === "cancelled"
  if (!terminal) return false
  return (
    Array.isArray(summary.parse_errors) ||
    summary.created_findings !== undefined ||
    summary.updated_findings !== undefined ||
    summary.finding_count !== undefined ||
    summary.ignored_lines !== undefined ||
    summary.occurrence_count !== undefined ||
    summary.rows_read !== undefined
  )
}

function hasProviderEvidence(
  run: AnalysisRunPublic | null,
  summary: AnalysisRunSummaryPublic,
  inputUpload: Record<string, unknown>,
) {
  return Boolean(
    summary.provider_snapshot_id ||
      run?.provider_snapshot_id ||
      summary.provider_snapshot_file ||
      summary.provider_snapshot_hash ||
      run?.provider_snapshot_file ||
      run?.provider_snapshot_hash ||
      stringValue(inputUpload.provider_snapshot_file) ||
      typeof summary.locked_provider_data === "boolean" ||
      typeof run?.locked_provider_data === "boolean" ||
      typeof inputUpload.locked_provider_data === "boolean",
  )
}

function hasOptionalContextEvidence(
  summary: AnalysisRunSummaryPublic,
  inputUpload: Record<string, unknown>,
) {
  const assetContextUpload = objectRecord(summary.asset_context_upload)
  const vexUpload = objectRecord(summary.vex_upload)
  const assetContext = objectRecord(summary.asset_context)
  const vex = objectRecord(summary.vex)
  const attackSource = summary.attack_source ?? stringValue(inputUpload.attack_source)
  return (
    hasStringRecordValue(assetContextUpload, [
      "original_filename",
      "stored_filename",
      "path",
    ]) ||
    hasStringRecordValue(vexUpload, [
      "original_filename",
      "stored_filename",
      "path",
    ]) ||
    hasStringRecordValue(inputUpload, [
      "asset_context_filename",
      "asset_context_file",
      "vex_filename",
      "vex_file",
      "attack_mapping_file",
      "attack_technique_metadata_file",
    ]) ||
    Object.keys(assetContext).length > 0 ||
    Object.keys(vex).length > 0 ||
    Boolean(summary.attack_mapping_file) ||
    Number(summary.attack_mapped_cves ?? 0) > 0 ||
    Number(summary.suppressed_by_vex ?? 0) > 0 ||
    Boolean(attackSource && attackSource !== "none")
  )
}

function hasStringRecordValue(record: Record<string, unknown>, keys: string[]) {
  return keys.some((key) => Boolean(stringValue(record[key])))
}

function numberValue(...values: unknown[]) {
  for (const value of values) {
    if (typeof value === "number") return value
  }
  return 0
}
