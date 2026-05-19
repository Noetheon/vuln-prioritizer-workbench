import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "@/api-client"
import { objectRecord, stringValue } from "./imports-workbench-records.ts"

export function importRunTimelineItems(
  run: AnalysisRunPublic | null,
  summary: AnalysisRunSummaryPublic | null,
) {
  if (!summary) return []

  const summaryJson = objectRecord(summary.summary_json ?? run?.summary_json)
  const inputUpload = objectRecord(
    summary.input_upload ??
      summaryJson.input_upload ??
      run?.summary_json?.input_upload,
  )
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

  if (hasParserEvidence(summary, summaryJson)) {
    items.push(
      (summary.parse_errors ?? []).length > 0
        ? "Parser diagnostics recorded"
        : "Data parsed",
    )
  }

  if (hasProviderEvidence(run, summary, summaryJson, inputUpload)) {
    items.push("Provider data applied")
  }

  if (hasOptionalContextEvidence(summaryJson, inputUpload)) {
    items.push("Optional context applied")
  }

  if (
    numberValue(summary.created_findings, summaryJson.created_findings) +
      numberValue(summary.updated_findings, summaryJson.updated_findings) >
    0
  ) {
    items.push("Findings created or updated")
  }

  if (summary.finished_at || run?.finished_at) {
    items.push("Import completed")
  }

  return items
}

function hasParserEvidence(
  summary: AnalysisRunSummaryPublic,
  summaryJson: Record<string, unknown>,
) {
  const terminal =
    summary.status === "succeeded" ||
    summary.status === "completed" ||
    summary.status === "completed_with_errors" ||
    summary.status === "failed" ||
    summary.status === "cancelled"
  if (!terminal) return false
  return (
    Array.isArray(summary.parse_errors) ||
    hasNumberRecordValue(summaryJson, [
      "created_findings",
      "updated_findings",
      "finding_count",
      "findings_count",
      "ignored_lines",
      "occurrence_count",
    ]) ||
    summary.created_findings !== undefined ||
    summary.updated_findings !== undefined ||
    summary.finding_count !== undefined ||
    summary.ignored_lines !== undefined ||
    summary.occurrence_count !== undefined
  )
}

function hasProviderEvidence(
  run: AnalysisRunPublic | null,
  summary: AnalysisRunSummaryPublic,
  summaryJson: Record<string, unknown>,
  inputUpload: Record<string, unknown>,
) {
  return Boolean(
    summary.provider_snapshot_id ||
      run?.provider_snapshot_id ||
      stringValue(summaryJson.provider_snapshot_id) ||
      stringValue(summaryJson.provider_snapshot_file) ||
      stringValue(inputUpload.provider_snapshot_file) ||
      typeof summaryJson.locked_provider_data === "boolean" ||
      typeof inputUpload.locked_provider_data === "boolean",
  )
}

function hasOptionalContextEvidence(
  summaryJson: Record<string, unknown>,
  inputUpload: Record<string, unknown>,
) {
  const assetContextUpload = objectRecord(summaryJson.asset_context_upload)
  const vexUpload = objectRecord(summaryJson.vex_upload)
  const attackSource =
    stringValue(summaryJson.attack_source) ??
    stringValue(inputUpload.attack_source)
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
    Boolean(attackSource && attackSource !== "none")
  )
}

function hasStringRecordValue(record: Record<string, unknown>, keys: string[]) {
  return keys.some((key) => Boolean(stringValue(record[key])))
}

function hasNumberRecordValue(record: Record<string, unknown>, keys: string[]) {
  return keys.some((key) => typeof record[key] === "number")
}

function numberValue(...values: unknown[]) {
  for (const value of values) {
    if (typeof value === "number") return value
  }
  return 0
}
