import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "@/api-client"
import {
  runAssetContextUpload,
  runCount,
  runInputUpload,
  runLockedProviderData,
  runProviderSnapshotFile,
  runProviderSnapshotHash,
  runResultRecord,
  runResultString,
  runVexUpload,
  stringValue,
} from "./imports-workbench-model.ts"

export function importRunTimelineItems(
  run: AnalysisRunPublic | null,
  summary: AnalysisRunSummaryPublic | null,
) {
  if (!summary) return []

  const inputUpload = runInputUpload(summary)
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
    runCount(summary, "created_findings") + runCount(run, "created_findings") +
      runCount(summary, "updated_findings") + runCount(run, "updated_findings") >
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
      runProviderSnapshotFile(summary) ||
      runProviderSnapshotHash(summary) ||
      runProviderSnapshotFile(run) ||
      runProviderSnapshotHash(run) ||
      stringValue(inputUpload.provider_snapshot_file) ||
      typeof runLockedProviderData(summary) === "boolean" ||
      typeof runLockedProviderData(run ?? undefined) === "boolean" ||
      typeof inputUpload.locked_provider_data === "boolean",
  )
}

function hasOptionalContextEvidence(
  summary: AnalysisRunSummaryPublic,
  inputUpload: Record<string, unknown>,
) {
  const assetContextUpload = runAssetContextUpload(summary)
  const vexUpload = runVexUpload(summary)
  const assetContext = runResultRecord(summary, "asset_context")
  const vex = runResultRecord(summary, "vex")
  const attackSource = runResultString(summary, "attack_source") ?? stringValue(inputUpload.attack_source)
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
    Boolean(runResultString(summary, "attack_mapping_file")) ||
    runCount(summary, "attack_mapped_cves") > 0 ||
    runCount(summary, "suppressed_by_vex") > 0 ||
    Boolean(attackSource && attackSource !== "none")
  )
}

function hasStringRecordValue(record: Record<string, unknown>, keys: string[]) {
  return keys.some((key) => Boolean(stringValue(record[key])))
}
