import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ProviderStatusPublic,
  ReportPublic,
  ReportVerificationPublic,
} from "../../api-client"
import type { ArtifactCard } from "../../lib/report-capability-catalog.ts"
import type {
  VpwBadgeTone,
  VpwCompactTone,
  VpwStatusBannerTone,
} from "../vpw"
import { objectRecord } from "../../lib/app-errors.ts"
import {
  formatReportDateTime,
  reportFormatLabel,
  type ReportFormat,
} from "../../lib/report-format.ts"
import { runStatusTone } from "../../lib/risk-format.ts"
import { workflowNeedsPolling, workflowStageLabel } from "../../workbench/workflow-model.ts"

export function reportForFormat(
  reports: readonly ReportPublic[],
  format: ReportFormat,
) {
  return reports.find((report) => report.format === format) ?? null
}

export function evidenceBundleReport(reports: readonly ReportPublic[]) {
  return reportForFormat(reports, "zip")
}

export function newestReport(reports: readonly ReportPublic[]) {
  return (
    reports
      .slice()
      .sort(
        (left, right) =>
          new Date(right.created_at).getTime() -
          new Date(left.created_at).getTime(),
      )[0] ?? null
  )
}

export function generatedArtifactsDetail(reports: readonly ReportPublic[]) {
  const latest = newestReport(reports)
  if (!latest) return "Generate the first artifact for this run"
  if (workflowNeedsPolling(latest.workflow)) {
    return `Latest workflow ${workflowStageLabel(latest.workflow)}`
  }
  return `Latest generated ${formatReportDateTime(latest.created_at)}`
}

export function generatedActionLabel(
  card: ArtifactCard | null,
  existingReport: ReportPublic | null,
) {
  if (existingReport) {
    return card?.reportFormat === "zip" ? "Rebuild evidence ZIP" : "Regenerate"
  }
  return card?.actionLabel ?? "Generate"
}

export function artifactStatusLabel(report: ReportPublic | null) {
  return report ? "Generated" : "Missing"
}

export function verificationSummary(report: ReportVerificationPublic | null) {
  return objectRecord(report?.summary)
}

export function artifactVerificationLabel({
  report,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: {
  report: ReportPublic | null
  verificationLoading: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
}) {
  if (!report) return "Not available"
  if (report.format !== "zip") return "Checksum recorded"
  if (verificationReportTarget?.id === report.id && verificationLoading) {
    return "Verification running"
  }
  const summary =
    verificationReportTarget?.id === report.id
      ? verificationSummary(verificationReport)
      : {}
  if (summary.ok === true) return "Verified"
  if (verificationReportTarget?.id === report.id && verificationReport) {
    return "Verification failed"
  }
  return "Verification pending"
}

export function verificationTone(label: string): VpwBadgeTone {
  if (label === "Verified" || label === "Checksum recorded") return "success"
  if (label === "Verification failed") return "critical"
  if (label === "Verification running" || label === "Verification pending") {
    return "warning"
  }
  return "neutral"
}

export function runFileLabel(run: AnalysisRunPublic): string {
  const inputUpload = objectRecord(run.uploads?.input ?? run.result?.input_upload)
  const uploadFilename =
    stringRecordValue(inputUpload, "original_filename") ??
    stringRecordValue(inputUpload, "stored_filename") ??
    stringRecordValue(inputUpload, "filename")
  return run.filename ?? uploadFilename ?? `${run.input_type} upload`
}

export function priorityCount(
  summary: ProjectDecisionSummaryPublic | AnalysisRunSummaryPublic | null,
  key: "critical" | "high",
): number {
  return (summary?.counts_by_priority?.[key] ??
    summary?.counts_by_priority?.[key.charAt(0).toUpperCase() + key.slice(1)] ??
    0) as number
}

export function summaryOpenFindings(
  summary: ProjectDecisionSummaryPublic | AnalysisRunSummaryPublic | null,
): number {
  if (!summary) return 0
  if ("open_finding_count" in summary) {
    return summary.open_finding_count ?? 0
  }
  return summary.finding_count ?? 0
}

export function runShortId(run: AnalysisRunPublic | null) {
  return run ? run.id.slice(0, 8) : "Not selected"
}

export function providerSnapshotShortId(
  run: AnalysisRunPublic | null,
  providerStatus: ProviderStatusPublic | null,
) {
  return (
    run?.provider_snapshot_id?.slice(0, 8) ??
    providerStatus?.snapshot.id?.slice(0, 8) ??
    "Not recorded"
  )
}

export function providerSnapshotLabel(
  run: AnalysisRunPublic | null,
  providerStatus: ProviderStatusPublic | null,
) {
  const snapshot = providerSnapshotShortId(run, providerStatus)
  const locked = providerStatus?.snapshot.locked_provider_data
    ? "locked"
    : providerStatus?.snapshot.missing
      ? "missing"
      : "fresh"
  return `${snapshot} · ${locked}`
}

export function evidenceReadinessLabel({
  reportActionsEnabled,
  selectedReportRun,
}: {
  reportActionsEnabled: boolean
  selectedReportRun: AnalysisRunPublic | null
}) {
  if (!selectedReportRun) return "No import run selected"
  if (selectedReportRun.status === "failed") return "Run failed"
  if (reportActionsEnabled) return "Ready for generation"
  return "Select a completed run"
}

export function evidenceReadinessTone(label: string): VpwBadgeTone {
  if (label === "Ready for generation") {
    return "success"
  }
  if (label === "Run failed") return "critical"
  return "neutral"
}

export function runSummaryRecord(
  summary: AnalysisRunSummaryPublic | null,
  run: AnalysisRunPublic | null,
) {
  return {
    ...workflowRecord(run),
    ...workflowRecord(summary),
  }
}

export function attackNavigatorAvailable(
  summary: AnalysisRunSummaryPublic | null,
  run: AnalysisRunPublic | null,
) {
  const record = runSummaryRecord(summary, run)
  return (
    Number(record.attack_mapped_cves ?? record.attack_mapped_count ?? 0) > 0 ||
    Boolean(record.attack_mapping_file)
  )
}

export function contextCoverageFacts(
  summary: AnalysisRunSummaryPublic | null,
  run: AnalysisRunPublic | null,
) {
  const record = runSummaryRecord(summary, run)
  const assetContext = objectRecord(record.asset_context)
  const vex = objectRecord(record.vex)
  const attackSource = stringRecordValue(record, "attack_source")
  return {
    acceptedRisk: "Recorded when accepted-risk decisions affect findings",
    assetContext:
      Object.keys(assetContext).length > 0 || record.asset_context_upload
        ? "Present"
        : "Optional missing",
    attack:
      attackNavigatorAvailable(summary, run) ||
      (attackSource && attackSource !== "none")
        ? "Present"
        : "Optional missing",
    vex:
      Object.keys(vex).length > 0 ||
      record.vex_upload ||
      Number(record.suppressed_by_vex ?? 0) > 0
        ? "Present"
        : "Optional missing",
  }
}

function workflowRecord(
  source: AnalysisRunSummaryPublic | AnalysisRunPublic | null,
) {
  if (!source) return {}
  const record: Record<string, unknown> = {}
  setDefined(record, "input_upload", source.uploads?.input ?? source.result?.input_upload)
  setDefined(
    record,
    "asset_context_upload",
    source.uploads?.asset_context ?? source.result?.asset_context_upload,
  )
  setDefined(record, "vex_upload", source.uploads?.vex ?? source.result?.vex_upload)
  setDefined(
    record,
    "attack_mapped_cves",
    "counts" in source
      ? source.counts?.attack_mapped_cves
      : source.result?.attack_mapped_cves,
  )
  setDefined(record, "attack_mapping_file", source.result?.attack_mapping_file)
  setDefined(record, "attack_source", source.result?.attack_source)
  setDefined(record, "asset_context", source.result?.asset_context)
  setDefined(record, "vex", source.result?.vex)
  setDefined(
    record,
    "suppressed_by_vex",
    "counts" in source
      ? source.counts?.suppressed_by_vex
      : source.result?.suppressed_by_vex,
  )
  return record
}

function setDefined(
  record: Record<string, unknown>,
  key: string,
  value: unknown,
) {
  if (value !== undefined && value !== null) record[key] = value
}

function stringRecordValue(record: Record<string, unknown>, key: string) {
  const value = record[key]
  return typeof value === "string" && value.trim() ? value : null
}

export function reportHistoryAction(report: ReportPublic) {
  if (report.format === "zip") return "Built bundle"
  if (report.format === "csv" || report.format === "json") return "Exported"
  return "Generated"
}

export function reportRunLabel(report: ReportPublic) {
  return report.analysis_run_id.slice(0, 8)
}

export function artifactFormatLabel(report: ReportPublic) {
  return reportFormatLabel(report.format)
}

export function runBadgeTone(
  status: AnalysisRunPublic["status"],
): VpwBadgeTone {
  const tone = runStatusTone(status)
  if (tone === "succeeded") return "success"
  if (tone === "failed") return "critical"
  if (tone === "warning") return "warning"
  return "neutral"
}

export function runMetricTone(run: AnalysisRunPublic | null): VpwCompactTone {
  if (!run) return "info"
  return runBadgeTone(run.status)
}

export function reportFormatTone(format: string): VpwBadgeTone {
  if (format === "zip") return "success"
  if (format === "html" || format === "markdown") return "info"
  if (format === "attack-navigator" || format === "sarif") return "support"
  return "neutral"
}

export function statusBannerTone(message: string): VpwStatusBannerTone {
  if (/failed/i.test(message)) return "critical"
  return message ? "success" : "info"
}

export function actionStatusTitle(message: string, error: string) {
  if (error) {
    if (/verification/i.test(error)) return "Bundle verification failed"
    return "Report generation failed"
  }
  if (/verification failed/i.test(message)) return "Bundle verification failed"
  if (/verified/i.test(message)) return "Bundle verification complete"
  if (/download/i.test(message)) return "Download started"
  return "Last action"
}
