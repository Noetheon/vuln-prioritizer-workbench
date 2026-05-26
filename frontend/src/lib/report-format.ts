import type { AnalysisRunStatus, ReportCreate } from "../client/types.gen.ts"
import { formatDateTime } from "./date-format.ts"

export type ReportFormat = NonNullable<ReportCreate["format"]>

const reportableRunStatuses = new Set<AnalysisRunStatus>([
  "succeeded",
  "completed",
  "completed_with_errors",
])

export function reportFormatLabel(format: string): string {
  if (format === "zip") return "Evidence ZIP"
  if (format === "attack-navigator") return "ATT&CK Navigator"
  if (format === "sarif") return "SARIF"
  return format.toUpperCase()
}

export function reportSizeLabel(sizeBytes: number): string {
  if (sizeBytes < 1024) return `${sizeBytes} B`
  if (sizeBytes < 1024 * 1024) return `${(sizeBytes / 1024).toFixed(1)} KB`
  return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`
}

export function formatReportDateTime(value: string | null | undefined): string {
  return formatDateTime(value)
}

export function isReportableRunStatus(
  status: string | null | undefined,
): boolean {
  return reportableRunStatuses.has(status as AnalysisRunStatus)
}
