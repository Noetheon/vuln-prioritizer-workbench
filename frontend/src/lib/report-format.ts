import type {
  AnalysisRunStatus,
  ReportCreate,
  ReportPublic,
} from "../client/types.gen.ts"
import { formatDateTime } from "./date-format.ts"

export type ReportFormat = NonNullable<ReportCreate["format"]>

const reportFormatDisplayOrder: readonly string[] = [
  "zip",
  "html",
  "markdown",
  "csv",
  "json",
  "attack-navigator",
  "sarif",
]

const reportableRunStatuses = new Set<AnalysisRunStatus>([
  "succeeded",
  "completed",
  "completed_with_errors",
])

type DisplayReport = Pick<
  ReportPublic,
  "created_at" | "filename" | "format" | "id"
>

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

export function compareReportsForDisplay(
  left: DisplayReport,
  right: DisplayReport,
): number {
  return (
    reportFormatRank(left.format) - reportFormatRank(right.format) ||
    reportFormatLabel(left.format).localeCompare(reportFormatLabel(right.format)) ||
    left.filename.localeCompare(right.filename) ||
    left.id.localeCompare(right.id)
  )
}

export function compareReportsByNewest(
  left: DisplayReport,
  right: DisplayReport,
): number {
  return (
    reportCreatedAtTime(right) - reportCreatedAtTime(left) ||
    compareReportsForDisplay(left, right)
  )
}

export function formatReportDateTime(value: string | null | undefined): string {
  return formatDateTime(value)
}

export function isReportableRunStatus(
  status: string | null | undefined,
): boolean {
  return reportableRunStatuses.has(status as AnalysisRunStatus)
}

function reportFormatRank(format: string): number {
  const index = reportFormatDisplayOrder.indexOf(format)
  return index === -1 ? reportFormatDisplayOrder.length : index
}

function reportCreatedAtTime(report: DisplayReport): number {
  const value = new Date(report.created_at).getTime()
  return Number.isFinite(value) ? value : 0
}
