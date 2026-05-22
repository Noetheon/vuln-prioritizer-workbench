import { formatDateTime } from "./date-format.ts"

export type ReportFormat =
  | "markdown"
  | "html"
  | "json"
  | "csv"
  | "zip"
  | "attack-navigator"
  | "sarif"

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
  return (
    status === "succeeded" ||
    status === "completed" ||
    status === "completed_with_errors"
  )
}
