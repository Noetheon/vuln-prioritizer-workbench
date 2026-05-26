import type { ReactNode } from "react"
import { runStatusLabel } from "@/lib/risk-format"
import { cn } from "@/lib/utils"
import {
  formatDateTime,
  formatDisplayType,
  objectRecord,
  runFileLabel,
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"

export type ImportRun = NonNullable<ImportsWorkbenchProps["selectedRun"]>
export type ImportRunSummary = NonNullable<
  ImportsWorkbenchProps["selectedRunSummary"]
>

export function RunDetailRows({
  className,
  items,
}: {
  className?: string
  items: readonly { label: string; value: ReactNode }[]
}) {
  return (
    <dl
      className={cn(
        "divide-y divide-[var(--vpw-border-subtle)] overflow-hidden rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] text-sm",
        className,
      )}
    >
      {items.map((item) => (
        <div
          className="grid gap-1 px-3 py-2.5 sm:grid-cols-[9.5rem_minmax(0,1fr)] sm:gap-4"
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd className="min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]">
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function stringFromRecord(source: unknown, key: string) {
  const value = objectRecord(source)[key]
  return typeof value === "string" && value.trim() ? value : null
}

export function uploadFilename(source: unknown) {
  return (
    stringFromRecord(source, "original_filename") ??
    stringFromRecord(source, "stored_filename") ??
    stringFromRecord(source, "filename")
  )
}

export function booleanFromRecord(source: unknown, key: string) {
  const value = objectRecord(source)[key]
  if (typeof value === "boolean") return value ? "Yes" : "No"
  return null
}

export function timelineDetail(item: string, summary: ImportRunSummary) {
  const created = summary.created_findings ?? 0
  const updated = summary.updated_findings ?? 0
  if (item === "File uploaded") return runFileLabel(summary)
  if (item === "Data parsed") return `${candidateFindings(summary)} candidate findings`
  if (item === "Provider data applied") {
    return summary.provider_snapshot_id
      ? `${summary.provider_snapshot_id} snapshot`
      : "Current provider data"
  }
  if (item === "Optional context applied") return "Reviewed supplemental context"
  if (item === "Findings created or updated") {
    return `${created} created, ${updated} updated`
  }
  if (item === "Import completed") return runStatusLabel(summary.status)
  if (item === "Parser diagnostics recorded") {
    return `${summary.parse_errors?.length ?? 0} parser error(s)`
  }
  return formatDisplayType(summary.input_type)
}

export function timelineTime(item: string, summary: ImportRunSummary) {
  if (item === "Import completed") return formatDateTime(summary.finished_at)
  return item === "Findings created or updated"
    ? `${summary.created_findings ?? 0} created`
    : formatDateTime(summary.started_at)
}

export function numberFromSummary(summary: ImportRunSummary, key: string) {
  const value = objectRecord(summary)[key]
  return typeof value === "number" ? value : "Not recorded"
}

export function candidateFindings(summary: ImportRunSummary) {
  if (typeof summary.finding_count === "number") return summary.finding_count
  return (summary.created_findings ?? 0) + (summary.updated_findings ?? 0)
}

export function arrayFromRecord(source: Record<string, unknown>, key: string) {
  const value = source[key]
  if (!Array.isArray(value)) return []
  return value
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean)
}
