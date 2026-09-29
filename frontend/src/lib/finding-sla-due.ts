import type { FindingPublic, FindingSlaState } from "../api-client"
import { formatDate, formatDateTime } from "./date-format.ts"

export type SlaDueTone = "critical" | "warning" | "neutral"

export type SlaDueSummary = {
  label: string
  title: string
  tone: SlaDueTone
}

export const slaFilterOptions: readonly {
  label: string
  value: FindingSlaState
}[] = [
  { label: "Overdue", value: "overdue" },
  { label: "Due soon", value: "due_soon" },
  { label: "On track", value: "on_track" },
]

export function slaStateLabel(state: FindingSlaState | "" | null | undefined) {
  return slaFilterOptions.find((option) => option.value === state)?.label ?? ""
}

const openWorkStatuses = new Set(["open", "in_review", "remediating"])

export function slaDueDetail(
  finding: Pick<FindingPublic, "sla_due_at" | "sla_state" | "status">,
) {
  const summary = slaDueSummary(finding)
  if (!summary) {
    return openWorkStatuses.has(finding.status ?? "")
      ? "No SLA target recorded"
      : "Not tracked for closed or governed findings"
  }
  return `${formatDateTime(finding.sla_due_at)} · ${slaStateLabel(finding.sla_state)}`
}

// Absolute dates keep the label stable when the browser clock and the
// Workbench clock differ; the server decides the state.
export function slaDueSummary(
  finding: Pick<FindingPublic, "sla_due_at" | "sla_state">,
): SlaDueSummary | null {
  const dueAt = finding.sla_due_at
  const state = finding.sla_state
  if (!dueAt || !state) return null
  const dueDateTime = formatDateTime(dueAt, { emptyFallback: "" })
  if (!dueDateTime) return null
  const title = `SLA due ${dueDateTime}`
  if (state === "overdue") {
    return {
      label: `Overdue since ${formatDate(dueAt)}`,
      title,
      tone: "critical",
    }
  }
  if (state === "due_soon") {
    return { label: `Due ${dueDateTime}`, title, tone: "warning" }
  }
  return { label: `Due ${formatDate(dueAt)}`, title, tone: "neutral" }
}
