import type {
  ProjectDecisionSummaryPublic,
  ProjectGovernanceRollupsPublic,
} from "../api-client"
import { objectRecord, stringValue } from "../lib/app-errors"
import { runStatusLabel } from "../lib/risk-format"
import { formatLabel as labelize } from "../lib/ui-copy"
import type { ProjectFormState } from "../lib/app-defaults"

export function numericFilterValue(value: string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return undefined
  }
  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : undefined
}

export function validateProjectForm(form: ProjectFormState) {
  const name = form.name.trim()
  const description = form.description.trim()
  if (!name) {
    return "Project name is required."
  }
  if (name.length > 255) {
    return "Project name must be 255 characters or fewer."
  }
  if (description.length > 4096) {
    return "Project description must be 4096 characters or fewer."
  }
  return ""
}

export function projectRequestBody(form: ProjectFormState) {
  const description = form.description.trim()
  return {
    description: description ? description : null,
    name: form.name.trim(),
  }
}

export function latestRunDetail(summary: ProjectDecisionSummaryPublic | null) {
  if (!summary?.latest_run_id) {
    return "import required"
  }
  return `run ${summary.latest_run_id.slice(0, 8)}`
}

export function latestRunStatusLabel(
  summary: ProjectDecisionSummaryPublic | null,
): string {
  if (!summary?.latest_run_status) {
    return "Complete"
  }
  return runStatusLabel(summary.latest_run_status)
}

export function latestAnalysisValue(
  summary: ProjectDecisionSummaryPublic | null,
) {
  if (!summary?.latest_run_id) {
    return "No run yet"
  }
  return latestRunStatusLabel(summary)
}

export function attackConfidenceSummary(
  summary: { confidence_distribution?: Record<string, number> } | null,
) {
  const counts = summary?.confidence_distribution ?? {}
  return ["high", "medium", "low", "unknown"]
    .map((key) => `${labelize(key)} ${counts[key] ?? 0}`)
    .join(" / ")
}

export function governanceServiceRows(
  rollups: ProjectGovernanceRollupsPublic | null,
) {
  const services = rollups?.top_services_by_risk ?? []
  if (services.length > 0) {
    return { rows: services, source: "services" as const }
  }
  return { rows: rollups?.top_assets_by_risk ?? [], source: "assets" as const }
}

export function waiverDebtRows(rollups: ProjectGovernanceRollupsPublic | null) {
  return rollups?.waiver_debt?.items ?? []
}

export function waiverDebtSummaryRows(
  rollups: ProjectGovernanceRollupsPublic | null,
) {
  const debt = rollups?.waiver_debt
  return [
    {
      label: "Expired",
      value: String(debt?.expired_count ?? 0),
      detail: "past expiry",
    },
    {
      label: "Review due",
      value: String(debt?.review_due_count ?? 0),
      detail: "needs owner review",
    },
    {
      label: "Expiring soon",
      value: String(debt?.expiring_soon_count ?? 0),
      detail: "within 14 days",
    },
    {
      label: "Accepted findings",
      value: String(debt?.accepted_finding_count ?? 0),
      detail: "currently accepted",
    },
  ]
}

export function runFileLabel(run: {
  filename?: string | null
  input_type: string
  uploads?: { input?: unknown } | null
  result?: Record<string, unknown> | null
}) {
  const upload = objectRecord(run.uploads?.input ?? run.result?.input_upload)
  const uploadFilename =
    stringValue(upload.original_filename) ??
    stringValue(upload.stored_filename) ??
    stringValue(upload.filename)
  return run.filename ?? uploadFilename ?? `${run.input_type} upload`
}
