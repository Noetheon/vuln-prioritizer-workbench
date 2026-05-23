import type { FormEventHandler } from "react"
import type { ProjectDecisionSummaryPublic, ProjectPublic } from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"
import { runStatusLabel, runStatusTone } from "@/lib/risk-format"
import { shortId } from "@/lib/ui-copy"

export { formatDateTime } from "../../lib/date-format.ts"
export { shortId }

export type ProjectFormStateLike = {
  description: string
  name: string
}

export type ProjectsWorkbenchProps = {
  createProjectDrawerOpen: boolean
  createProjectError: string
  createProjectForm: ProjectFormStateLike
  deleteConfirmed: boolean
  editProjectForm: ProjectFormStateLike
  editProjectId: string
  onCancelEditProject: () => void
  onCreateProjectDrawerOpenChange: (open: boolean) => void
  onCreateProject: FormEventHandler<HTMLFormElement>
  onCreateProjectDescriptionChange: (value: string) => void
  onCreateProjectNameChange: (value: string) => void
  onDeleteConfirmedChange: (checked: boolean) => void
  onDeleteProject: (project: ProjectPublic) => void
  onEditProjectDescriptionChange: (value: string) => void
  onEditProjectNameChange: (value: string) => void
  onRefreshProjects: () => void
  onSaveProject: FormEventHandler<HTMLFormElement>
  onSelectProject: (projectId: string) => void
  onStartEditProject: (project: ProjectPublic) => void
  projectActionError: string
  projectActionLoading: boolean
  projectActionMessage: string
  projectListLoading: boolean
  projectSummary: ProjectDecisionSummaryPublic | null
  projectSummaryById: Record<string, ProjectDecisionSummaryPublic>
  projectSummaryWarning: string
  projects: ProjectPublic[]
  selectedProject: ProjectPublic | null
  selectedProjectId: string
}

export function runTone(
  status: ProjectDecisionSummaryPublic["latest_run_status"] | undefined,
): VpwBadgeTone {
  const tone = runStatusTone(status ?? undefined)
  if (tone === "succeeded") return "success"
  if (tone === "failed") return "critical"
  if (tone === "warning") return "warning"
  return "neutral"
}

export function latestRunLabel(summary: ProjectDecisionSummaryPublic | null) {
  if (!summary?.latest_run_id) return "No runs yet"
  return `Run ${shortId(summary.latest_run_id)}`
}

export function latestRunStatus(summary: ProjectDecisionSummaryPublic | null) {
  return summary?.latest_run_status
    ? runStatusLabel(summary.latest_run_status)
    : "No runs yet"
}

export function openFindings(summary: ProjectDecisionSummaryPublic | null) {
  return summary?.open_finding_count ?? summary?.finding_count ?? null
}

export function totalOpenFindings(
  projects: ProjectPublic[],
  summaryById: Record<string, ProjectDecisionSummaryPublic>,
) {
  let total = 0
  let hasKnownValue = false

  for (const project of projects) {
    const count = openFindings(summaryById[project.id] ?? null)
    if (typeof count === "number") {
      total += count
      hasKnownValue = true
    }
  }

  return hasKnownValue ? total : null
}

export function evidenceState(summary: ProjectDecisionSummaryPublic | null) {
  if (!summary) {
    return {
      detail: "Project summary unavailable",
      label: "Checking",
      tone: "neutral" as VpwBadgeTone,
    }
  }
  if (summary.provider_degraded) {
    return {
      detail: "Provider data quality needs review",
      label: "Needs attention",
      tone: "warning" as VpwBadgeTone,
    }
  }
  if (summary.latest_run_id) {
    return {
      detail: "Evidence can be generated from current findings",
      label: "Ready",
      tone: "success" as VpwBadgeTone,
    }
  }
  return {
    detail: "Import findings before generating evidence",
    label: "Not generated yet",
    tone: "info" as VpwBadgeTone,
  }
}

export function readinessProgress(
  selectedProject: ProjectPublic | null,
  summary: ProjectDecisionSummaryPublic | null,
) {
  if (!selectedProject) return 0
  let value = 25
  if (summary?.latest_run_id) value += 30
  if ((summary?.finding_count ?? 0) > 0) value += 25
  if (!summary?.provider_degraded) value += 20
  return Math.min(value, 100)
}
