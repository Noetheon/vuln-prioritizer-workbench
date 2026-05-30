import type { WorkflowRunPublic, WorkflowRunStatus } from "../api-client"

const ACTIVE_WORKFLOW_STATUSES = new Set<WorkflowRunStatus>([
  "pending",
  "running",
])

const TERMINAL_WORKFLOW_STATUSES = new Set<WorkflowRunStatus>([
  "succeeded",
  "completed_with_errors",
  "failed",
  "cancelled",
])

export function workflowNeedsPolling(
  workflow: WorkflowRunPublic | null | undefined,
) {
  return Boolean(workflow?.status && ACTIVE_WORKFLOW_STATUSES.has(workflow.status))
}

export function workflowIsTerminal(
  workflow: WorkflowRunPublic | null | undefined,
) {
  return Boolean(
    workflow?.status && TERMINAL_WORKFLOW_STATUSES.has(workflow.status),
  )
}

export function workflowStatusLabel(
  workflow: WorkflowRunPublic | null | undefined,
) {
  if (!workflow) return "Not recorded"
  return formatWorkflowText(workflow.status)
}

export function workflowStageLabel(
  workflow: WorkflowRunPublic | null | undefined,
) {
  if (!workflow?.current_stage) return "Not recorded"
  return formatWorkflowText(workflow.current_stage)
}

export function workflowProgressLabel(
  workflow: WorkflowRunPublic | null | undefined,
) {
  if (!workflow) return "Not recorded"
  if (typeof workflow.progress_total === "number" && workflow.progress_total > 0) {
    return `${workflow.progress_current ?? 0}/${workflow.progress_total}`
  }
  return workflowStatusLabel(workflow)
}

export function workflowSummaryLabel(
  workflow: WorkflowRunPublic | null | undefined,
) {
  if (!workflow) return "Workflow not recorded"
  const stage = workflowStageLabel(workflow)
  const progress = workflowProgressLabel(workflow)
  return `${workflowStatusLabel(workflow)} · ${stage} · ${progress}`
}

function formatWorkflowText(value: string) {
  return value.replaceAll("_", " ").replaceAll("-", " ")
}
