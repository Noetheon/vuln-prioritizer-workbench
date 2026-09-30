import type { AnalysisRunPublic } from "../../api-client"
import { formatReportDateTime } from "../../lib/report-format.ts"

const REPORTABLE_RUN_STATUSES: ReadonlySet<string> = new Set([
  "completed",
  "completed_with_errors",
  "succeeded",
])
const REEVALUATION_INPUT_TYPE = "reevaluation"
const PROVIDER_UPDATE_INPUT_TYPE = "provider_update"
const PROJECT_STATE_INPUT_TYPE = "project_state"

/** Picker value for "report on the project as it is now". */
export const CURRENT_PROJECT_STATE = "current-state"

export type ReportRunScope = {
  message: string
  title: string
  tone: "info" | "warning"
}

function objectRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {}
}

function stringRecordValue(record: Record<string, unknown>, key: string) {
  const value = record[key]
  return typeof value === "string" && value.trim() ? value : null
}

export function runFileLabel(run: AnalysisRunPublic): string {
  const inputUpload = objectRecord(run.uploads?.input)
  const uploadFilename =
    stringRecordValue(inputUpload, "original_filename") ??
    stringRecordValue(inputUpload, "stored_filename") ??
    stringRecordValue(inputUpload, "filename")
  if (run.filename ?? uploadFilename) {
    return (run.filename ?? uploadFilename) as string
  }
  if (isProjectStateRun(run)) {
    return "Project state"
  }
  return isReevaluationRun(run) ? "Re-evaluation" : `${run.input_type} upload`
}

export function isReevaluationRun(run: AnalysisRunPublic) {
  return run.input_type === REEVALUATION_INPUT_TYPE
}

export function isProjectStateRun(run: AnalysisRunPublic) {
  return run.input_type === PROJECT_STATE_INPUT_TYPE
}

export function isReportableRun(run: AnalysisRunPublic) {
  return (
    REPORTABLE_RUN_STATUSES.has(run.status) &&
    run.input_type !== PROVIDER_UPDATE_INPUT_TYPE
  )
}

/** Runs a report can describe: imports, re-evaluations, and recorded project states. */
export function reportRunOptions(runs: readonly AnalysisRunPublic[]) {
  return runs.filter((run) => run.input_type !== PROVIDER_UPDATE_INPUT_TYPE)
}

/** The newest completed import, for comparisons with an older selected import. */
export function latestImportRunId(runs: readonly AnalysisRunPublic[]) {
  return (
    runs.find(
      (run) =>
        isReportableRun(run) && !isReevaluationRun(run) && !isProjectStateRun(run),
    )?.id ?? ""
  )
}

/**
 * What a report describes unless the user picks a run: the current state of
 * the whole project. A recorded state that still matches the project is that
 * state, so its reports open directly.
 */
export function defaultReportRunId(runs: readonly AnalysisRunPublic[]) {
  const currentRecording = runs.find(
    (run) =>
      isProjectStateRun(run) &&
      isReportableRun(run) &&
      run.project_state_current === true,
  )
  if (currentRecording) {
    return currentRecording.id
  }
  return runs.some(isReportableRun) ? CURRENT_PROJECT_STATE : ""
}

export function runFindingCount(run: AnalysisRunPublic) {
  return run.counts?.finding_count ?? null
}

function findingCountLabel(run: AnalysisRunPublic) {
  const count = runFindingCount(run)
  if (count === null) {
    return "findings"
  }
  return `${count} finding${count === 1 ? "" : "s"}`
}

export function reportRunOptionLabel(run: AnalysisRunPublic) {
  const kind = isReevaluationRun(run) ? "Re-evaluation" : runFileLabel(run)
  const status = isReportableRun(run) ? findingCountLabel(run) : run.status
  return `${kind} · ${formatReportDateTime(run.started_at)} · ${status}`
}

export function currentProjectStateScope(
  findingCount: number | null | undefined,
): ReportRunScope {
  const findings =
    findingCount === null || findingCount === undefined
      ? "all findings"
      : `all ${findingCount} finding${findingCount === 1 ? "" : "s"}`
  return {
    message: `Reports cover ${findings} of the project with their current status and priority. Generating a report records this state, so later changes do not alter it.`,
    title: "Current project state",
    tone: "info",
  }
}

/** Tell the reader exactly which findings a report from this run covers. */
export function reportRunScope(
  run: AnalysisRunPublic | null,
  runs: readonly AnalysisRunPublic[],
  { projectStateCurrent }: { projectStateCurrent?: boolean | null } = {},
): ReportRunScope | null {
  if (run === null) {
    return null
  }
  if (!isReportableRun(run)) {
    return {
      message:
        "Reports need a completed run. Select Current project state instead.",
      title: "This run did not complete",
      tone: "warning",
    }
  }
  const covered = findingCountLabel(run)
  const recordedAt = formatReportDateTime(run.started_at)
  if (isProjectStateRun(run)) {
    return (projectStateCurrent ?? run.project_state_current) === false
      ? {
          message: `This state from ${recordedAt} covered ${covered}. Reports already generated from it stay valid, but new ones fail because the project has changed. Select Current project state to report on the project as it is now.`,
          title: "The project changed since this state was recorded",
          tone: "warning",
        }
      : {
          message: `This report covers the whole project as recorded on ${recordedAt}: ${covered}.`,
          title: "Recorded project state",
          tone: "info",
        }
  }
  if (isReevaluationRun(run)) {
    return {
      message: `This run re-scored ${covered} after an asset or policy change. A report from it covers only those findings, not the whole project. Select Current project state for a full report.`,
      title: "Re-evaluation run selected",
      tone: "warning",
    }
  }
  const latestImportId = latestImportRunId(runs)
  const latestImport = runs.find((candidate) => candidate.id === latestImportId)
  const scope = `This report covers ${covered} from ${runFileLabel(run)}, imported ${formatReportDateTime(run.started_at)}.`
  if (latestImport && latestImport.id !== run.id) {
    return {
      message: `${scope} A newer import exists: ${runFileLabel(latestImport)} from ${formatReportDateTime(latestImport.started_at)}.`,
      title: "Older import selected",
      tone: "warning",
    }
  }
  return { message: scope, title: "Report scope", tone: "info" }
}
