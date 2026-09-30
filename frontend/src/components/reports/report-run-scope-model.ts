import type { AnalysisRunPublic } from "../../api-client"
import { formatReportDateTime } from "../../lib/report-format.ts"

const REPORTABLE_RUN_STATUSES: ReadonlySet<string> = new Set([
  "completed",
  "completed_with_errors",
  "succeeded",
])
const REEVALUATION_INPUT_TYPE = "reevaluation"
const PROVIDER_UPDATE_INPUT_TYPE = "provider_update"

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
  return isReevaluationRun(run) ? "Re-evaluation" : `${run.input_type} upload`
}

export function isReevaluationRun(run: AnalysisRunPublic) {
  return run.input_type === REEVALUATION_INPUT_TYPE
}

export function isReportableRun(run: AnalysisRunPublic) {
  return (
    REPORTABLE_RUN_STATUSES.has(run.status) &&
    run.input_type !== PROVIDER_UPDATE_INPUT_TYPE
  )
}

/** Runs a report can describe: imports and re-evaluations, never provider updates. */
export function reportRunOptions(runs: readonly AnalysisRunPublic[]) {
  return runs.filter((run) => run.input_type !== PROVIDER_UPDATE_INPUT_TYPE)
}

/**
 * The run a report describes unless the user picks one: the newest completed
 * import. Re-evaluations only re-score some findings and failed runs have no
 * results, so neither is ever the default.
 */
export function defaultReportRunId(runs: readonly AnalysisRunPublic[]) {
  const latestImport = runs.find(
    (run) => isReportableRun(run) && !isReevaluationRun(run),
  )
  return latestImport?.id ?? runs.find(isReportableRun)?.id ?? ""
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

/** Tell the reader exactly which findings a report from this run covers. */
export function reportRunScope(
  run: AnalysisRunPublic | null,
  runs: readonly AnalysisRunPublic[],
): ReportRunScope | null {
  if (run === null) {
    return null
  }
  if (!isReportableRun(run)) {
    return {
      message:
        "Reports need a completed run. Select the latest completed import instead.",
      title: "This run did not complete",
      tone: "warning",
    }
  }
  const covered = findingCountLabel(run)
  if (isReevaluationRun(run)) {
    return {
      message: `This run re-scored ${covered} after an asset or policy change. A report from it covers only those findings, not the whole project. Select the latest import for a full report.`,
      title: "Re-evaluation run selected",
      tone: "warning",
    }
  }
  const latestImportId = defaultReportRunId(runs)
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
