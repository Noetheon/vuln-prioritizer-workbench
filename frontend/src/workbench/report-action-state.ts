import type { AnalysisRunPublic } from "../api-client"
import { isReportableRunStatus } from "../lib/report-format.ts"

export type ReportActionStateInput = {
  currentPath: string
  reportActionPending: boolean
  reportsLoading: boolean
  selectedReportRun: AnalysisRunPublic | null
}

export function reportActionsAvailable({
  currentPath,
  reportActionPending,
  reportsLoading,
  selectedReportRun,
}: ReportActionStateInput): boolean {
  return (
    currentPath === "/reports" &&
    Boolean(selectedReportRun) &&
    isReportableRunStatus(selectedReportRun?.status) &&
    !reportsLoading &&
    !reportActionPending
  )
}
