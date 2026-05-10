import { useEffect, useState } from "react"
import { EvidenceCenter } from "../../components/reports/EvidenceCenter"
import { apiErrorMessage } from "../../lib/app-errors"
import { useWorkbenchContext } from "../WorkbenchContext"
import {
  useProjectRunsQuery,
  useProjectSummaryQuery,
  useRunDetailQuery,
} from "../useWorkbenchQueries"
import { useReportsRouteState } from "../useReportsRouteState"

function ReportsRouteContent() {
  const {
    handleAuthExpired,
    projectListLoading,
    projectListError,
    projects,
    providerStatus,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const [selectedRunId, setSelectedRunId] = useState("")
  const projectRunsQuery = useProjectRunsQuery(selectedProjectId, true)
  const projectRuns = projectRunsQuery.data?.data ?? []
  const runDetailQuery = useRunDetailQuery(selectedRunId, true)
  const projectSummaryQuery = useProjectSummaryQuery(selectedProjectId)
  const selectedReportRun =
    projectRuns.find((run) => run.id === selectedRunId) ?? null
  const reportsState = useReportsRouteState({
    currentPath: "/reports",
    onAuthExpired: handleAuthExpired,
    selectedReportRun,
    selectedRunId,
  })

  useEffect(() => {
    setSelectedRunId((currentRunId) =>
      projectRuns.some((run) => run.id === currentRunId)
        ? currentRunId
        : (projectRuns[0]?.id ?? ""),
    )
  }, [projectRuns])

  function handleProjectChange(projectId: string) {
    setSelectedProjectId(projectId)
    setSelectedRunId("")
  }

  return (
    <section className="w-full">
      <EvidenceCenter
        activeReportFormat={reportsState.activeReportFormat}
        onCreateReport={reportsState.createReport}
        onDownloadReport={reportsState.downloadReport}
        onProjectChange={handleProjectChange}
        onRunIdChange={setSelectedRunId}
        onVerifyReport={reportsState.verifyEvidenceReport}
        projectListError={projectListError}
        projectListLoading={projectListLoading}
        projectRuns={projectRuns}
        projectSummary={projectSummaryQuery.data ?? null}
        projects={projects}
        providerStatus={providerStatus}
        reportActionError={reportsState.reportActionError}
        reportActionMessage={reportsState.reportActionMessage}
        reportActionsEnabled={reportsState.reportActionsEnabled}
        reports={reportsState.reports}
        reportsError={reportsState.reportsError}
        reportsLoading={reportsState.reportsLoading}
        runDetailError={
          runDetailQuery.isError
            ? apiErrorMessage("Run detail unavailable", runDetailQuery.error)
            : ""
        }
        runsError={
          projectRunsQuery.isError
            ? apiErrorMessage("Import runs unavailable", projectRunsQuery.error)
            : ""
        }
        runsLoading={projectRunsQuery.isLoading || projectRunsQuery.isFetching}
        selectedProject={selectedProject}
        selectedProjectId={selectedProjectId}
        selectedReportRun={selectedReportRun}
        selectedRunId={selectedRunId}
        selectedRunSummary={runDetailQuery.data?.summary ?? null}
        verificationLoading={reportsState.verificationLoading}
        verificationReport={reportsState.verificationReport}
        verificationReportTarget={reportsState.verificationReportTarget}
      />
    </section>
  )
}

export function ReportsRoute() {
  return <ReportsRouteContent />
}
