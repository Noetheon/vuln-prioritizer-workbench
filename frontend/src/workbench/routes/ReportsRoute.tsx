import { useCallback, useEffect, useMemo, useState } from "react"
import { useLocation, useNavigate } from "@/lib/router"
import { EvidenceCenter } from "../../components/reports/EvidenceCenter"
import { apiErrorMessage } from "../../lib/app-errors"
import { useWorkbenchContext } from "../WorkbenchContext"
import {
  normalizeSelectedRunId,
  reportRunUrlSearch,
  selectedReportRunIdFromSearch,
} from "../report-route-search"
import { searchStringFromUrlSearch } from "../selected-project-search"
import {
  useProjectRunsQuery,
  useProjectSummaryQuery,
  useRunDetailQuery,
} from "../useWorkbenchQueries"
import { useReportsRouteState } from "../useReportsRouteState"

function activeSearchString(fallbackSearch: string) {
  return typeof window === "undefined" ? fallbackSearch : window.location.search
}

function ReportsRouteContent() {
  const location = useLocation()
  const navigate = useNavigate()
  const {
    projectListLoading,
    projectListError,
    projects,
    providerStatus,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const routeRunId = selectedReportRunIdFromSearch(location.searchStr)
  const [selectedRunId, setSelectedRunIdState] = useState(routeRunId)
  const projectRunsQuery = useProjectRunsQuery(selectedProjectId, true)
  const projectRuns = projectRunsQuery.data?.data ?? []
  const runDetailQuery = useRunDetailQuery(selectedRunId, true)
  const projectSummaryQuery = useProjectSummaryQuery(selectedProjectId)
  const selectedReportRun =
    projectRuns.find((run) => run.id === selectedRunId) ?? null
  const reportsState = useReportsRouteState({
    currentPath: "/reports",
    selectedReportRun,
    selectedRunId,
  })
  const runIds = useMemo(() => projectRuns.map((run) => run.id), [projectRuns])

  const selectRunId = useCallback(
    (nextRunId: string, { replace }: { replace: boolean }) => {
      setSelectedRunIdState(nextRunId)
      const currentLocationSearch = activeSearchString(location.searchStr)
      const nextSearch = reportRunUrlSearch(currentLocationSearch, nextRunId)
      const currentSearch = currentLocationSearch.startsWith("?")
        ? currentLocationSearch.slice(1)
        : currentLocationSearch
      if (searchStringFromUrlSearch(nextSearch) === currentSearch) {
        return
      }
      void navigate({
        replace,
        search: () => nextSearch,
      })
    },
    [location.searchStr, navigate],
  )

  useEffect(() => {
    if (projectRunsQuery.isLoading && runIds.length === 0) {
      return
    }
    const nextRunId = normalizeSelectedRunId(
      [routeRunId, selectedRunId],
      runIds,
    )
    if (nextRunId === selectedRunId && nextRunId === routeRunId) {
      return
    }
    selectRunId(nextRunId, { replace: true })
  }, [
    projectRunsQuery.isLoading,
    routeRunId,
    runIds,
    selectRunId,
    selectedRunId,
  ])

  function handleProjectChange(projectId: string) {
    setSelectedProjectId(projectId)
    selectRunId("", { replace: true })
  }

  return (
    <EvidenceCenter
      activeReportFormat={reportsState.activeReportFormat}
      onCreateReport={reportsState.createReport}
      onDownloadReport={reportsState.downloadReport}
      onProjectChange={handleProjectChange}
      onRunIdChange={(runId) => selectRunId(runId, { replace: false })}
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
  )
}

export function ReportsRoute() {
  return <ReportsRouteContent />
}
