import { useQueryClient } from "@tanstack/react-query"
import { RiskOperationsDashboard } from "../../components/dashboard/RiskOperationsDashboard"
import { apiErrorMessage } from "../../lib/app-errors"
import { epssBucketChartData } from "../../lib/chart-data"
import { useWorkbenchContext } from "../WorkbenchContext"
import { governanceServiceRows } from "../route-utils"
import {
  dashboardSignalCountsFromApi,
  emptyDashboardSignalCounts,
  useProjectDashboardQuery,
} from "../useWorkbenchQueries"
import { workbenchQueryKeys } from "../workbench-query-keys"

function DashboardRouteContainer() {
  const queryClient = useQueryClient()
  const {
    projectListLoading,
    projects,
    providerStatus,
    providerStatusError,
    providerStatusLoading,
    refreshProjects,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
    statusError,
  } = useWorkbenchContext()
  const projectDashboardQuery = useProjectDashboardQuery(
    selectedProjectId,
    true,
  )
  const projectDashboard = projectDashboardQuery.data ?? null
  const projectSummary = projectDashboard?.summary ?? null
  const projectGovernanceRollups = projectDashboard?.governance ?? null
  const projectRuns = projectDashboard?.runs.data ?? []
  const dashboardFindings =
    projectDashboard?.findings.remediation_queue.data ?? []
  const topServiceRows = governanceServiceRows(projectGovernanceRollups)
  const dashboardSignalCounts = projectDashboard
    ? dashboardSignalCountsFromApi(projectDashboard.findings.signal_counts)
    : emptyDashboardSignalCounts

  const refreshDashboard = () => {
    void refreshProjects(selectedProjectId)
    if (selectedProjectId) {
      void queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.projectDashboard(selectedProjectId),
      })
    }
  }

  return (
    <RiskOperationsDashboard
      dashboardError={
        projectDashboardQuery.isError
          ? apiErrorMessage(
              "Project dashboard unavailable",
              projectDashboardQuery.error,
            )
          : ""
      }
      epssBuckets={epssBucketChartData(dashboardSignalCounts.epssBuckets)}
      findings={dashboardFindings}
      findingsError=""
      findingsLoading={
        projectDashboardQuery.isLoading || projectDashboardQuery.isFetching
      }
      governanceError=""
      governanceLoading={
        projectDashboardQuery.isLoading || projectDashboardQuery.isFetching
      }
      onProjectChange={setSelectedProjectId}
      onRefresh={refreshDashboard}
      projectListLoading={projectListLoading}
      projectRuns={projectRuns}
      projectSummary={projectSummary}
      projects={projects}
      providerStatus={providerStatus}
      providerStatusError={providerStatusError || statusError}
      providerStatusLoading={providerStatusLoading}
      runsLoading={
        projectDashboardQuery.isLoading || projectDashboardQuery.isFetching
      }
      selectedProject={selectedProject}
      selectedProjectId={selectedProjectId}
      signalCounts={dashboardSignalCounts}
      signalError=""
      signalLoading={
        projectDashboardQuery.isLoading || projectDashboardQuery.isFetching
      }
      summaryLoading={
        projectDashboardQuery.isLoading || projectDashboardQuery.isFetching
      }
      topServiceRows={topServiceRows.rows}
      topServiceSource={topServiceRows.source}
    />
  )
}

export function DashboardRoute() {
  return <DashboardRouteContainer />
}
