import { useQueryClient } from "@tanstack/react-query"
import { RiskOperationsDashboard } from "../../components/dashboard/RiskOperationsDashboard"
import { apiErrorMessage } from "../../lib/app-errors"
import { epssBucketChartData } from "../../lib/chart-data"
import { WorkbenchShell } from "../WorkbenchShell"
import { useWorkbenchContext } from "../WorkbenchContext"
import { governanceServiceRows } from "../route-utils"
import {
  emptyDashboardSignalCounts,
  useDashboardFindingsQuery,
  useDashboardSignalCountsQuery,
  useProjectGovernanceRollupsQuery,
  useProjectRunsQuery,
  useProjectSummaryQuery,
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
  const projectSummaryQuery = useProjectSummaryQuery(selectedProjectId)
  const projectGovernanceRollupsQuery =
    useProjectGovernanceRollupsQuery(selectedProjectId)
  const projectRunsQuery = useProjectRunsQuery(selectedProjectId, true)
  const dashboardFindingsQuery = useDashboardFindingsQuery(
    selectedProjectId,
    true,
  )
  const dashboardSignalQuery = useDashboardSignalCountsQuery(
    selectedProjectId,
    true,
  )
  const projectSummary = projectSummaryQuery.data ?? null
  const projectGovernanceRollups =
    projectGovernanceRollupsQuery.data ?? null
  const projectRuns = projectRunsQuery.data?.data ?? []
  const dashboardFindings = dashboardFindingsQuery.data?.data ?? []
  const topServiceRows = governanceServiceRows(projectGovernanceRollups)
  const dashboardSignalCounts =
    dashboardSignalQuery.data ?? emptyDashboardSignalCounts

  const refreshDashboard = () => {
    void refreshProjects(selectedProjectId)
    if (selectedProjectId) {
      void queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.dashboardFindings(selectedProjectId),
      })
      void queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.dashboardSignalCounts(selectedProjectId),
      })
      void queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.projectGovernanceRollups(selectedProjectId),
      })
    }
  }

  return (
    <RiskOperationsDashboard
      dashboardError={
        projectSummaryQuery.isError
          ? apiErrorMessage("Project summary unavailable", projectSummaryQuery.error)
          : ""
      }
      epssBuckets={epssBucketChartData(dashboardSignalCounts.epssBuckets)}
      findings={dashboardFindings}
      findingsError={
        dashboardFindingsQuery.isError
          ? apiErrorMessage(
              "Remediation queue unavailable",
              dashboardFindingsQuery.error,
            )
          : ""
      }
      findingsLoading={
        dashboardFindingsQuery.isLoading || dashboardFindingsQuery.isFetching
      }
      governanceError={
        projectGovernanceRollupsQuery.isError
          ? apiErrorMessage(
              "Governance rollups unavailable",
              projectGovernanceRollupsQuery.error,
            )
          : ""
      }
      governanceLoading={
        projectGovernanceRollupsQuery.isLoading ||
        projectGovernanceRollupsQuery.isFetching
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
      runsLoading={projectRunsQuery.isLoading || projectRunsQuery.isFetching}
      selectedProject={selectedProject}
      selectedProjectId={selectedProjectId}
      signalCounts={dashboardSignalCounts}
      signalError={
        dashboardSignalQuery.isError
          ? apiErrorMessage("Signal counts unavailable", dashboardSignalQuery.error)
          : ""
      }
      signalLoading={
        dashboardSignalQuery.isLoading || dashboardSignalQuery.isFetching
      }
      summaryLoading={
        projectSummaryQuery.isLoading || projectSummaryQuery.isFetching
      }
      topServiceRows={topServiceRows.rows}
      topServiceSource={topServiceRows.source}
    />
  )
}

export function DashboardRoute() {
  return (
    <WorkbenchShell routePath="/">
      <DashboardRouteContainer />
    </WorkbenchShell>
  )
}
