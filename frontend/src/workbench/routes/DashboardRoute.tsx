import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { WorkbenchService } from "../../api-client"
import { RiskOperationsDashboard } from "../../components/dashboard/RiskOperationsDashboard"
import { apiErrorMessage } from "../../lib/app-errors"
import { epssBucketChartData } from "../../lib/chart-data"
import { useWorkbenchContext } from "../WorkbenchContext"
import { governanceServiceRows } from "../route-utils"
import { useWorkbenchDemoWorkspaceQuery } from "../useWorkbenchRuntimeQueries"
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
    projectListError,
    projects,
    providerStatus,
    providerStatusError,
    providerStatusLoading,
    refreshProjects,
    refreshProviderStatus,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
    statusError,
  } = useWorkbenchContext()
  const [demoWorkspaceActionError, setDemoWorkspaceActionError] = useState("")
  const projectDashboardQuery = useProjectDashboardQuery(
    selectedProjectId,
    true,
  )
  const demoWorkspaceQuery = useWorkbenchDemoWorkspaceQuery()
  const demoWorkspaceMutation = useMutation({
    mutationFn: (reset: boolean) =>
      WorkbenchService.createDemoWorkspace({
        demoWorkspaceCreate: { reset },
      }),
  })
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

  const activateDemoWorkspace = async (reset: boolean) => {
    setDemoWorkspaceActionError("")
    try {
      const workspace = await demoWorkspaceMutation.mutateAsync(reset)
      await queryClient.invalidateQueries({ queryKey: workbenchQueryKeys.all })
      await refreshProviderStatus()
      await refreshProjects(workspace.project.id)
      setSelectedProjectId(workspace.project.id)
    } catch (caught) {
      setDemoWorkspaceActionError(
        apiErrorMessage("Demo workspace setup failed", caught),
      )
    }
  }

  const demoWorkspaceStatus = demoWorkspaceQuery.data ?? null
  const demoWorkspaceEnabled = Boolean(demoWorkspaceStatus?.enabled)
  const isManagedDemoWorkspace =
    Boolean(demoWorkspaceStatus?.project_id) &&
    selectedProjectId === demoWorkspaceStatus?.project_id

  return (
    <RiskOperationsDashboard
      dashboardError={
        projectListError ||
        (projectDashboardQuery.isError
          ? apiErrorMessage(
              "Project dashboard unavailable",
              projectDashboardQuery.error,
            )
          : "")
      }
      demoWorkspaceEnabled={demoWorkspaceEnabled}
      demoWorkspaceError={demoWorkspaceActionError}
      demoWorkspacePending={demoWorkspaceMutation.isPending}
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
      isManagedDemoWorkspace={isManagedDemoWorkspace}
      onLoadDemoWorkspace={() => void activateDemoWorkspace(false)}
      onProjectChange={setSelectedProjectId}
      onRefresh={refreshDashboard}
      onResetDemoWorkspace={() => void activateDemoWorkspace(true)}
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
