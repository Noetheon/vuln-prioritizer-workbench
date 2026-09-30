import { useMemo, useState } from "react"
import { ReevaluateControl } from "@/components/evaluations/ReevaluateControl"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Callout } from "@/components/vpw"
import { formatProviderFreshness } from "@/lib/provider-format"
import { DashboardContextBar } from "./DashboardContextBar"
import { DashboardOnboardingChecklist } from "./DashboardOnboardingChecklist"
import { DashboardMetricStrip } from "./DashboardMetricStrip"
import { DashboardProviderWarning } from "./DashboardProviderWarning"
import { DashboardRemediationSection } from "./DashboardRemediationSection"
import { DashboardRiskReductionPanel } from "./DashboardRiskReductionPanel"
import type {
  QueueFilterState,
  RiskOperationsDashboardProps,
} from "./dashboard-model"
import { onboardingVisible } from "./dashboard-onboarding-model"
import {
  buildDashboardMetricSummaries,
  providerNeedsRefresh,
  providerRefreshDetail,
  rankedDashboardQueueFindings,
} from "./dashboard-summary-model"

export function RiskOperationsDashboard({
  dashboardError,
  demoWorkspaceEnabled,
  demoWorkspaceError,
  demoWorkspacePending,
  findings,
  findingsError,
  findingsLoading,
  governanceError,
  governanceLoading,
  isManagedDemoWorkspace,
  onLoadDemoWorkspace,
  onRefresh,
  onResetDemoWorkspace,
  projectListLoading,
  projects,
  providerStatus,
  providerStatusError,
  providerStatusLoading,
  kpis = null,
  onboarding = null,
  onCreateProject = () => {},
  riskReduction,
  runsLoading,
  selectedProject,
  selectedProjectId,
  signalCounts,
  signalError,
  signalLoading,
  summaryLoading,
  projectSummary,
}: RiskOperationsDashboardProps) {
  const [filters, setFilters] = useState<QueueFilterState>({
    queueSearch: "",
  })

  const isLoading =
    projectListLoading ||
    summaryLoading ||
    signalLoading ||
    providerStatusLoading ||
    runsLoading ||
    governanceLoading

  const hasProjects = projects.length > 0
  const hasProviderStatus = selectedProject !== null && hasProjects
  const staleProvider = providerNeedsRefresh(hasProviderStatus, providerStatus)

  const freshness = formatProviderFreshness(providerStatus)

  const queueFindings = useMemo(
    () => rankedDashboardQueueFindings(findings, filters.queueSearch),
    [findings, filters.queueSearch],
  )

  const acceptedRiskCount = projectSummary?.counts_by_status?.accepted ?? 0
  const summaryMetrics = useMemo(
    () =>
      buildDashboardMetricSummaries({
        acceptedRiskCount,
        effectiveSignalCounts: signalCounts,
        effectiveSummary: projectSummary,
        kpis,
        signalLoading,
        summaryLoading,
      }),
    [
      acceptedRiskCount,
      kpis,
      signalCounts,
      projectSummary,
      signalLoading,
      summaryLoading,
    ],
  )

  const showEmptyState =
    !isLoading &&
    !hasProviderStatus &&
    !projectListLoading &&
    !projectSummary &&
    !dashboardError &&
    !signalError &&
    !providerStatusError
  const showOnboarding =
    !projectListLoading &&
    onboardingVisible({ hasProjects, onboarding, selectedProjectId })
  // Nothing to re-score or report on until the first import.
  const hasFindings = (projectSummary?.finding_count ?? 0) > 0
  const onboardingChecklist = (
    <DashboardOnboardingChecklist
      demoWorkspaceEnabled={demoWorkspaceEnabled}
      demoWorkspacePending={demoWorkspacePending}
      onCreateProject={onCreateProject}
      onLoadDemoWorkspace={onLoadDemoWorkspace}
      onboarding={onboarding}
      projectName={selectedProject?.name ?? null}
      selectedProjectId={selectedProjectId}
    />
  )

  const dashboardContent = (
    <div className="min-w-0 flex flex-col gap-4">
      <DashboardContextBar
        demoWorkspaceEnabled={demoWorkspaceEnabled}
        demoWorkspacePending={demoWorkspacePending}
        effectiveProjects={projects}
        effectiveProviderStatus={providerStatus}
        effectiveSelectedProject={selectedProject}
        freshness={freshness}
        hasFindings={hasFindings}
        isManagedDemoWorkspace={isManagedDemoWorkspace}
        onCreateProject={onCreateProject}
        onLoadDemoWorkspace={onLoadDemoWorkspace}
        onRefresh={onRefresh}
        onResetDemoWorkspace={onResetDemoWorkspace}
        providerStatusLoading={providerStatusLoading}
        selectedProjectId={selectedProjectId}
      />

      {dashboardError ||
      signalError ||
      providerStatusError ||
      findingsError ||
      demoWorkspaceError ||
      governanceError ? (
        <Callout severity="critical" title="Dashboard unavailable">
          {dashboardError ||
            signalError ||
            providerStatusError ||
            findingsError ||
            demoWorkspaceError ||
            governanceError ||
            "Dashboard is currently unavailable"}
        </Callout>
      ) : null}

      {staleProvider ? (
        <DashboardProviderWarning detail={providerRefreshDetail(providerStatus)} />
      ) : null}
      {selectedProjectId && hasFindings ? (
        <ReevaluateControl
          key={selectedProjectId}
          projectId={selectedProjectId}
          latestProviderSnapshotId={providerStatus?.snapshot.id}
        />
      ) : null}

      {showEmptyState ? (
        onboardingChecklist
      ) : (
        <>
          {showOnboarding ? onboardingChecklist : null}
          <DashboardRiskReductionPanel
            isLoading={isLoading}
            kpis={kpis}
            projectSummary={projectSummary}
            riskReduction={riskReduction}
            selectedProjectId={selectedProjectId}
          />
          <DashboardMetricStrip
            isLoading={isLoading}
            metrics={summaryMetrics}
          />
          <DashboardRemediationSection
            findingsError={findingsError}
            findingsLoading={findingsLoading}
            onQueueSearchChange={(queueSearch) =>
              setFilters((current) => ({
                ...current,
                queueSearch,
              }))
            }
            queueFindings={queueFindings}
            queueSearch={filters.queueSearch}
            selectedProjectId={selectedProjectId}
          />
        </>
      )}
    </div>
  )

  return (
    <TooltipProvider>
      <section
        aria-label="Risk Operations dashboard"
        className="dashboard-analyst-layout flex flex-col gap-4 pb-4"
      >
        <div className="grid gap-4">{dashboardContent}</div>
      </section>
    </TooltipProvider>
  )
}
