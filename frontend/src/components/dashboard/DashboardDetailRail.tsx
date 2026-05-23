import type {
  AnalysisRunPublic,
  ProjectDecisionSummaryPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { ProviderFreshnessSummary } from "@/lib/provider-format"
import type { DashboardRunFact } from "./dashboard-model"
import { DashboardDataQualityPanel } from "./DashboardDataQualityPanel"
import { DashboardOperationsStatePanel } from "./DashboardOperationsStatePanel"
import { DashboardRecentRunsPanel } from "./DashboardRecentRunsPanel"
import { DashboardRecommendedActionsPanel } from "./DashboardRecommendedActionsPanel"

type DashboardDetailRailProps = {
  dataQualityError: string | null
  dataQualityWarnings: readonly string[]
  effectiveProviderStatus: ProviderStatusPublic | null
  effectiveRuns: readonly AnalysisRunPublic[]
  effectiveSummary: ProjectDecisionSummaryPublic | null
  freshness: ProviderFreshnessSummary
  latestRun: AnalysisRunPublic | null
  latestRunFactsRows: readonly DashboardRunFact[]
  providerStatusLoading: boolean
  selectedProjectId: string
  staleProvider: boolean
}

export function DashboardDetailRail({
  dataQualityError,
  dataQualityWarnings,
  effectiveProviderStatus,
  effectiveRuns,
  effectiveSummary,
  freshness,
  latestRun,
  latestRunFactsRows,
  providerStatusLoading,
  selectedProjectId,
  staleProvider,
}: DashboardDetailRailProps) {
  return (
    <aside
      aria-label="Dashboard context rail"
      className="dashboard-detail-rail flex flex-col gap-4"
    >
      <DashboardOperationsStatePanel
        effectiveProviderStatus={effectiveProviderStatus}
        effectiveRuns={effectiveRuns}
        effectiveSummary={effectiveSummary}
        freshness={freshness}
        latestRun={latestRun}
        providerStatusLoading={providerStatusLoading}
        staleProvider={staleProvider}
      />
      <DashboardRecentRunsPanel
        latestRunFactsRows={latestRunFactsRows}
        selectedProjectId={selectedProjectId}
      />
      <DashboardDataQualityPanel
        dataQualityError={dataQualityError}
        dataQualityWarnings={dataQualityWarnings}
      />
      <DashboardRecommendedActionsPanel selectedProjectId={selectedProjectId} />
    </aside>
  )
}
