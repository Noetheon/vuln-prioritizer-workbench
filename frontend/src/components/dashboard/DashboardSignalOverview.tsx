import { useState } from "react"
import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import type { MitigationLeverPublic } from "@/api-client"
import type { ChartDatum } from "@/lib/chart-data"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { DashboardRunRange } from "./dashboard-model"
import { DashboardKeyTakeaways } from "./DashboardKeyTakeaways"
import {
  DashboardSignalTabs,
  type SignalTab,
} from "./DashboardSignalTabs"

type DashboardSignalOverviewProps = {
  epssItems: readonly ChartDatum[]
  governanceLoading: boolean
  mitigationLevers: readonly MitigationLeverPublic[]
  onRunRangeChange: (value: DashboardRunRange) => void
  openRiskTotal: number | null
  priorityItems: readonly ChartDatum[]
  riskInsightsError: string
  riskInsightsLoading: boolean
  riskTrendItems: readonly ChartDatum[]
  runsLoading: boolean
  selectedProjectId: string
  selectedRunRange: DashboardRunRange
  serviceItems: readonly ChartDatum[]
  showRiskInsights: boolean
  summaryLoading: boolean
  keyTakeaways: readonly string[]
  topServiceSource: "assets" | "services"
  trendItems: readonly ChartDatum[]
}

export function DashboardSignalOverview({
  epssItems,
  governanceLoading,
  keyTakeaways,
  mitigationLevers,
  onRunRangeChange,
  openRiskTotal,
  priorityItems,
  riskInsightsError,
  riskInsightsLoading,
  riskTrendItems,
  runsLoading,
  selectedProjectId,
  selectedRunRange,
  serviceItems,
  showRiskInsights,
  summaryLoading,
  topServiceSource,
  trendItems,
}: DashboardSignalOverviewProps) {
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const [activeSignalTab, setActiveSignalTab] =
    useState<SignalTab>("priority")
  // The Impact tab only exists in the compact layout; fall back when hidden.
  const effectiveSignalTab =
    !showRiskInsights && activeSignalTab === "impact"
      ? "trend"
      : activeSignalTab

  return (
    <VpwSurface className="gap-2 py-4">
      <VpwSurfaceHeader>
        <VpwSurfaceTitle>Signal Overview</VpwSurfaceTitle>
        <VpwSurfaceDescription>
          Signal concentration, service risk, and trend direction for executive
          review.
        </VpwSurfaceDescription>
      </VpwSurfaceHeader>
      <VpwSurfaceBody>
        <div className="dashboard-signal-layout">
          <DashboardSignalTabs
            activeSignalTab={effectiveSignalTab}
            epssItems={epssItems}
            governanceLoading={governanceLoading}
            mitigationLevers={mitigationLevers}
            onActiveSignalTabChange={setActiveSignalTab}
            openRiskTotal={openRiskTotal}
            onRunRangeChange={onRunRangeChange}
            priorityItems={priorityItems}
            projectSearch={projectSearch}
            riskInsightsError={riskInsightsError}
            riskInsightsLoading={riskInsightsLoading}
            riskTrendItems={riskTrendItems}
            runsLoading={runsLoading}
            selectedRunRange={selectedRunRange}
            serviceItems={serviceItems}
            showRiskInsights={showRiskInsights}
            summaryLoading={summaryLoading}
            topServiceSource={topServiceSource}
            trendItems={trendItems}
          />
          <DashboardKeyTakeaways
            items={keyTakeaways}
            projectSearch={projectSearch}
          />
        </div>
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
