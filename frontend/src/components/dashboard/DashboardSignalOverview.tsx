import { useState } from "react"
import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
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
  onRunRangeChange: (value: DashboardRunRange) => void
  priorityItems: readonly ChartDatum[]
  runsLoading: boolean
  selectedProjectId: string
  selectedRunRange: DashboardRunRange
  serviceItems: readonly ChartDatum[]
  summaryLoading: boolean
  keyTakeaways: readonly string[]
  topServiceSource: "assets" | "services"
  trendItems: readonly ChartDatum[]
}

export function DashboardSignalOverview({
  epssItems,
  governanceLoading,
  keyTakeaways,
  onRunRangeChange,
  priorityItems,
  runsLoading,
  selectedProjectId,
  selectedRunRange,
  serviceItems,
  summaryLoading,
  topServiceSource,
  trendItems,
}: DashboardSignalOverviewProps) {
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const [activeSignalTab, setActiveSignalTab] =
    useState<SignalTab>("priority")

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
            activeSignalTab={activeSignalTab}
            epssItems={epssItems}
            governanceLoading={governanceLoading}
            onActiveSignalTabChange={setActiveSignalTab}
            onRunRangeChange={onRunRangeChange}
            priorityItems={priorityItems}
            projectSearch={projectSearch}
            runsLoading={runsLoading}
            selectedRunRange={selectedRunRange}
            serviceItems={serviceItems}
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
