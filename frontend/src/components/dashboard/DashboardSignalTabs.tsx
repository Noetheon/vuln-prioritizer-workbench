import { Link } from "@/lib/router"
import { lazy, Suspense } from "react"
import { ChartCard } from "@/components/charts/ChartCard"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import type { ChartDatum } from "@/lib/chart-data"
import type { ProjectUrlSearch } from "@/workbench/selected-project-search"
import { EmptyState } from "../states"
import type { DashboardRunRange } from "./dashboard-model"

export type SignalTab = "priority" | "epss" | "services" | "trend"

const DashboardPriorityChart = lazy(() => import("./DashboardPriorityChart"))
const DashboardEpssChart = lazy(() => import("./DashboardEpssChart"))
const DashboardServicesChart = lazy(() => import("./DashboardServicesChart"))
const DashboardTrendChart = lazy(() => import("./DashboardTrendChart"))

type DashboardSignalTabsProps = {
  activeSignalTab: SignalTab
  epssItems: readonly ChartDatum[]
  governanceLoading: boolean
  onActiveSignalTabChange: (value: SignalTab) => void
  onRunRangeChange: (value: DashboardRunRange) => void
  priorityItems: readonly ChartDatum[]
  projectSearch: ProjectUrlSearch
  runsLoading: boolean
  selectedRunRange: DashboardRunRange
  serviceItems: readonly ChartDatum[]
  summaryLoading: boolean
  topServiceSource: "assets" | "services"
  trendItems: readonly ChartDatum[]
}

export function DashboardSignalTabs({
  activeSignalTab,
  epssItems,
  governanceLoading,
  onActiveSignalTabChange,
  onRunRangeChange,
  priorityItems,
  projectSearch,
  runsLoading,
  selectedRunRange,
  serviceItems,
  summaryLoading,
  topServiceSource,
  trendItems,
}: DashboardSignalTabsProps) {
  return (
    <Tabs
      className="min-w-0 w-full"
      onValueChange={(value) => onActiveSignalTabChange(value as SignalTab)}
      value={activeSignalTab}
    >
      <TabsList className="mb-3 grid h-auto w-full grid-cols-2 gap-1 text-xs sm:h-8 sm:grid-cols-4 2xl:inline-flex 2xl:w-auto 2xl:grid-cols-none">
        <TabsTrigger className="min-w-0 px-2" value="priority">
          <span className="hidden sm:inline">Findings by Priority</span>
          <span className="sm:hidden">Priority</span>
        </TabsTrigger>
        <TabsTrigger className="min-w-0 px-2" value="epss">
          <span className="hidden sm:inline">EPSS Distribution</span>
          <span className="sm:hidden">EPSS</span>
        </TabsTrigger>
        <TabsTrigger className="min-w-0 px-2" value="services">
          <span className="hidden sm:inline">Top Services</span>
          <span className="sm:hidden">Services</span>
        </TabsTrigger>
        <TabsTrigger className="min-w-0 px-2" value="trend">
          <span className="hidden sm:inline">Risk Trend</span>
          <span className="sm:hidden">Trend</span>
        </TabsTrigger>
      </TabsList>

      <TabsContent className="mt-4" value="priority">
        <ChartCard
          description="Severity distribution across findings in scope"
          title="Findings by priority"
        >
          {summaryLoading ? (
            <Skeleton className="h-64" />
          ) : priorityItems.length === 0 ? (
            <EmptyState
              action={
                <Button asChild size="sm" variant="outline">
                  <Link search={projectSearch} to="/imports">
                    Import findings
                  </Link>
                </Button>
              }
              ariaLabel="No priority data"
              compact
              detail="Import findings to populate priority distribution."
              title="No findings yet"
            />
          ) : (
            activeSignalTab === "priority" && (
              <Suspense fallback={<Skeleton className="h-64" />}>
                <DashboardPriorityChart items={priorityItems} />
              </Suspense>
            )
          )}
        </ChartCard>
      </TabsContent>

      <TabsContent className="mt-4" value="epss">
        <ChartCard
          description="EPSS bucket distribution for exploit likelihood"
          title="EPSS exploit probability"
        >
          {summaryLoading ? (
            <Skeleton className="h-64" />
          ) : epssItems.length === 0 ||
            epssItems.every((e) => e.value === 0) ? (
            <EmptyState
              action={
                <Button asChild size="sm" variant="outline">
                  <Link search={projectSearch} to="/imports">
                    Run import
                  </Link>
                </Button>
              }
              ariaLabel="No EPSS data"
              compact
              detail="EPSS signals need a provider-enriched import to display buckets."
              title="No EPSS data"
            />
          ) : (
            activeSignalTab === "epss" && (
              <Suspense fallback={<Skeleton className="h-64" />}>
                <DashboardEpssChart items={epssItems} />
              </Suspense>
            )
          )}
        </ChartCard>
      </TabsContent>

      <TabsContent className="mt-4" value="services">
        <ChartCard
          description={
            topServiceSource === "assets"
              ? "Assets with highest accumulated risk score"
              : "Services with highest accumulated risk score"
          }
          title={
            topServiceSource === "assets"
              ? "Top Assets by Risk"
              : "Top Services by Risk"
          }
        >
          {governanceLoading ? (
            <Skeleton className="h-72" />
          ) : serviceItems.length === 0 ? (
            <EmptyState
              action={
                <Button asChild size="sm" variant="outline">
                  <Link search={projectSearch} to="/findings">
                    Review findings
                  </Link>
                </Button>
              }
              ariaLabel="No service risk data"
              compact
              detail="Add ownership or component labels and rerun analysis to build entity rankings."
              title="No rollup data"
            />
          ) : (
            activeSignalTab === "services" && (
              <Suspense fallback={<Skeleton className="h-72" />}>
                <DashboardServicesChart
                  items={serviceItems}
                  label={`${
                    topServiceSource === "assets"
                      ? "Top assets"
                      : "Top services"
                  } chart data`}
                />
              </Suspense>
            )
          )}
        </ChartCard>
      </TabsContent>

      <TabsContent className="mt-4" value="trend">
        <ChartCard
          action={
            <Select onValueChange={onRunRangeChange} value={selectedRunRange}>
              <SelectTrigger aria-label="Risk trend range" className="w-36">
                <SelectValue placeholder="Range" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="10">Last 10 runs</SelectItem>
                <SelectItem value="30">Last 30 runs</SelectItem>
              </SelectContent>
            </Select>
          }
          description="Imported run cadence and trend signal over time"
          title="Risk trend"
        >
          {runsLoading ? (
            <Skeleton className="h-72" />
          ) : trendItems.length === 0 ? (
            <EmptyState
              action={
                <Button asChild size="sm" variant="outline">
                  <Link search={projectSearch} to="/imports">
                    Create first import
                  </Link>
                </Button>
              }
              ariaLabel="No trend data"
              compact
              detail="Run at least one import to generate trend history."
              title="No trend data"
            />
          ) : (
            activeSignalTab === "trend" && (
              <Suspense fallback={<Skeleton className="h-72" />}>
                <DashboardTrendChart items={trendItems} />
              </Suspense>
            )
          )}
        </ChartCard>
      </TabsContent>
    </Tabs>
  )
}
