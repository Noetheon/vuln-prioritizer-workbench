import { Link } from "@tanstack/react-router"
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  XAxis,
  YAxis,
} from "recharts"
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
import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import type { ChartDatum } from "@/lib/chart-data"
import { EmptyState } from "../states"
import type { DashboardRunRange } from "./dashboard-model"

type DashboardSignalOverviewProps = {
  epssItems: readonly ChartDatum[]
  governanceLoading: boolean
  onRunRangeChange: (value: DashboardRunRange) => void
  priorityItems: readonly ChartDatum[]
  runsLoading: boolean
  selectedRunRange: DashboardRunRange
  serviceItems: readonly ChartDatum[]
  summaryLoading: boolean
  topServiceSource: "assets" | "services"
  trendItems: readonly ChartDatum[]
}

function priorityFill(tone: ChartDatum["tone"]) {
  return tone === "critical"
    ? "var(--vpw-red)"
    : tone === "high"
      ? "var(--vpw-amber)"
      : tone === "medium"
        ? "var(--vpw-amber)"
        : tone === "low"
          ? "var(--vpw-green)"
          : "var(--vpw-text-muted)"
}

function epssFill(tone: ChartDatum["tone"]) {
  return tone === "critical"
    ? "var(--vpw-red)"
    : tone === "high"
      ? "var(--vpw-amber)"
      : tone === "medium"
        ? "var(--vpw-amber)"
        : "var(--vpw-green)"
}

export function DashboardSignalOverview({
  epssItems,
  governanceLoading,
  onRunRangeChange,
  priorityItems,
  runsLoading,
  selectedRunRange,
  serviceItems,
  summaryLoading,
  topServiceSource,
  trendItems,
}: DashboardSignalOverviewProps) {
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
        <Tabs className="w-full" defaultValue="priority">
          <TabsList className="mb-3 h-8 text-xs">
            <TabsTrigger value="priority">Findings by Priority</TabsTrigger>
            <TabsTrigger value="epss">EPSS Distribution</TabsTrigger>
            <TabsTrigger value="services">Top Services</TabsTrigger>
            <TabsTrigger value="trend">Risk Trend</TabsTrigger>
          </TabsList>

          <TabsContent className="mt-4" value="priority">
            <ChartCard
              description="Severity distribution across open findings"
              title="Findings by priority"
            >
              {summaryLoading ? (
                <Skeleton className="h-64" />
              ) : priorityItems.length === 0 ? (
                <EmptyState
                  action={
                    <Button asChild size="sm" variant="outline">
                      <Link to="/imports">Import findings</Link>
                    </Button>
                  }
                  ariaLabel="No priority data"
                  compact
                  detail="Import findings to populate priority distribution."
                  title="No findings yet"
                />
              ) : (
                <ResponsiveContainer height={196} width="100%">
                  <BarChart
                    data={priorityItems}
                    margin={{ bottom: 0, left: 0, right: 6, top: 6 }}
                  >
                    <CartesianGrid
                      className="opacity-40"
                      strokeDasharray="3 3"
                    />
                    <XAxis dataKey="label" tick={{ fontSize: 12 }} />
                    <YAxis tick={{ fontSize: 12 }} />
                    <RechartsTooltip />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {priorityItems.map((entry) => (
                        <Cell key={entry.label} fill={priorityFill(entry.tone)} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
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
                      <Link to="/imports">Run import</Link>
                    </Button>
                  }
                  ariaLabel="No EPSS data"
                  compact
                  detail="EPSS signals need a provider-enriched import to display buckets."
                  title="No EPSS data"
                />
              ) : (
                <ResponsiveContainer height={196} width="100%">
                  <BarChart
                    data={epssItems}
                    margin={{ bottom: 0, left: 0, right: 6, top: 6 }}
                  >
                    <CartesianGrid
                      className="opacity-40"
                      strokeDasharray="3 3"
                    />
                    <XAxis dataKey="label" tick={{ fontSize: 12 }} />
                    <YAxis tick={{ fontSize: 12 }} />
                    <RechartsTooltip />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {epssItems.map((entry) => (
                        <Cell key={entry.label} fill={epssFill(entry.tone)} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
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
                      <Link to="/findings">Review findings</Link>
                    </Button>
                  }
                  ariaLabel="No service risk data"
                  compact
                  detail="Add ownership or component labels and rerun analysis to build entity rankings."
                  title="No rollup data"
                />
              ) : (
                <ResponsiveContainer height={220} width="100%">
                  <BarChart
                    data={serviceItems}
                    margin={{ bottom: 0, left: 0, right: 6, top: 6 }}
                  >
                    <CartesianGrid
                      className="opacity-40"
                      strokeDasharray="3 3"
                    />
                    <XAxis dataKey="label" tick={{ fontSize: 12 }} />
                    <YAxis tick={{ fontSize: 12 }} />
                    <RechartsTooltip />
                    <Bar
                      dataKey="value"
                      fill="var(--vpw-teal)"
                      radius={[4, 4, 0, 0]}
                    />
                  </BarChart>
                </ResponsiveContainer>
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
                    <SelectItem value="all">All runs</SelectItem>
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
                      <Link to="/imports">Create first import</Link>
                    </Button>
                  }
                  ariaLabel="No trend data"
                  compact
                  detail="Run at least one import to generate trend history."
                  title="No trend data"
                />
              ) : (
                <ResponsiveContainer height={220} width="100%">
                  <LineChart
                    data={trendItems}
                    margin={{ bottom: 0, left: 0, right: 6, top: 6 }}
                  >
                    <CartesianGrid
                      className="opacity-40"
                      strokeDasharray="3 3"
                    />
                    <XAxis dataKey="label" tick={{ fontSize: 12 }} />
                    <YAxis tick={{ fontSize: 12 }} />
                    <RechartsTooltip />
                    <Line
                      dataKey="value"
                      dot={{ r: 3 }}
                      stroke="var(--vpw-violet)"
                      strokeWidth={2}
                      type="monotone"
                    />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </ChartCard>
          </TabsContent>
        </Tabs>
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
