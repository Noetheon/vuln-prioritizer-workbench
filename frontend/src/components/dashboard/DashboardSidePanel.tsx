import { Link } from "@/lib/router"
import { AlertCircle, CheckCircle2 } from "lucide-react"
import type {
  AnalysisRunPublic,
  ProjectDecisionSummaryPublic,
  ProviderStatusPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import type { ProviderFreshnessSummary } from "@/lib/provider-format"
import { ProviderStatusBadge } from "../risk/ProviderStatusBadge"
import type { DashboardRunFact } from "./dashboard-model"
import { latestRunLabel } from "./dashboard-model"

type DashboardSidePanelProps = {
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

export function DashboardSidePanel({
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
}: DashboardSidePanelProps) {
  const qualityIssueCount =
    dataQualityWarnings.length + (dataQualityError ? 1 : 0)
  const readinessTone: VpwBadgeTone = staleProvider ? "warning" : "success"
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)

  return (
    <div className="flex flex-col gap-4 lg:sticky lg:top-20">
      <VpwSurface className="gap-4 py-4">
        <VpwSurfaceHeader className="px-4 pb-0">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <VpwSurfaceTitle>Operations State</VpwSurfaceTitle>
              <VpwSurfaceDescription className="mt-1 text-xs">
                Provider recency and run evidence for the selected project.
              </VpwSurfaceDescription>
            </div>
            <VpwBadge tone={readinessTone}>
              {staleProvider ? "Needs sync" : "Current"}
            </VpwBadge>
          </div>
        </VpwSurfaceHeader>
        <VpwSurfaceBody className="flex flex-col gap-4 px-4">
          <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-3">
            <p className="vpw-label">Provider freshness</p>
            <div className="mt-2 flex items-center gap-2">
              <ProviderStatusBadge
                status={
                  effectiveProviderStatus?.status ??
                  (providerStatusLoading ? "loading" : "unknown")
                }
              />
              <span className="truncate text-base font-semibold">
                {freshness.value}
              </span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
              {freshness.detail}
            </p>
            {providerStatusLoading && <Skeleton className="mt-2 h-4 w-32" />}
          </div>
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <div className="col-span-2 rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3">
              <dt className="vpw-label">Latest run</dt>
              <dd className="mt-1 truncate font-medium">
                {latestRunLabel(latestRun)}
              </dd>
            </div>
            <div className="rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3">
              <dt className="vpw-label">Findings</dt>
              <dd className="mt-1 text-lg font-semibold">
                {effectiveSummary?.finding_count ?? 0}
              </dd>
            </div>
            <div className="rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3">
              <dt className="vpw-label">Runs</dt>
              <dd className="mt-1 text-lg font-semibold">
                {effectiveRuns.length}
              </dd>
            </div>
          </dl>
        </VpwSurfaceBody>
      </VpwSurface>

      <VpwSurface className="gap-3 py-4">
        <VpwSurfaceHeader className="px-4 pb-0">
          <VpwSurfaceTitle className="text-sm">Recent Runs</VpwSurfaceTitle>
        </VpwSurfaceHeader>
        <VpwSurfaceBody className="px-4">
          {latestRunFactsRows.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No analysis runs yet.
            </p>
          ) : (
            <div className="flex flex-col gap-2">
              {latestRunFactsRows.map((run) => (
                <div
                  className="flex items-center justify-between gap-2 rounded-md border bg-muted/20 px-2.5 py-2 text-xs"
                  key={run.id}
                >
                  <VpwBadge
                    className="shrink-0"
                    tone={runBadgeTone(run.tone)}
                  >
                    {run.status}
                  </VpwBadge>
                  <span className="truncate text-muted-foreground">
                    {run.startedAt}
                  </span>
                </div>
              ))}
            </div>
          )}
          <Button asChild className="mt-3 w-full" size="sm" variant="outline">
            <Link search={projectSearch} to="/imports">
              View all imports
            </Link>
          </Button>
        </VpwSurfaceBody>
      </VpwSurface>

      <VpwSurface className="gap-3 py-4">
        <VpwSurfaceHeader className="px-4 pb-0">
          <div className="flex items-center justify-between gap-3">
            <VpwSurfaceTitle className="text-sm">Data Quality</VpwSurfaceTitle>
            <VpwBadge tone={qualityIssueCount > 0 ? "warning" : "success"}>
              {qualityIssueCount > 0 ? `${qualityIssueCount} issue(s)` : "Clear"}
            </VpwBadge>
          </div>
        </VpwSurfaceHeader>
        <VpwSurfaceBody className="px-4">
          {dataQualityWarnings.length === 0 && !dataQualityError ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <CheckCircle2 className="size-3.5 shrink-0 text-[var(--vpw-green)]" />
              <span>No data quality issues detected.</span>
            </div>
          ) : (
            <ul className="flex flex-col gap-2">
              {dataQualityWarnings.map((warning) => (
                <li className="flex gap-2 text-xs" key={warning}>
                  <AlertCircle
                    aria-hidden="true"
                    className="mt-0.5 size-3.5 shrink-0 text-[var(--vpw-amber)]"
                  />
                  <span className="leading-relaxed text-muted-foreground">
                    {warning}
                  </span>
                </li>
              ))}
              {dataQualityError && (
                <li className="flex gap-2 text-xs">
                  <AlertCircle
                    aria-hidden="true"
                    className="mt-0.5 size-3.5 shrink-0 text-[var(--vpw-red)]"
                  />
                  <span className="leading-relaxed text-muted-foreground">
                    {dataQualityError}
                  </span>
                </li>
              )}
            </ul>
          )}
        </VpwSurfaceBody>
      </VpwSurface>
    </div>
  )
}

function runBadgeTone(tone: DashboardRunFact["tone"]): VpwBadgeTone {
  if (tone === "succeeded") return "success"
  if (tone === "failed") return "critical"
  if (tone === "warning") return "warning"
  return "neutral"
}
