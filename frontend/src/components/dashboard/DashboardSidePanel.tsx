import { Link } from "@tanstack/react-router"
import { AlertCircle, CheckCircle2 } from "lucide-react"
import type {
  AnalysisRunPublic,
  ProjectDecisionSummaryPublic,
  ProviderStatusPublic,
} from "@/api-client"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  VpwSurface,
  VpwSurfaceBody,
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
  staleProvider,
}: DashboardSidePanelProps) {
  return (
    <div className="space-y-3">
      <VpwSurface className="gap-3 py-4">
        <VpwSurfaceHeader className="pb-0 px-4">
          <VpwSurfaceTitle className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
            Provider Freshness
          </VpwSurfaceTitle>
        </VpwSurfaceHeader>
        <VpwSurfaceBody className="space-y-2 px-4">
          <div className="flex items-center gap-2">
            <ProviderStatusBadge
              status={
                effectiveProviderStatus?.status ??
                (providerStatusLoading ? "loading" : "unknown")
              }
            />
            <span className="text-sm font-bold">{freshness.value}</span>
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            {freshness.detail}
          </p>
          {providerStatusLoading && <Skeleton className="h-4 w-32" />}
        </VpwSurfaceBody>
      </VpwSurface>

      <VpwSurface className="gap-3 py-4">
        <VpwSurfaceHeader className="pb-0 px-4">
          <VpwSurfaceTitle className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
            Evidence Readiness
          </VpwSurfaceTitle>
        </VpwSurfaceHeader>
        <VpwSurfaceBody className="px-4">
          <dl className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">Latest run</dt>
              <dd className="max-w-32.5 truncate text-right text-xs font-medium">
                {latestRunLabel(latestRun)}
              </dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">Findings</dt>
              <dd className="font-semibold">
                {effectiveSummary?.finding_count ?? 0}
              </dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">Runs</dt>
              <dd className="font-semibold">{effectiveRuns.length}</dd>
            </div>
            <div className="flex items-center justify-between border-t pt-2">
              <dt className="text-muted-foreground">Evidence quality</dt>
              <dd>
                <Badge
                  className="text-xs"
                  variant={staleProvider ? "destructive" : "secondary"}
                >
                  {staleProvider ? "Needs sync" : "Healthy"}
                </Badge>
              </dd>
            </div>
          </dl>
        </VpwSurfaceBody>
      </VpwSurface>

      <VpwSurface className="gap-3 py-4">
        <VpwSurfaceHeader className="pb-0 px-4">
          <VpwSurfaceTitle className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
            Data Quality
          </VpwSurfaceTitle>
        </VpwSurfaceHeader>
        <VpwSurfaceBody className="px-4">
          {dataQualityWarnings.length === 0 && !dataQualityError ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <CheckCircle2 className="size-3.5 shrink-0 text-green-500" />
              <span>No data quality issues detected.</span>
            </div>
          ) : (
            <ul className="space-y-2">
              {dataQualityWarnings.map((warning) => (
                <li className="flex gap-2 text-xs" key={warning}>
                  <AlertCircle
                    aria-hidden="true"
                    className="mt-0.5 size-3.5 shrink-0 text-amber-500"
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
                    className="mt-0.5 size-3.5 shrink-0 text-red-500"
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

      <VpwSurface className="gap-3 py-4">
        <VpwSurfaceHeader className="pb-0 px-4">
          <VpwSurfaceTitle className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
            Recent Runs
          </VpwSurfaceTitle>
        </VpwSurfaceHeader>
        <VpwSurfaceBody className="px-4">
          {latestRunFactsRows.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No analysis runs yet.
            </p>
          ) : (
            <div className="space-y-2">
              {latestRunFactsRows.map((run) => (
                <div
                  className="flex items-center justify-between gap-2 rounded-md border bg-muted/20 px-2.5 py-2 text-xs"
                  key={run.id}
                >
                  <Badge
                    className="shrink-0"
                    variant={
                      run.tone === "succeeded" ? "secondary" : "destructive"
                    }
                  >
                    {run.status}
                  </Badge>
                  <span className="truncate text-muted-foreground">
                    {run.startedAt}
                  </span>
                </div>
              ))}
            </div>
          )}
          <Button asChild className="mt-3 w-full" size="sm" variant="outline">
            <Link to="/imports">View all imports</Link>
          </Button>
        </VpwSurfaceBody>
      </VpwSurface>
    </div>
  )
}
