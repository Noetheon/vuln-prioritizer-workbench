import { Link } from "@/lib/router"
import { Activity, FileText } from "lucide-react"
import type { ProviderStatusPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  MetaTag,
  StatusLozenge,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  evidenceReadinessLabel,
  providerFreshnessLabel,
  providerHealthLabel,
  type ProvidersWorkbenchProps,
  snapshotModeLabel,
  warningSummary,
} from "./providers-workbench-model"

type ProviderStatusAlertsProps = Pick<
  ProvidersWorkbenchProps,
  "providerStatusError" | "providerStatusLoading"
> & {
  providerStatus: ProviderStatusPublic | null
}

export function ProvidersHero({
  onRefreshProviderStatus,
  providerStatus,
  providerStatusLoading,
  selectedProjectId,
}: ProvidersWorkbenchProps) {
  const evidenceReadiness = evidenceReadinessLabel(providerStatus)
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)

  return (
    <VpwSection>
      <VpwPanel className="flex flex-col gap-5 p-5">
        <VpwSectionHeader
          description="Monitor vulnerability intelligence sources, provider snapshot freshness, and evidence data quality."
          eyebrow="Data source trust"
          title="Provider trust status"
        />
        <VpwToolbar label="Provider actions" variant="plain">
          <VpwToolbarGroup>
            <Button
              aria-busy={providerStatusLoading}
              disabled={providerStatusLoading}
              onClick={onRefreshProviderStatus}
              type="button"
            >
              <Activity aria-hidden="true" data-icon="inline-start" />
              Refresh status
            </Button>
            <Button asChild variant="outline">
              <Link search={projectSearch} to="/reports">
                <FileText aria-hidden="true" data-icon="inline-start" />
                Open Evidence Center
              </Link>
            </Button>
          </VpwToolbarGroup>
        </VpwToolbar>
        <p className="max-w-3xl text-sm leading-6 text-[var(--vpw-text-secondary)]">
          Evidence Center uses recorded provider snapshots and report artifacts
          for reproducible review. Refresh status reloads stored provider state
          from the backend; it does not scan systems.
        </p>
        <VpwToolbar label="Provider trust summary" variant="plain">
          <VpwToolbarGroup>
            <MetaTag label="Provider data" />
            <StatusLozenge
              label={`Health: ${providerHealthLabel(providerStatus)}`}
              status={providerHealthLabel(providerStatus)}
            />
            <StatusLozenge
              label={`Freshness: ${providerFreshnessLabel(providerStatus)}`}
              status={providerFreshnessLabel(providerStatus)}
            />
            <StatusLozenge
              label={`Snapshot: ${snapshotModeLabel(providerStatus)}`}
              status={
                providerStatus?.snapshot.locked_provider_data
                  ? "ready"
                  : "open"
              }
            />
            <StatusLozenge
              label={`Evidence: ${evidenceReadiness}`}
              status={evidenceReadiness === "Ready" ? "ready" : "review_due"}
            />
            <StatusLozenge
              label={`Warnings: ${warningSummary(providerStatus)}`}
              status={
                providerStatus?.last_error
                  ? "failed"
                  : (providerStatus?.warnings?.length ?? 0) > 0
                    ? "review_due"
                    : "ready"
              }
            />
          </VpwToolbarGroup>
        </VpwToolbar>
      </VpwPanel>
    </VpwSection>
  )
}

export function ProviderStatusAlerts({
  providerStatus,
  providerStatusError,
  providerStatusLoading,
}: ProviderStatusAlertsProps) {
  const providerWarnings = providerStatus?.warnings ?? []

  return (
    <>
      {providerStatusError ? (
        <VpwStatusBanner title="Provider data unavailable" tone="critical">
          {providerStatusError}
        </VpwStatusBanner>
      ) : null}

      {!providerStatusError && providerStatus?.last_error ? (
        <VpwStatusBanner title="Provider update failed" tone="critical">
          {providerStatus.last_error}
        </VpwStatusBanner>
      ) : null}

      {!providerStatusError &&
      !providerStatus?.last_error &&
      providerStatus &&
      providerStatus.status !== "ok" ? (
        <VpwStatusBanner title="Provider status degraded" tone="warning">
          Current status is {providerStatus.status}. Prioritization can
          continue, but evidence freshness should be reviewed.
        </VpwStatusBanner>
      ) : null}

      {providerWarnings.map((warning) => (
        <VpwStatusBanner key={warning} title="Provider warning" tone="warning">
          {warning}
        </VpwStatusBanner>
      ))}

      {providerStatusLoading ? (
        <VpwPanel className="p-5">
          <VpwSkeletonStack rows={5} />
        </VpwPanel>
      ) : null}
    </>
  )
}
