import { Link } from "@tanstack/react-router"
import { Activity } from "lucide-react"

import type { ProviderStatusPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { providerSnapshotHealth } from "@/lib/provider-format"
import {
  evidenceReadinessLabel,
  evidenceReadinessTone,
  formatDateTime,
  type ProvidersWorkbenchProps,
  providerHealthTone,
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
}: ProvidersWorkbenchProps) {
  const evidenceReadiness = evidenceReadinessLabel(providerStatus)

  return (
    <VpwSection>
      <VpwPanel className="flex flex-col gap-5 p-5">
        <VpwSectionHeader
          description="Monitor vulnerability intelligence sources, snapshot freshness and evidence data quality."
          eyebrow="Provider intelligence"
          title="Providers"
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
              Refresh providers
            </Button>
            <Button asChild variant="outline">
              <Link to="/reports">View Evidence Center</Link>
            </Button>
          </VpwToolbarGroup>
          <VpwToolbarGroup>
            <VpwBadge tone={providerHealthTone(providerStatus)}>
              Snapshot mode: {providerStatus?.snapshot_mode ?? "missing"}
            </VpwBadge>
            <VpwBadge tone="neutral">
              Last sync: {formatDateTime(providerStatus?.last_sync)}
            </VpwBadge>
            <VpwBadge tone={providerHealthTone(providerStatus)}>
              Provider health: {providerSnapshotHealth(providerStatus)}
            </VpwBadge>
            <VpwBadge tone={evidenceReadinessTone(providerStatus)}>
              Evidence: {evidenceReadiness}
            </VpwBadge>
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
