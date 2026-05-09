import { Link } from "@tanstack/react-router"
import { Activity } from "lucide-react"

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

type ProvidersHeroProps = ProvidersWorkbenchProps

type ProviderStatusAlertsProps = Pick<
  ProvidersWorkbenchProps,
  "providerStatusError" | "providerStatusLoading"
>

export function ProvidersHero({
  onRefreshProviderStatus,
  providerStatus,
  providerStatusLoading,
}: ProvidersHeroProps) {
  const evidenceReadiness = evidenceReadinessLabel(providerStatus)

  return (
    <VpwSection>
      <VpwPanel className="space-y-5 p-5">
        <VpwSectionHeader
          description="Monitor vulnerability intelligence sources, snapshot freshness and evidence data quality."
          eyebrow="Provider intelligence"
          title="Providers"
        />
        <VpwToolbar label="Provider actions">
          <VpwToolbarGroup>
            <Button
              aria-busy={providerStatusLoading}
              disabled={providerStatusLoading}
              onClick={onRefreshProviderStatus}
              type="button"
            >
              <Activity aria-hidden="true" />
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
  providerStatusError,
  providerStatusLoading,
}: ProviderStatusAlertsProps) {
  return (
    <>
      {providerStatusError ? (
        <VpwStatusBanner title="Provider data unavailable" tone="critical">
          {providerStatusError}
        </VpwStatusBanner>
      ) : null}

      {providerStatusLoading ? (
        <VpwPanel className="p-5">
          <VpwSkeletonStack rows={5} />
        </VpwPanel>
      ) : null}
    </>
  )
}
