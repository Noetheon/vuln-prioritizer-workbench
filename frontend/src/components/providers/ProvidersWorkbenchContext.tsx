import { Link } from "@/lib/router"
import {
  Activity,
  AlertTriangle,
  Database,
  FileCheck2,
  FileText,
  LockKeyhole,
  Signal,
} from "lucide-react"
import type { ReactNode } from "react"
import type { ProviderStatusPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwCommandPanel,
  MetricStrip,
  type MetricStripMetric,
  type VpwCompactTone,
  VpwPanel,
  VpwSection,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  evidenceReadinessLabel,
  evidenceReadinessCardTone,
  providerFreshnessLabel,
  providerFreshnessTone,
  providerHealthLabel,
  providerHealthTone,
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

function ProviderContextItem({
  detail,
  icon,
  label,
  tone,
  value,
}: {
  detail: string
  icon: ReactNode
  label: string
  tone: VpwCompactTone
  value: string
}): MetricStripMetric {
  return {
    description: detail,
    icon,
    label,
    tone,
    value,
  }
}

export function ProvidersContext({
  onRefreshProviderStatus,
  providerStatus,
  providerStatusLoading,
  selectedProjectId,
}: ProvidersWorkbenchProps) {
  const evidenceReadiness = evidenceReadinessLabel(providerStatus)
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const warningCount = providerStatus?.warnings?.length ?? 0
  const snapshotTone: VpwCompactTone = providerStatus?.snapshot
    .locked_provider_data
    ? "support"
    : "info"
  const metrics: MetricStripMetric[] = [
    ProviderContextItem({
      detail: "Provider signals for prioritization",
      icon: <Signal aria-hidden="true" />,
      label: "Provider health",
      tone: providerHealthTone(providerStatus),
      value: providerHealthLabel(providerStatus),
    }),
    ProviderContextItem({
      detail: "Stored cache age and sync state",
      icon: <Database aria-hidden="true" />,
      label: "Freshness",
      tone: providerFreshnessTone(providerStatus),
      value: providerFreshnessLabel(providerStatus),
    }),
    ProviderContextItem({
      detail: "Replay behavior for reports",
      icon: <LockKeyhole aria-hidden="true" />,
      label: "Snapshot",
      tone: snapshotTone,
      value: snapshotModeLabel(providerStatus),
    }),
    ProviderContextItem({
      detail: "Report artifact metadata",
      icon: <FileCheck2 aria-hidden="true" />,
      label: "Evidence readiness",
      tone: evidenceReadinessCardTone(providerStatus),
      value: evidenceReadiness,
    }),
    ProviderContextItem({
      detail: "Source warnings and update errors",
      icon: <AlertTriangle aria-hidden="true" />,
      label: "Warnings",
      tone: providerStatus?.last_error
        ? "critical"
        : warningCount > 0
          ? "warning"
          : "success",
      value: warningSummary(providerStatus),
    }),
  ]

  return (
    <VpwSection>
      <VpwCommandPanel
        className="providers-context-panel"
        actions={
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
        }
        description="Monitor vulnerability intelligence sources, provider snapshot freshness, and evidence data quality."
        eyebrow="Data source trust"
        title="Provider status"
      >
        <MetricStrip
          className="providers-context-strip"
          metrics={metrics}
          minCardWidth="13rem"
        />
      </VpwCommandPanel>
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
