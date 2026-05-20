import type { ProviderStatusPublic } from "@/api-client"
import {
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { formatCacheAge } from "@/lib/provider-format"
import {
  evidenceReadinessExplanation,
  evidenceReadinessScore,
  evidenceReadinessTone,
  formatDateTime,
  providerAgeLabel,
  providerFreshnessLabel,
  providerFreshnessThresholdLabel,
  providerHealthLabel,
  sourceDisplayName,
  snapshotModeLabel,
} from "./providers-workbench-model"

export function ProviderDiagnosticsSection({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  const warnings = providerStatus?.warnings ?? []
  const sourceErrors = (providerStatus?.sources ?? []).filter(
    (source) => source.last_error,
  )
  const errorsCount =
    (providerStatus?.last_error ? 1 : 0) + sourceErrors.length
  const readinessScore = evidenceReadinessScore(providerStatus)

  return (
    <VpwSection>
      <VpwGrid columns={2}>
        <VpwPanel className="flex flex-col gap-4 p-5">
          <VpwSectionHeader
            description="Operational provider state from the stored local status response."
            eyebrow="Runtime status"
            title="Runtime facts"
          />
          <VpwKeyValueList
            columns={2}
            items={[
              {
                label: "Overall status",
                value: providerHealthLabel(providerStatus),
                tone:
                  providerStatus?.status === "ok" ? "success" : "warning",
              },
              {
                label: "Snapshot mode",
                value: snapshotModeLabel(providerStatus),
              },
              {
                label: "Last sync",
                value: formatDateTime(providerStatus?.last_sync),
              },
              {
                label: "Age",
                value: providerAgeLabel(providerStatus),
              },
              {
                label: "Freshness threshold",
                value: providerFreshnessThresholdLabel(),
              },
              {
                label: "Freshness status",
                value: providerFreshnessLabel(providerStatus),
                tone:
                  providerFreshnessLabel(providerStatus) === "Fresh"
                    ? "success"
                    : "warning",
              },
              {
                label: "Last error",
                value: providerStatus?.last_error ?? "None",
                tone: providerStatus?.last_error ? "critical" : "success",
              },
              {
                label: "Cache age",
                value: formatCacheAge(providerStatus?.cache_age_seconds),
              },
              {
                label: "Cache directory",
                value: providerStatus?.cache_dir ?? "Not recorded",
              },
              {
                label: "Snapshot directory",
                value: providerStatus?.snapshot_dir ?? "Not recorded",
              },
            ]}
          />
        </VpwPanel>

        <VpwPanel className="flex flex-col gap-4 p-5">
          <VpwSectionHeader
            description="Latest status check and warning/error counts from stored provider state."
            eyebrow="Last provider status check"
            title="Status check"
          />
          <VpwKeyValueList
            columns={2}
            items={[
              {
                label: "Checked at",
                value: formatDateTime(
                  providerStatus?.latest_update_job?.finished_at ??
                    providerStatus?.last_sync,
                ),
              },
              {
                label: "Result",
                value:
                  providerStatus?.latest_update_job?.status ??
                  providerHealthLabel(providerStatus),
                tone: errorsCount > 0 ? "critical" : "success",
              },
              {
                label: "Warnings",
                value: warnings.length,
                tone: warnings.length > 0 ? "warning" : "success",
              },
              {
                label: "Errors",
                value: errorsCount,
                tone: errorsCount > 0 ? "critical" : "success",
              },
            ]}
          />
          {providerStatus?.latest_update_job ? (
            <VpwKeyValueList
              columns={2}
              items={[
                { label: "Job ID", value: providerStatus.latest_update_job.id },
                {
                  label: "Requested sources",
                  value:
                    providerStatus.latest_update_job.requested_sources?.join(
                      ", ",
                    ) ?? "Not recorded",
                },
                {
                  label: "Started",
                  value: formatDateTime(
                    providerStatus.latest_update_job.started_at,
                  ),
                },
                {
                  label: "Finished",
                  value: formatDateTime(
                    providerStatus.latest_update_job.finished_at,
                  ),
                },
              ]}
            />
          ) : (
            <VpwStatusBanner
              title="No provider update job recorded"
              tone="info"
            >
              The current provider state was read from the stored local provider
              status.
            </VpwStatusBanner>
          )}
          {providerStatus?.latest_update_job?.error_message ? (
            <VpwStatusBanner title="Provider update job error" tone="critical">
              {providerStatus.latest_update_job.error_message}
            </VpwStatusBanner>
          ) : null}
        </VpwPanel>
      </VpwGrid>

      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          description="Whether provider metadata can be attached to reproducible evidence bundles."
          eyebrow="Evidence readiness"
          title="Evidence readiness"
        />
        <VpwProgress
          label="Evidence readiness"
          tone={evidenceReadinessTone(providerStatus)}
          value={readinessScore}
        />
        <p className="text-sm leading-6 text-[var(--vpw-text-secondary)]">
          Evidence readiness: {readinessScore}%.{" "}
          {evidenceReadinessExplanation(providerStatus)}
        </p>
        {warnings.length > 0 ? (
          <div className="flex flex-col gap-3">
            {warnings.map((warning) => (
              <VpwStatusBanner key={warning} title="Provider warning" tone="warning">
                {warning}
              </VpwStatusBanner>
            ))}
          </div>
        ) : null}
        {sourceErrors.length > 0 ? (
          <div className="flex flex-col gap-3">
            {sourceErrors.map((source) => (
              <VpwStatusBanner
                key={`${source.name}-${source.last_error}`}
                title={`${sourceDisplayName(source.name)} source error`}
                tone="critical"
              >
                {source.last_error}
              </VpwStatusBanner>
            ))}
          </div>
        ) : null}
      </VpwPanel>

      <VpwPanel className="p-5">
        <details className="group">
          <summary className="cursor-pointer text-sm font-semibold text-[var(--vpw-text-primary)]">
            Raw diagnostics
          </summary>
          <pre className="mt-4 max-h-96 overflow-auto rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] p-4 text-xs leading-5 text-[var(--vpw-text-secondary)]">
            {JSON.stringify(providerStatus, null, 2)}
          </pre>
        </details>
      </VpwPanel>
    </VpwSection>
  )
}
