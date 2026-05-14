import { GitBranch } from "lucide-react"

import type { ProviderStatusPublic } from "@/api-client"
import {
  VpwEmptyState,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { formatCacheAge } from "@/lib/provider-format"
import {
  evidenceReadinessTone,
  formatDateTime,
} from "./providers-workbench-model"

function ProviderUpdateJobPanel({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  return (
    <VpwPanel className="flex flex-col gap-4 p-5">
      <VpwSectionHeader
        description="Latest provider update-job state from the existing provider status response."
        eyebrow="Update job"
        title="Latest provider update"
      />
      {providerStatus?.latest_update_job ? (
        <VpwKeyValueList
          columns={2}
          items={[
            { label: "Job ID", value: providerStatus.latest_update_job.id },
            {
              label: "Status",
              value: providerStatus.latest_update_job.status,
              tone:
                providerStatus.latest_update_job.status === "failed"
                  ? "critical"
                  : "info",
            },
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
            {
              label: "Error",
              value: providerStatus.latest_update_job.error_message ?? "None",
            },
            {
              label: "Metadata",
              value: providerStatus.latest_update_job.metadata
                ? Object.keys(providerStatus.latest_update_job.metadata).join(
                    ", ",
                  ) || "Recorded"
                : "Not recorded",
            },
          ]}
        />
      ) : (
        <VpwEmptyState
          description="The current provider status response has no update-job history."
          icon={<GitBranch aria-hidden="true" />}
          title="No provider update job recorded"
        />
      )}
      <VpwProgress
        label="Evidence readiness"
        tone={evidenceReadinessTone(providerStatus)}
        value={providerStatus?.last_error ? 35 : providerStatus ? 86 : 20}
      />
    </VpwPanel>
  )
}

export function ProviderDiagnosticsSection({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  const sourceErrors = (providerStatus?.sources ?? []).filter(
    (source) => source.last_error,
  )

  return (
    <VpwGrid columns={2}>
      <ProviderUpdateJobPanel providerStatus={providerStatus} />
      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          description="Runtime provider facts from the current stored status response."
          eyebrow="Diagnostics"
          title="Provider runtime facts"
        />
        <VpwKeyValueList
          columns={2}
          items={[
            {
              label: "Overall status",
              value: providerStatus?.status ?? "Not recorded",
              tone: providerStatus?.status === "ok" ? "success" : "warning",
            },
            {
              label: "Snapshot mode",
              value: providerStatus?.snapshot_mode ?? "missing",
            },
            {
              label: "Last sync",
              value: formatDateTime(providerStatus?.last_sync),
            },
            {
              label: "Warnings",
              value: providerStatus?.warnings?.length ?? 0,
              tone:
                (providerStatus?.warnings?.length ?? 0) > 0
                  ? "warning"
                  : "success",
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
        {sourceErrors.length > 0 ? (
          <div className="flex flex-col gap-3">
            {sourceErrors.map((source) => (
              <VpwStatusBanner
                key={`${source.name}-${source.last_error}`}
                title={`${source.name.toUpperCase()} source error`}
                tone="critical"
              >
                {source.last_error}
              </VpwStatusBanner>
            ))}
          </div>
        ) : null}
      </VpwPanel>
    </VpwGrid>
  )
}
