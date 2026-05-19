import type { ProviderStatusPublic } from "@/api-client"
import {
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { formatCacheAge } from "@/lib/provider-format"
import { formatDateTime } from "./providers-workbench-model"

export function ProviderRuntimeFactsPanel({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  const sourceErrors = (providerStatus?.sources ?? []).filter(
    (source) => source.last_error,
  )

  return (
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
  )
}
