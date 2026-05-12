import type { ProviderStatusPublic } from "@/api-client"
import {
  VpwChecksum,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwProviderSnapshotCard,
  VpwSectionHeader,
} from "@/components/vpw"
import {
  formatDateTime,
  type ProviderSourceRow,
  selectedSources,
  snapshotId,
  snapshotSources,
  sourceHashes,
} from "./providers-workbench-model"

type ProviderSnapshotDetailsProps = {
  onRefreshProviderStatus: () => void
  providerStatus: ProviderStatusPublic | null
  rows: readonly ProviderSourceRow[]
}

export function ProviderSnapshotDetails({
  onRefreshProviderStatus,
  providerStatus,
  rows,
}: ProviderSnapshotDetailsProps) {
  const snapshotChecksum =
    providerStatus?.snapshot.content_hash ?? "No content hash recorded"

  return (
    <VpwGrid columns={2}>
      <VpwProviderSnapshotCard
        onRefresh={onRefreshProviderStatus}
        refreshLabel="Refresh providers"
        snapshotId={snapshotId(providerStatus)}
        sources={snapshotSources(rows)}
      />

      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          description="Snapshot metadata used to make evidence bundles reproducible."
          eyebrow="Snapshot details"
          title="Recorded snapshot"
        />
        <VpwChecksum
          label="Content hash"
          value={snapshotChecksum}
          verified={Boolean(providerStatus?.snapshot.content_hash)}
        />
        <VpwKeyValueList
          columns={2}
          items={[
            {
              label: "Snapshot ID",
              value: snapshotId(providerStatus),
            },
            {
              label: "Mode",
              value: providerStatus?.snapshot.mode ?? "missing",
              tone: providerStatus?.snapshot.locked_provider_data
                ? "support"
                : "info",
            },
            {
              label: "Generated",
              value: formatDateTime(
                providerStatus?.snapshot.generated_at ??
                  providerStatus?.snapshot.created_at,
              ),
            },
            {
              label: "Requested CVEs",
              value: providerStatus?.snapshot.requested_cves ?? 0,
            },
            {
              label: "Selected sources",
              value: selectedSources(providerStatus),
            },
            {
              label: "Source path",
              value: providerStatus?.snapshot.source_path ?? "Not recorded",
            },
            {
              label: "NVD last sync",
              value: formatDateTime(providerStatus?.snapshot.nvd_last_sync),
            },
            {
              label: "EPSS date",
              value: providerStatus?.snapshot.epss_date ?? "Not recorded",
            },
            {
              label: "KEV catalog",
              value:
                providerStatus?.snapshot.kev_catalog_version ?? "Not recorded",
            },
            {
              label: "Source hashes",
              value: sourceHashes(providerStatus),
            },
          ]}
        />
      </VpwPanel>
    </VpwGrid>
  )
}
