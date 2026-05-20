import { Check, Copy } from "lucide-react"
import type { ReactNode } from "react"
import { useState } from "react"

import type { ProviderStatusPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  StatusLozenge,
  VpwChecksum,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import {
  formatDateTime,
  type ProviderSourceRow,
  redactedSourcePath,
  selectedSources,
  snapshotId,
  snapshotModeLabel,
  snapshotVerificationLabel,
  sourceHashes,
} from "./providers-workbench-model"

type ProviderSnapshotDetailsProps = {
  onRefreshProviderStatus: () => void
  providerStatus: ProviderStatusPublic | null
  rows: readonly ProviderSourceRow[]
}

function SummaryItem({
  label,
  value,
}: {
  label: string
  value: ReactNode
}) {
  return (
    <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2.5">
      <p className="vpw-label">{label}</p>
      <div className="mt-1 min-w-0 text-sm font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]">
        {value}
      </div>
    </div>
  )
}

export function ProviderSnapshotDetails({
  onRefreshProviderStatus,
  providerStatus,
  rows,
}: ProviderSnapshotDetailsProps) {
  const [copied, setCopied] = useState(false)
  const currentSnapshotId = snapshotId(providerStatus)
  const snapshotChecksum =
    providerStatus?.snapshot.content_hash ?? "No content hash recorded"
  const generatedAt =
    providerStatus?.snapshot.generated_at ?? providerStatus?.snapshot.created_at
  const verification = snapshotVerificationLabel(providerStatus)

  function copySnapshotId() {
    void navigator.clipboard?.writeText(currentSnapshotId)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }

  return (
    <VpwSection>
      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          actions={
            <div className="flex flex-wrap gap-2">
              <Button onClick={copySnapshotId} type="button" variant="outline">
                {copied ? (
                  <Check aria-hidden="true" data-icon="inline-start" />
                ) : (
                  <Copy aria-hidden="true" data-icon="inline-start" />
                )}
                {copied ? "Copied ID" : "Copy ID"}
              </Button>
              <Button
                onClick={onRefreshProviderStatus}
                type="button"
                variant="outline"
              >
                Refresh status
              </Button>
            </div>
          }
          description="Recorded provider snapshot used for deterministic and reproducible evidence."
          eyebrow="Snapshot"
          title="Snapshot audit summary"
        />
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
          <SummaryItem label="Snapshot ID" value={currentSnapshotId} />
          <SummaryItem
            label="Mode"
            value={
              <StatusLozenge
                label={snapshotModeLabel(providerStatus)}
                status={
                  providerStatus?.snapshot.locked_provider_data
                    ? "ready"
                    : "open"
                }
              />
            }
          />
          <SummaryItem label="Generated" value={formatDateTime(generatedAt)} />
          <SummaryItem label="Selected sources" value={selectedSources(providerStatus)} />
          <SummaryItem
            label="Verification"
            value={
              <StatusLozenge
                label={verification}
                status={verification === "Verified" ? "succeeded" : "unknown"}
              />
            }
          />
        </div>
      </VpwPanel>

      <VpwGrid columns={2}>
        <VpwPanel className="flex flex-col gap-4 p-5">
          <VpwSectionHeader
            description="Audit fields recorded with the provider snapshot."
            eyebrow="Recorded snapshot details"
            title="Reproducibility record"
          />
          <VpwChecksum
            label="Content hash"
            value={snapshotChecksum}
            verified={Boolean(providerStatus?.snapshot.content_hash)}
          />
          <VpwKeyValueList
            columns={2}
            items={[
              { label: "Snapshot ID", value: currentSnapshotId },
              {
                label: "Generated time",
                value: formatDateTime(generatedAt),
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
                label: "Source hashes",
                value: sourceHashes(providerStatus),
              },
              {
                label: "Recorded sources",
                value: rows.map((row) => row.name).join(", "),
              },
            ]}
          />
        </VpwPanel>

        <VpwPanel className="flex flex-col gap-4 p-5">
          <VpwSectionHeader
            description="Local cache and source locations from the stored provider status."
            eyebrow="Cache and source paths"
            title="Provider cache paths"
          />
          <VpwKeyValueList
            columns={2}
            items={[
              {
                label: "Cache directory",
                value: providerStatus?.cache_dir ?? "Not recorded",
              },
              {
                label: "Snapshot directory",
                value: providerStatus?.snapshot_dir ?? "Not recorded",
              },
              {
                label: "Source path redacted",
                value: redactedSourcePath(providerStatus?.snapshot.source_path),
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
                label: "KEV catalog date",
                value:
                  providerStatus?.snapshot.kev_catalog_version ??
                  "Not recorded",
              },
            ]}
          />
        </VpwPanel>
      </VpwGrid>

      <VpwStatusBanner title="Snapshot replay boundary" tone="info">
        {providerStatus?.snapshot.locked_provider_data
          ? "Locked snapshot mode means provider replay is deterministic. Live provider lookups are disabled for this snapshot."
          : "Locked snapshots make evidence bundles reproducible. Live provider lookups are not used for locked snapshots."}
      </VpwStatusBanner>
    </VpwSection>
  )
}
