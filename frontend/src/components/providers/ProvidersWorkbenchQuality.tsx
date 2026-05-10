import { GitBranch } from "lucide-react"

import type { ProviderStatusPublic } from "@/api-client"
import {
  VpwEmptyState,
  VpwEvidenceFlowCard,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { providerDataQualityNotes } from "@/lib/provider-format"
import {
  buildProviderEvidenceFlowItems,
  evidenceReadinessLabel,
  evidenceReadinessTone,
  formatDateTime,
  type ProviderSourceCounts,
} from "./providers-workbench-model"

type ProviderDataQualitySectionProps = {
  counts: ProviderSourceCounts
  providerStatus: ProviderStatusPublic | null
}

function ProviderDataQualityNotes({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  return (
    <VpwPanel className="flex flex-col gap-4 p-5">
      <VpwSectionHeader
        description="Structured trust notes for prioritization and reporting."
        eyebrow="Data quality"
        title="Provider data quality notes"
      />
      <div className="flex flex-col gap-3">
        <VpwStatusBanner title="CVSS coverage" tone="info">
          Missing CVSS does not mean low risk; it is a provider data gap.
        </VpwStatusBanner>
        <VpwStatusBanner title="EPSS coverage" tone="warning">
          Missing EPSS should be treated as incomplete exploit-probability
          evidence, not as zero likelihood.
        </VpwStatusBanner>
        <VpwStatusBanner title="KEV signal" tone="critical">
          KEV is a strong prioritization signal when present.
        </VpwStatusBanner>
        <VpwStatusBanner title="Locked snapshots" tone="success">
          Locked snapshots are used for reproducible evidence bundles and
          executive reports.
        </VpwStatusBanner>
        {providerDataQualityNotes(providerStatus).map((note) => (
          <VpwStatusBanner key={note} title="Snapshot note" tone="info">
            {note}
          </VpwStatusBanner>
        ))}
        {(providerStatus?.warnings ?? []).map((warning) => (
          <VpwStatusBanner
            key={warning}
            title="Provider warning"
            tone="warning"
          >
            {warning}
          </VpwStatusBanner>
        ))}
        {providerStatus?.last_error ? (
          <VpwStatusBanner title="Last provider error" tone="critical">
            {providerStatus.last_error}
          </VpwStatusBanner>
        ) : null}
      </div>
    </VpwPanel>
  )
}

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
            {
              label: "Job ID",
              value: providerStatus.latest_update_job.id,
            },
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
                ) ?? "N.A.",
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

export function ProviderDataQualitySection({
  counts,
  providerStatus,
}: ProviderDataQualitySectionProps) {
  const evidenceReadiness = evidenceReadinessLabel(providerStatus)
  const evidenceFlowItems = buildProviderEvidenceFlowItems({
    availableSources: counts.availableSources,
    evidenceReadiness,
    missingSources: counts.missingSources,
    providerStatus,
  })

  return (
    <VpwGrid columns={2}>
      <ProviderDataQualityNotes providerStatus={providerStatus} />

      <div className="flex flex-col gap-4">
        <VpwEvidenceFlowCard items={evidenceFlowItems} />
        <ProviderUpdateJobPanel providerStatus={providerStatus} />
      </div>
    </VpwGrid>
  )
}
