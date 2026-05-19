import { GitBranch } from "lucide-react"

import type { ProviderStatusPublic } from "@/api-client"
import {
  VpwEmptyState,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSectionHeader,
} from "@/components/vpw"
import {
  evidenceReadinessTone,
  formatDateTime,
} from "./providers-workbench-model"

export function ProviderUpdateJobPanel({
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
