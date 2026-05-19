import {
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { shortId, type WaiversWorkbenchProps } from "./waivers-workbench-model"

export function WaiversWorkbenchCreateGuidance({
  completeness,
  projectSummary,
  reviewDue,
  selectedProject,
}: Pick<WaiversWorkbenchProps, "projectSummary" | "selectedProject"> & {
  completeness: number
  reviewDue: string
}) {
  return (
    <VpwPanel className="flex flex-col gap-5 p-5">
      <VpwSectionHeader
        description="Accepted risk remains visible in prioritization and evidence."
        eyebrow="Safety rules"
        title="Governance guidance"
      />
      <VpwStatusBanner
        title="Owner, reason and expiry are required"
        tone="warning"
      >
        Waivers should document why risk is accepted and when it must be
        revisited.
      </VpwStatusBanner>
      <VpwStatusBanner title="Accepted risk stays visible" tone="info">
        Reports should continue to show accepted findings instead of hiding them
        silently.
      </VpwStatusBanner>
      <VpwStatusBanner
        title="Critical findings still need review"
        tone="critical"
      >
        A waiver is an explicit decision record, not a remediation replacement.
      </VpwStatusBanner>
      <VpwKeyValueList
        columns={2}
        items={[
          {
            label: "Active project",
            value: selectedProject?.name ?? "No project",
          },
          {
            label: "Latest run",
            value: projectSummary?.latest_run_id
              ? shortId(projectSummary.latest_run_id)
              : "No run yet",
          },
          {
            label: "Evidence completeness",
            value: `${completeness}%`,
            tone: completeness >= 80 ? "success" : "warning",
          },
          {
            label: "Review due",
            value: reviewDue,
            tone: Number(reviewDue) > 0 ? "warning" : "neutral",
          },
        ]}
      />
      <VpwProgress
        label="Approval evidence coverage"
        tone={completeness >= 80 ? "success" : "warning"}
        value={completeness}
      />
    </VpwPanel>
  )
}
