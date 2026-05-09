import { Link } from "@tanstack/react-router"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import {
  VpwField,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { shortId, type WaiversWorkbenchProps } from "./waivers-workbench-model"

export function CreateWaiverSection({
  completeness,
  onCreateWaiver,
  onFieldChange,
  projectListLoading,
  projectSummary,
  projects,
  reviewDue,
  selectedProject,
  waiverActionLoading,
  waiverForm,
}: Pick<
  WaiversWorkbenchProps,
  | "onCreateWaiver"
  | "onFieldChange"
  | "projectListLoading"
  | "projectSummary"
  | "projects"
  | "selectedProject"
  | "waiverActionLoading"
  | "waiverForm"
> & {
  completeness: number
  reviewDue: string
}) {
  return (
    <VpwGrid columns={2}>
      <div id="create-waiver">
        <VpwPanel className="space-y-5 p-5">
          <VpwSectionHeader
            description="Create an accepted-risk decision only when remediation cannot happen immediately."
            eyebrow="Governance form"
            title="Create waiver"
          />
          <form className="space-y-5" onSubmit={onCreateWaiver}>
            <VpwGrid columns={2}>
              <VpwField htmlFor="waiver-cve-id" label="CVE ID">
                <Input
                  aria-label="Waiver CVE ID"
                  id="waiver-cve-id"
                  onChange={(event) =>
                    onFieldChange("cveId", event.target.value)
                  }
                  placeholder="CVE-2024-3094"
                  value={waiverForm.cveId}
                />
              </VpwField>
              <VpwField htmlFor="waiver-finding-id" label="Finding ID">
                <Input
                  aria-label="Waiver finding ID"
                  id="waiver-finding-id"
                  onChange={(event) =>
                    onFieldChange("findingId", event.target.value)
                  }
                  placeholder="Optional UUID"
                  value={waiverForm.findingId}
                />
              </VpwField>
              <VpwField htmlFor="waiver-asset-key" label="Asset key">
                <Input
                  aria-label="Waiver asset key"
                  id="waiver-asset-key"
                  onChange={(event) =>
                    onFieldChange("assetKey", event.target.value)
                  }
                  placeholder="payments-api"
                  value={waiverForm.assetKey}
                />
              </VpwField>
              <VpwField htmlFor="waiver-service" label="Service">
                <Input
                  aria-label="Waiver service"
                  id="waiver-service"
                  onChange={(event) =>
                    onFieldChange("service", event.target.value)
                  }
                  placeholder="checkout"
                  value={waiverForm.service}
                />
              </VpwField>
              <VpwField htmlFor="waiver-asset-id" label="Asset ID">
                <Input
                  aria-label="Waiver asset ID"
                  id="waiver-asset-id"
                  onChange={(event) =>
                    onFieldChange("assetId", event.target.value)
                  }
                  placeholder="Optional UUID"
                  value={waiverForm.assetId}
                />
              </VpwField>
              <VpwField htmlFor="waiver-owner" label="Owner" required>
                <Input
                  aria-label="Waiver owner"
                  id="waiver-owner"
                  onChange={(event) =>
                    onFieldChange("owner", event.target.value)
                  }
                  placeholder="risk-owner"
                  value={waiverForm.owner}
                />
              </VpwField>
              <VpwField
                className="lg:col-span-2"
                htmlFor="waiver-reason"
                label="Reason"
                required
              >
                <Textarea
                  aria-label="Waiver reason"
                  id="waiver-reason"
                  onChange={(event) =>
                    onFieldChange("reason", event.target.value)
                  }
                  rows={3}
                  value={waiverForm.reason}
                />
              </VpwField>
              <VpwField
                htmlFor="waiver-expires-at"
                label="Expiry date"
                required
              >
                <Input
                  aria-label="Waiver expires at"
                  id="waiver-expires-at"
                  onChange={(event) =>
                    onFieldChange("expiresAt", event.target.value)
                  }
                  type="date"
                  value={waiverForm.expiresAt}
                />
              </VpwField>
              <VpwField htmlFor="waiver-review-at" label="Review date">
                <Input
                  aria-label="Waiver review at"
                  id="waiver-review-at"
                  onChange={(event) =>
                    onFieldChange("reviewAt", event.target.value)
                  }
                  type="date"
                  value={waiverForm.reviewAt}
                />
              </VpwField>
              <VpwField
                htmlFor="waiver-approval-ref"
                label="Approval reference"
              >
                <Input
                  aria-label="Waiver approval reference"
                  id="waiver-approval-ref"
                  onChange={(event) =>
                    onFieldChange("approvalRef", event.target.value)
                  }
                  placeholder="CAB-064"
                  value={waiverForm.approvalRef}
                />
              </VpwField>
              <VpwField htmlFor="waiver-ticket-url" label="Ticket URL">
                <Input
                  aria-label="Waiver ticket URL"
                  id="waiver-ticket-url"
                  onChange={(event) =>
                    onFieldChange("ticketUrl", event.target.value)
                  }
                  placeholder="https://tracker.example/..."
                  value={waiverForm.ticketUrl}
                />
              </VpwField>
            </VpwGrid>
            <div className="flex flex-wrap gap-2">
              <Button
                aria-busy={waiverActionLoading}
                disabled={
                  waiverActionLoading ||
                  projectListLoading ||
                  projects.length === 0
                }
                type="submit"
              >
                {waiverActionLoading ? "Creating" : "Create waiver"}
              </Button>
              <Button asChild type="button" variant="outline">
                <Link to="/findings">View findings</Link>
              </Button>
            </div>
          </form>
        </VpwPanel>
      </div>

      <VpwPanel className="space-y-5 p-5">
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
          Reports should continue to show accepted findings instead of hiding
          them silently.
        </VpwStatusBanner>
        <VpwStatusBanner
          title="Critical findings still need review"
          tone="critical"
        >
          A waiver is an explicit decision record, not a remediation
          replacement.
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
    </VpwGrid>
  )
}
