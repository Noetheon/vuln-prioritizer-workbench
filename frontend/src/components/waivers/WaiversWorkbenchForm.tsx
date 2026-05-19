import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { VpwField, VpwGrid } from "@/components/vpw"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"

export function WaiverForm({
  buttonLabel,
  onFieldChange,
  onSubmit,
  waiverActionLoading,
  waiverForm,
}: {
  buttonLabel: string
  onFieldChange: WaiversWorkbenchProps["onFieldChange"]
  onSubmit: WaiversWorkbenchProps["onCreateWaiver"]
  waiverActionLoading: boolean
  waiverForm: WaiversWorkbenchProps["waiverForm"]
}) {
  return (
    <form className="flex flex-col gap-5" onSubmit={onSubmit}>
      <VpwGrid columns={2}>
        <VpwField htmlFor="waiver-cve-id" label="CVE ID">
          <Input
            aria-label="Waiver CVE ID"
            id="waiver-cve-id"
            onChange={(event) => onFieldChange("cveId", event.target.value)}
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
            onChange={(event) => onFieldChange("assetKey", event.target.value)}
            placeholder="payments-api"
            value={waiverForm.assetKey}
          />
        </VpwField>
        <VpwField htmlFor="waiver-service" label="Service">
          <Input
            aria-label="Waiver service"
            id="waiver-service"
            onChange={(event) => onFieldChange("service", event.target.value)}
            placeholder="checkout"
            value={waiverForm.service}
          />
        </VpwField>
        <VpwField htmlFor="waiver-asset-id" label="Asset ID">
          <Input
            aria-label="Waiver asset ID"
            id="waiver-asset-id"
            onChange={(event) => onFieldChange("assetId", event.target.value)}
            placeholder="Optional UUID"
            value={waiverForm.assetId}
          />
        </VpwField>
        <VpwField htmlFor="waiver-owner" label="Owner" required>
          <Input
            aria-label="Waiver owner"
            id="waiver-owner"
            onChange={(event) => onFieldChange("owner", event.target.value)}
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
            onChange={(event) => onFieldChange("reason", event.target.value)}
            rows={3}
            value={waiverForm.reason}
          />
        </VpwField>
        <VpwField htmlFor="waiver-expires-at" label="Expiry date" required>
          <Input
            aria-label="Waiver expires at"
            id="waiver-expires-at"
            onChange={(event) => onFieldChange("expiresAt", event.target.value)}
            type="date"
            value={waiverForm.expiresAt}
          />
        </VpwField>
        <VpwField htmlFor="waiver-review-at" label="Review date">
          <Input
            aria-label="Waiver review at"
            id="waiver-review-at"
            onChange={(event) => onFieldChange("reviewAt", event.target.value)}
            type="date"
            value={waiverForm.reviewAt}
          />
        </VpwField>
        <VpwField htmlFor="waiver-approval-ref" label="Approval reference">
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
            onChange={(event) => onFieldChange("ticketUrl", event.target.value)}
            placeholder="https://tracker.example/..."
            value={waiverForm.ticketUrl}
          />
        </VpwField>
      </VpwGrid>
      <Button
        aria-busy={waiverActionLoading}
        disabled={waiverActionLoading}
        type="submit"
      >
        {waiverActionLoading ? "Saving" : buttonLabel}
      </Button>
    </form>
  )
}
