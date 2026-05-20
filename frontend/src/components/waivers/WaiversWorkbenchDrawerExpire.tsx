import { AlertTriangle, ShieldAlert } from "lucide-react"

import type { WaiverPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import {
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"

export function WaiverExpireContent({
  onCancel,
  onExpireWaiver,
  waiver,
  waiverActionLoading,
}: {
  onCancel: () => void
  onExpireWaiver: WaiversWorkbenchProps["onExpireWaiver"]
  waiver: WaiverPublic
  waiverActionLoading: boolean
}) {
  return (
    <VpwPanel className="flex flex-col gap-4 p-5">
      <VpwSectionHeader
        description="This ends the active accepted-risk state while keeping the historical decision visible."
        eyebrow="Expire acceptance"
        title={waiverScopeLabel(waiver)}
      />
      <VpwStatusBanner title="Expire accepted-risk decision?" tone="critical">
        <span className="flex items-start gap-2">
          <AlertTriangle aria-hidden="true" className="mt-0.5 size-4" />
          Expire accepted-risk decision? This will end the accepted-risk state
          for matching findings, but the historical decision record remains
          visible.
        </span>
      </VpwStatusBanner>
      <div className="flex flex-wrap gap-2">
        <Button
          aria-busy={waiverActionLoading}
          disabled={waiverActionLoading}
          onClick={() => onExpireWaiver(waiver)}
          type="button"
          variant="destructive"
        >
          <ShieldAlert aria-hidden="true" />
          Expire acceptance
        </Button>
        <Button
          disabled={waiverActionLoading}
          onClick={onCancel}
          type="button"
          variant="outline"
        >
          Cancel
        </Button>
      </div>
    </VpwPanel>
  )
}
