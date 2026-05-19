import type { WaiverPublic } from "@/api-client"
import { VpwStatusBanner } from "@/components/vpw"
import {
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"
import { WaiverDetailContent } from "./WaiversWorkbenchDrawerDetail"
import { WaiverExpireContent } from "./WaiversWorkbenchDrawerExpire"
import { WaiverForm } from "./WaiversWorkbenchForm"

export function WaiverDrawerContent({
  state,
}: {
  state: WaiversWorkbenchProps
}) {
  if (state.waiverDrawerMode === "create") {
    return (
      <WaiverForm
        buttonLabel="Create waiver"
        onFieldChange={state.onFieldChange}
        onSubmit={state.onCreateWaiver}
        waiverActionLoading={
          state.waiverActionLoading ||
          state.projectListLoading ||
          state.projects.length === 0
        }
        waiverForm={state.waiverForm}
      />
    )
  }

  if (!state.selectedWaiver) {
    return (
      <VpwStatusBanner title="No risk acceptance selected" tone="warning">
        Select a row from the register before opening this panel.
      </VpwStatusBanner>
    )
  }
  const selectedWaiver = state.selectedWaiver

  if (state.waiverDrawerMode === "review") {
    return (
      <WaiverForm
        buttonLabel="Save acceptance"
        onFieldChange={state.onReviewFieldChange}
        onSubmit={state.onUpdateWaiver}
        waiverActionLoading={state.waiverActionLoading}
        waiverForm={state.waiverEditForm}
      />
    )
  }

  if (state.waiverDrawerMode === "expire") {
    return (
      <WaiverExpireContent
        onCancel={() => state.openWaiverDrawer("detail", selectedWaiver)}
        onExpireWaiver={state.onExpireWaiver}
        waiver={selectedWaiver}
        waiverActionLoading={state.waiverActionLoading}
      />
    )
  }

  return (
    <WaiverDetailContent
      openWaiverDrawer={state.openWaiverDrawer}
      waiver={selectedWaiver}
      waiverActionLoading={state.waiverActionLoading}
    />
  )
}

export function waiverDrawerTitle(
  mode: WaiversWorkbenchProps["waiverDrawerMode"],
  waiver: WaiverPublic | null,
) {
  switch (mode) {
    case "create":
      return "Create acceptance"
    case "review":
      return waiver ? `Review ${waiverScopeLabel(waiver)}` : "Review acceptance"
    case "expire":
      return waiver ? `Expire ${waiverScopeLabel(waiver)}` : "Expire acceptance"
    case "detail":
      return waiver ? waiverScopeLabel(waiver) : "Risk acceptance detail"
    default:
      return "Risk acceptance"
  }
}

export function waiverDrawerDescription(
  mode: WaiversWorkbenchProps["waiverDrawerMode"],
) {
  switch (mode) {
    case "create":
      return "Record a time-bound accepted-risk decision for an existing scope."
    case "review":
      return "Update owner, reason, approval evidence, review, expiry, or scope."
    case "expire":
      return "Confirm that this accepted-risk decision should no longer apply."
    case "detail":
      return "Inspect the decision, lifecycle state, evidence, and matched findings."
    default:
      return "Risk acceptance drawer."
  }
}
