import { Link } from "@/lib/router"
import { AlertTriangle, ShieldAlert } from "lucide-react"

import type { WaiverPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import {
  CountBadge,
  StatusLozenge,
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
  VpwToolbarGroup,
} from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { WaiverForm } from "./WaiversWorkbenchCreate"
import {
  daysLabel,
  formatDate,
  statusLabel,
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"

export function WaiverDrawer({ state }: { state: WaiversWorkbenchProps }) {
  const title = waiverDrawerTitle(state.waiverDrawerMode, state.selectedWaiver)
  const description = waiverDrawerDescription(state.waiverDrawerMode)

  return (
    <Sheet
      onOpenChange={(open) => {
        if (!open) {
          state.closeWaiverDrawer()
        }
      }}
      open={state.waiverDrawerMode !== null}
    >
      <SheetContent className="w-[min(100vw,48rem)] overflow-y-auto sm:max-w-none">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>{description}</SheetDescription>
        </SheetHeader>
        <WaiverDrawerContent state={state} />
      </SheetContent>
    </Sheet>
  )
}

function WaiverDrawerContent({ state }: { state: WaiversWorkbenchProps }) {
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

function WaiverDetailContent({
  openWaiverDrawer,
  waiver,
  waiverActionLoading,
}: {
  openWaiverDrawer: WaiversWorkbenchProps["openWaiverDrawer"]
  waiver: WaiverPublic
  waiverActionLoading: boolean
}) {
  return (
    <div className="flex flex-col gap-4">
      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          actions={
            <VpwToolbarGroup>
              {waiver.status !== "expired" ? (
                <>
                  <Button
                    onClick={() => openWaiverDrawer("review", waiver)}
                    type="button"
                    variant="outline"
                  >
                    Review/edit
                  </Button>
                  <Button
                    aria-busy={waiverActionLoading}
                    disabled={waiverActionLoading}
                    onClick={() => openWaiverDrawer("expire", waiver)}
                    type="button"
                    variant="outline"
                  >
                    Expire
                  </Button>
                </>
              ) : null}
              {waiver.finding_id ? (
                <Button asChild variant="outline">
                  <Link
                    params={{ findingId: waiver.finding_id }}
                    search={selectedProjectRouteSearch(waiver.project_id)}
                    to="/findings/$findingId"
                  >
                    View finding
                  </Link>
                </Button>
              ) : null}
            </VpwToolbarGroup>
          }
          description="Accepted risk remains visible in findings and evidence while the decision is active."
          eyebrow="Risk acceptance detail"
          title="Decision record"
        />
        <VpwKeyValueList
          columns={2}
          items={[
            {
              label: "Scope",
              value: waiverScopeLabel(waiver),
            },
            {
              label: "Status",
              value: (
                <StatusLozenge
                  label={statusLabel(waiver.status)}
                  status={waiver.status}
                />
              ),
            },
            {
              label: "Owner",
              value: waiver.owner,
            },
            {
              label: "Matched findings",
              value: <CountBadge value={waiver.matched_findings ?? 0} />,
            },
            {
              label: "Expiry",
              value: formatDate(waiver.expires_at),
              description: daysLabel(waiver.days_remaining),
            },
            {
              label: "Review date",
              value: formatDate(waiver.review_at),
            },
            {
              label: "Approval",
              value: optionalText(waiver.approval_ref),
            },
            {
              label: "Ticket",
              value: optionalText(waiver.ticket_url),
            },
            {
              label: "Reason",
              value: waiver.reason,
            },
          ]}
        />
      </VpwPanel>
      <VpwStatusBanner title="Accepted risk stays visible" tone="info">
        This record documents a time-bound decision. It does not hide the
        underlying finding from Triage or Finding Detail.
      </VpwStatusBanner>
    </div>
  )
}

function WaiverExpireContent({
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
        description="Expire this accepted-risk decision and return matching findings to normal remediation visibility."
        eyebrow="Expire acceptance"
        title={waiverScopeLabel(waiver)}
      />
      <VpwStatusBanner title="Confirm expiry" tone="critical">
        <span className="flex items-start gap-2">
          <AlertTriangle aria-hidden="true" className="mt-0.5 size-4" />
          Expiring this decision clears the active accepted-risk state for
          matching findings.
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
          Confirm expiry
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

function waiverDrawerTitle(
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

function waiverDrawerDescription(
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
