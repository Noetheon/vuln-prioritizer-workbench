import { Link } from "@/lib/router"
import type { WaiverPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
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
import {
  daysLabel,
  formatDate,
  statusLabel,
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"

export function WaiverDetailContent({
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
