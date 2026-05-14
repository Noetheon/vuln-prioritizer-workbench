import { Link } from "@/lib/router"
import { Eye, Pencil, ShieldAlert } from "lucide-react"

import type { WaiverPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  CountBadge,
  StatusLozenge,
  type VpwDataTableColumn,
} from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"
import { cn } from "@/lib/utils"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  daysLabel,
  formatDate,
  shortId,
  statusLabel,
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"

type BuildWaiverRegisterColumnsArgs = Pick<
  WaiversWorkbenchProps,
  "openWaiverDrawer" | "selectedWaiverId" | "waiverActionLoading"
>

export function buildWaiverRegisterColumns({
  openWaiverDrawer,
  selectedWaiverId,
  waiverActionLoading,
}: BuildWaiverRegisterColumnsArgs): VpwDataTableColumn<WaiverPublic>[] {
  const columns: VpwDataTableColumn<WaiverPublic>[] = [
    {
      cell: (waiver) => (
        <div className="grid min-w-44 gap-0.5">
          <strong className="text-sm text-[var(--vpw-text-primary)]">
            {waiverScopeLabel(waiver)}
          </strong>
          <span className="font-mono text-xs text-[var(--vpw-text-muted)]">
            {waiver.finding_id
              ? `Finding ${shortId(waiver.finding_id)}`
              : `Acceptance ${shortId(waiver.id)}`}
          </span>
        </div>
      ),
      header: "Scope",
      id: "scope",
      width: "18rem",
    },
    {
      cell: (waiver) => (
        <span className="line-clamp-2 text-sm leading-5">
          {waiver.reason}
        </span>
      ),
      header: "Reason",
      id: "reason",
      width: "18rem",
    },
    {
      cell: (waiver) => waiver.owner,
      header: "Owner",
      id: "owner",
      width: "10rem",
    },
    {
      cell: (waiver) => (
        <StatusLozenge
          label={statusLabel(waiver.status)}
          status={waiver.status}
        />
      ),
      header: "Status",
      id: "status",
      width: "9rem",
    },
    {
      cell: (waiver) => (
        <div className="grid min-w-32 gap-1">
          <span>{formatDate(waiver.expires_at)}</span>
          <small className="text-xs text-[var(--vpw-text-muted)]">
            {daysLabel(waiver.days_remaining)}
          </small>
          <small className="text-xs text-[var(--vpw-text-muted)]">
            Review {formatDate(waiver.review_at)}
          </small>
        </div>
      ),
      header: "Expiry / Review",
      id: "lifecycle",
      width: "12rem",
    },
    {
      cell: (waiver) => <CountBadge value={waiver.matched_findings ?? 0} />,
      header: "Matched findings",
      id: "matched-findings",
      width: "9rem",
    },
    {
      cell: (waiver) =>
        optionalText(waiver.approval_ref ?? waiver.ticket_url),
      header: "Evidence",
      id: "evidence",
      width: "12rem",
    },
    {
      cell: (waiver) => (
        <WaiverRegisterActions
          openWaiverDrawer={openWaiverDrawer}
          selectedWaiverId={selectedWaiverId}
          waiver={waiver}
          waiverActionLoading={waiverActionLoading}
        />
      ),
      header: "Actions",
      id: "actions",
      width: "17rem",
    },
  ]

  return columns.map((column) => ({
    ...column,
    className: cn("px-3", column.className),
    headerClassName: cn("whitespace-normal px-3", column.headerClassName),
  }))
}

function WaiverRegisterActions({
  openWaiverDrawer,
  selectedWaiverId,
  waiver,
  waiverActionLoading,
}: BuildWaiverRegisterColumnsArgs & { waiver: WaiverPublic }) {
  return (
    <div className="flex min-w-60 flex-wrap gap-2">
      <Button
        aria-current={selectedWaiverId === waiver.id ? "true" : undefined}
        onClick={() => openWaiverDrawer("detail", waiver)}
        size="sm"
        type="button"
        variant="outline"
      >
        <Eye aria-hidden="true" />
        View
      </Button>
      {waiver.status !== "expired" ? (
        <>
          <Button
            onClick={() => openWaiverDrawer("review", waiver)}
            size="sm"
            type="button"
            variant="outline"
          >
            <Pencil aria-hidden="true" />
            Review/edit
          </Button>
          <Button
            aria-busy={waiverActionLoading}
            disabled={waiverActionLoading}
            onClick={() => openWaiverDrawer("expire", waiver)}
            size="sm"
            type="button"
            variant="outline"
          >
            <ShieldAlert aria-hidden="true" />
            Expire
          </Button>
        </>
      ) : null}
      {waiver.finding_id ? (
        <Button asChild size="sm" variant="outline">
          <Link
            params={{ findingId: waiver.finding_id }}
            search={selectedProjectRouteSearch(waiver.project_id)}
            to="/findings/$findingId"
          >
            View finding
          </Link>
        </Button>
      ) : null}
    </div>
  )
}
