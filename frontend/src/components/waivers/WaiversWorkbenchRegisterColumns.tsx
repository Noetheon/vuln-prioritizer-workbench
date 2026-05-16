import { Link } from "@/lib/router"
import { ExternalLink, Eye, Pencil, ShieldAlert } from "lucide-react"
import type { ReactNode } from "react"

import type { WaiverPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
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
      width: "18%",
    },
    {
      cell: (waiver) => (
        <span className="line-clamp-2 text-sm leading-5">
          {waiver.reason}
        </span>
      ),
      header: "Reason",
      id: "reason",
      width: "18%",
    },
    {
      cell: (waiver) => waiver.owner,
      header: "Owner",
      id: "owner",
      width: "10%",
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
      width: "11%",
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
      width: "13%",
    },
    {
      cell: (waiver) => <CountBadge value={waiver.matched_findings ?? 0} />,
      header: "Matched findings",
      id: "matched-findings",
      width: "8%",
    },
    {
      cell: (waiver) =>
        optionalText(waiver.approval_ref ?? waiver.ticket_url),
      header: "Evidence",
      id: "evidence",
      width: "10%",
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
      headerClassName: "text-right",
      id: "actions",
      className: "min-w-[8.5rem] text-right align-middle",
      width: "8.5rem",
    },
  ]

  return columns.map((column) => ({
    ...column,
    className: cn("px-3", column.className),
    headerClassName: cn("whitespace-normal px-3", column.headerClassName),
  }))
}

function WaiverAction({
  children,
  label,
}: {
  children: ReactNode
  label: string
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

function WaiverRegisterActions({
  openWaiverDrawer,
  selectedWaiverId,
  waiver,
  waiverActionLoading,
}: BuildWaiverRegisterColumnsArgs & { waiver: WaiverPublic }) {
  return (
    <div className="vpw-table-actions">
      <WaiverAction label="View acceptance">
        <Button
          aria-current={selectedWaiverId === waiver.id ? "true" : undefined}
          aria-label="View"
          className="vpw-table-action-button"
          onClick={() => openWaiverDrawer("detail", waiver)}
          size="icon-xs"
          type="button"
          variant="outline"
        >
          <Eye aria-hidden="true" />
        </Button>
      </WaiverAction>
      {waiver.status !== "expired" ? (
        <>
          <WaiverAction label="Review or edit">
            <Button
              aria-label={`Review ${waiverScopeLabel(waiver)}`}
              className="vpw-table-action-button"
              onClick={() => openWaiverDrawer("review", waiver)}
              size="icon-xs"
              type="button"
              variant="outline"
            >
              <Pencil aria-hidden="true" />
            </Button>
          </WaiverAction>
          <WaiverAction label="Expire acceptance">
            <Button
              aria-busy={waiverActionLoading}
              aria-label={`Expire ${waiverScopeLabel(waiver)}`}
              className="vpw-table-action-button"
              disabled={waiverActionLoading}
              onClick={() => openWaiverDrawer("expire", waiver)}
              size="icon-xs"
              type="button"
              variant="outline"
            >
              <ShieldAlert aria-hidden="true" />
            </Button>
          </WaiverAction>
        </>
      ) : null}
      {waiver.finding_id ? (
        <WaiverAction label="Open finding">
          <Button
            asChild
            className="vpw-table-action-button"
            size="icon-xs"
            variant="outline"
          >
            <Link
              aria-label={`Open finding for ${waiverScopeLabel(waiver)}`}
              params={{ findingId: waiver.finding_id }}
              search={selectedProjectRouteSearch(waiver.project_id)}
              to="/findings/$findingId"
            >
              <ExternalLink aria-hidden="true" />
            </Link>
          </Button>
        </WaiverAction>
      ) : null}
    </div>
  )
}
