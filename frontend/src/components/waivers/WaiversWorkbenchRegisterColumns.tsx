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
import { cn } from "@/lib/utils"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  daysLabel,
  evidenceDetail,
  evidenceStateLabel,
  evidenceStateToken,
  formatDate,
  lifecycleLabel,
  lifecycleStatusToken,
  shortId,
  type WaiversWorkbenchProps,
  waiverScopeLines,
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
      cell: (waiver) => {
        const scope = waiverScopeLines(waiver)
        return (
          <div className="grid min-w-44 gap-0.5">
            <strong className="text-sm text-[var(--vpw-text-primary)]">
              {scope.primary}
            </strong>
            {scope.secondary ? (
              <span className="text-sm text-[var(--vpw-text-secondary)]">
                {scope.secondary}
              </span>
            ) : null}
            <span className="font-mono text-xs text-[var(--vpw-text-muted)]">
              Acceptance {shortId(waiver.id)}
            </span>
          </div>
        )
      },
      header: "Scope",
      id: "scope",
      width: "18%",
    },
    {
      cell: (waiver) => (
        <span className="line-clamp-2 text-sm leading-5" title={waiver.reason}>
          {waiver.reason}
        </span>
      ),
      header: "Decision",
      id: "decision",
      width: "18%",
    },
    {
      cell: (waiver) => (
        <div className="grid gap-0.5">
          <strong className="text-sm text-[var(--vpw-text-primary)]">
            {waiver.owner}
          </strong>
          <span className="text-xs text-[var(--vpw-text-muted)]">
            accountable owner
          </span>
        </div>
      ),
      header: "Owner",
      id: "owner",
      width: "10%",
    },
    {
      cell: (waiver) => (
        <StatusLozenge
          label={lifecycleLabel(waiver)}
          status={lifecycleStatusToken(waiver)}
        />
      ),
      header: "State",
      id: "state",
      width: "11%",
    },
    {
      cell: (waiver) => (
        <div className="grid min-w-32 gap-1">
          <span>Expires {formatDate(waiver.expires_at)}</span>
          <small className="text-xs text-[var(--vpw-text-muted)]">
            {daysLabel(waiver.days_remaining)}
          </small>
          <small className="text-xs text-[var(--vpw-text-muted)]">
            Review due {formatDate(waiver.review_at)}
          </small>
        </div>
      ),
      header: "Review / Expiry",
      id: "lifecycle",
      width: "13%",
    },
    {
      cell: (waiver) => (
        <Button asChild size="xs" variant="ghost">
          <Link
            search={{
              ...selectedProjectRouteSearch(waiver.project_id),
              q: waiver.cve_id ?? waiver.asset_key ?? waiver.service ?? "",
              status: "accepted",
            }}
            to="/findings"
          >
            <CountBadge
              label={`${waiver.matched_findings ?? 0} finding${(waiver.matched_findings ?? 0) === 1 ? "" : "s"}`}
              value={waiver.matched_findings ?? 0}
            />
          </Link>
        </Button>
      ),
      header: "Matched findings",
      id: "matched-findings",
      width: "10%",
    },
    {
      cell: (waiver) => (
        <div className="grid min-w-32 gap-1">
          <StatusLozenge
            label={evidenceStateLabel(waiver)}
            status={evidenceStateToken(waiver)}
          />
          <small className="truncate text-xs text-[var(--vpw-text-muted)]">
            {evidenceDetail(waiver)}
          </small>
        </div>
      ),
      header: "Evidence",
      id: "evidence",
      width: "12%",
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
          aria-label={`View accepted-risk decision for ${waiverScopeLabel(waiver)}`}
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
              aria-label={`Review or edit accepted-risk decision for ${waiverScopeLabel(waiver)}`}
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
              aria-label={`Expire accepted-risk decision for ${waiverScopeLabel(waiver)}`}
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
              aria-label={`Open matched finding for ${waiverScopeLabel(waiver)}`}
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
