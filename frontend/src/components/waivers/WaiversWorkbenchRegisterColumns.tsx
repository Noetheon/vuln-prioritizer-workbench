import { Link } from "@/lib/router"
import { ShieldAlert } from "lucide-react"
import type { Dispatch, SetStateAction } from "react"
import type { WaiverPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { VpwBadge, type VpwDataTableColumn } from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"
import { cn } from "@/lib/utils"
import {
  daysLabel,
  formatDate,
  shortId,
  statusLabel,
  statusTone,
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"

type BuildWaiverRegisterColumnsArgs = Pick<
  WaiversWorkbenchProps,
  "onExpireWaiver" | "waiverActionLoading"
> & {
  confirmExpireId: string | null
  setConfirmExpireId: Dispatch<SetStateAction<string | null>>
}

export function buildWaiverRegisterColumns({
  confirmExpireId,
  onExpireWaiver,
  setConfirmExpireId,
  waiverActionLoading,
}: BuildWaiverRegisterColumnsArgs): VpwDataTableColumn<WaiverPublic>[] {
  const columns: VpwDataTableColumn<WaiverPublic>[] = [
    {
      id: "finding",
      header: "Finding / CVE",
      className: "w-[12%] break-words",
      headerClassName: "w-[12%]",
      cell: (waiver) => (
        <div>
          <strong className="block text-sm text-[var(--vpw-text-primary)]">
            {waiver.cve_id ?? "Scoped waiver"}
          </strong>
          <span className="font-mono text-xs text-[var(--vpw-text-muted)]">
            {waiver.finding_id
              ? `Finding ${shortId(waiver.finding_id)}`
              : `Waiver ${shortId(waiver.id)}`}
          </span>
        </div>
      ),
    },
    {
      id: "scope",
      header: "Scope",
      className: "w-[12%] break-words",
      headerClassName: "w-[12%]",
      cell: (waiver) => waiverScopeLabel(waiver),
    },
    {
      id: "owner",
      header: "Owner",
      className: "w-[9%] break-words",
      headerClassName: "w-[9%]",
      cell: (waiver) => waiver.owner,
    },
    {
      id: "reason",
      header: "Reason",
      className: "w-[14%]",
      headerClassName: "w-[14%]",
      cell: (waiver) => (
        <span className="line-clamp-2 text-sm leading-5">{waiver.reason}</span>
      ),
    },
    {
      id: "status",
      header: "Status",
      className: "w-[9%]",
      headerClassName: "w-[9%]",
      cell: (waiver) => (
        <VpwBadge tone={statusTone(waiver.status)}>
          {statusLabel(waiver.status)}
        </VpwBadge>
      ),
    },
    {
      id: "expires",
      header: "Expires",
      className: "w-[11%]",
      headerClassName: "w-[11%]",
      cell: (waiver) => (
        <div>
          <span>{formatDate(waiver.expires_at)}</span>
          <small className="block text-xs text-[var(--vpw-text-muted)]">
            {daysLabel(waiver.days_remaining)}
          </small>
        </div>
      ),
    },
    {
      id: "review",
      header: "Review date",
      className: "w-[10%]",
      headerClassName: "w-[10%]",
      cell: (waiver) => formatDate(waiver.review_at),
    },
    {
      id: "approval",
      header: "Approval reference",
      className: "w-[13%] break-words",
      headerClassName: "w-[13%]",
      cell: (waiver) => optionalText(waiver.approval_ref ?? waiver.ticket_url),
    },
    {
      id: "actions",
      header: "Actions",
      className: "w-[10%]",
      headerClassName: "w-[10%]",
      cell: (waiver) => (
        <WaiverRegisterActions
          confirmExpireId={confirmExpireId}
          onExpireWaiver={onExpireWaiver}
          setConfirmExpireId={setConfirmExpireId}
          waiver={waiver}
          waiverActionLoading={waiverActionLoading}
        />
      ),
    },
  ]

  return columns.map((column) => ({
    ...column,
    className: cn("px-3", column.className),
    headerClassName: cn("whitespace-normal px-3", column.headerClassName),
  }))
}

function WaiverRegisterActions({
  confirmExpireId,
  onExpireWaiver,
  setConfirmExpireId,
  waiver,
  waiverActionLoading,
}: BuildWaiverRegisterColumnsArgs & { waiver: WaiverPublic }) {
  return (
    <div className="flex flex-wrap gap-2">
      {waiver.finding_id ? (
        <Button asChild size="sm" variant="outline">
          <Link
            to="/findings/$findingId"
            params={{ findingId: waiver.finding_id }}
          >
            View finding
          </Link>
        </Button>
      ) : null}
      {waiver.status !== "expired" && confirmExpireId === waiver.id ? (
        <>
          <Button
            aria-busy={waiverActionLoading}
            disabled={waiverActionLoading}
            onClick={() => {
              onExpireWaiver(waiver)
              setConfirmExpireId(null)
            }}
            size="sm"
            type="button"
            variant="destructive"
          >
            <ShieldAlert aria-hidden="true" className="h-4 w-4" />
            Confirm expiry
          </Button>
          <Button
            disabled={waiverActionLoading}
            onClick={() => setConfirmExpireId(null)}
            size="sm"
            type="button"
            variant="ghost"
          >
            Cancel
          </Button>
        </>
      ) : waiver.status !== "expired" ? (
        <Button
          aria-busy={waiverActionLoading}
          disabled={waiverActionLoading}
          onClick={() => setConfirmExpireId(waiver.id)}
          size="sm"
          type="button"
          variant="outline"
        >
          Expire
        </Button>
      ) : null}
    </div>
  )
}
