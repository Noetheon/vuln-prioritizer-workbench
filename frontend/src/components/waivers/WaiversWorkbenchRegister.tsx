import { Link } from "@tanstack/react-router"
import { RefreshCw } from "lucide-react"
import type { WaiverPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
} from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"
import {
  daysLabel,
  formatDate,
  shortId,
  statusLabel,
  statusTone,
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"

export function WaiverRegister({
  onExpireWaiver,
  onRefreshWaivers,
  waiverActionLoading,
  waivers,
  waiversLoading,
}: Pick<
  WaiversWorkbenchProps,
  | "onExpireWaiver"
  | "onRefreshWaivers"
  | "waiverActionLoading"
  | "waivers"
  | "waiversLoading"
>) {
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
          {waiver.status !== "expired" ? (
            <Button
              aria-busy={waiverActionLoading}
              disabled={waiverActionLoading}
              onClick={() => onExpireWaiver(waiver)}
              size="sm"
              type="button"
              variant="outline"
            >
              Expire
            </Button>
          ) : null}
        </div>
      ),
    },
  ]

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          <Button
            onClick={onRefreshWaivers}
            size="sm"
            type="button"
            variant="outline"
          >
            <RefreshCw aria-hidden="true" className="h-4 w-4" />
            Refresh
          </Button>
        }
        description="Accepted risk remains visible after creation and expiry."
        eyebrow="Register"
        title="Risk acceptance register"
      />
      {waiversLoading ? (
        <VpwPanel className="p-5">
          <VpwSkeletonStack rows={5} />
        </VpwPanel>
      ) : (
        <VpwDataTable
          caption="Waivers table"
          className="[&_table]:table-fixed [&_td]:px-3 [&_th]:whitespace-normal [&_th]:px-3"
          columns={columns}
          data={waivers}
          density="compact"
          emptyState={
            <VpwEmptyState
              action={
                <div className="flex flex-wrap justify-center gap-2">
                  <Button asChild>
                    <a href="#create-waiver">Create waiver</a>
                  </Button>
                  <Button asChild variant="outline">
                    <Link to="/findings">View findings</Link>
                  </Button>
                </div>
              }
              description="Create a waiver only when remediation cannot happen immediately and compensating controls are documented."
              title="No accepted risk decisions yet"
            />
          }
          getRowKey={(waiver) => waiver.id}
        />
      )}
    </VpwSection>
  )
}
