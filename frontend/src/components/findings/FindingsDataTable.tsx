import { Link } from "@tanstack/react-router"
import { ArrowDown, ArrowUp, ArrowUpDown, Eye } from "lucide-react"
import type {
  FindingPublic,
  FindingsReadProjectFindingsData,
} from "@/api-client"
import {
  CvssBadge,
  EpssBadge,
  FindingStatusBadge,
  KevBadge,
  PriorityBadge,
  RiskScore,
} from "@/components/risk"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import type { ReactNode } from "react"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import { cn } from "@/lib/utils"

type FindingsSort = NonNullable<FindingsReadProjectFindingsData["sort"]>
type FindingsDirection = NonNullable<
  FindingsReadProjectFindingsData["direction"]
>
export type QueueSort = FindingsSort | "component" | "owner"

const defaultSortDirections: Record<QueueSort, FindingsDirection> = {
  operational: "asc",
  priority: "asc",
  score: "desc",
  cve: "asc",
  component: "asc",
  owner: "asc",
  status: "asc",
  epss: "desc",
  cvss: "desc",
  kev: "desc",
  last_seen: "desc",
}

function componentLabel(finding: FindingPublic) {
  const name = optionalText(finding.component_name)
  return finding.component_version
    ? `${name} ${finding.component_version}`
    : name
}

function serviceLabel(finding: FindingPublic) {
  return (
    finding.business_service ?? finding.component_purl ?? "Service not linked"
  )
}

function assetLabel(finding: FindingPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.business_service ??
    "N.A."
  )
}

function ownerLabel(finding: FindingPublic) {
  return finding.owner ?? finding.business_service ?? "Unassigned"
}

function findingWhyNow(finding: FindingPublic) {
  return (
    optionalText(finding.rationale) ??
    optionalText(finding.recommended_action) ??
    "No priority rationale has been recorded yet."
  )
}

function formatDateTime(value: string | null | undefined) {
  if (!value) return "N.A."
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "N.A."
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

function formatShortDate(value: string | null | undefined) {
  if (!value) return "N.A."
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "N.A."
  }
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "2-digit",
    year: "2-digit",
  }).format(date)
}

type SortHeaderProps = {
  currentDirection: FindingsDirection
  currentSort: QueueSort
  label: string
  onSort: (sort: QueueSort) => void
  sort: QueueSort
}

function sortAriaState(
  currentDirection: FindingsDirection,
  currentSort: QueueSort,
  sort: QueueSort,
) {
  if (currentSort !== sort) return undefined
  return currentDirection === "asc" ? "ascending" : "descending"
}

function SortHeader({
  currentDirection,
  currentSort,
  label,
  onSort,
  sort,
}: SortHeaderProps) {
  const active = currentSort === sort
  const nextDirection: FindingsDirection = active
    ? currentDirection === "asc"
      ? "desc"
      : "asc"
    : defaultSortDirections[sort]
  const Icon = active
    ? currentDirection === "asc"
      ? ArrowUp
      : ArrowDown
    : ArrowUpDown

  return (
    <button
      aria-label={`Sort by ${label} (${active ? `${currentDirection} active` : `${nextDirection} first`})`}
      aria-pressed={active}
      className={cn(
        "-ml-1 inline-flex h-7 items-center gap-1 rounded-md px-1.5 text-[0.72rem] font-extrabold uppercase text-inherit transition hover:bg-slate-100 hover:text-slate-900",
        active ? "text-teal-700" : "text-slate-500",
      )}
      onClick={() => onSort(sort)}
      type="button"
    >
      <Icon
        aria-hidden="true"
        className={cn(
          "size-3.5 shrink-0",
          active ? "opacity-100" : "opacity-50",
        )}
      />
      <span className="text-left leading-tight">{label}</span>
    </button>
  )
}

function StaticHeader({
  align = "left",
  label,
}: {
  align?: "left" | "right"
  label: string
}) {
  return (
    <span
      className={cn(
        "inline-flex h-7 items-center text-[0.72rem] font-extrabold uppercase text-slate-500",
        align === "right" ? "justify-end" : "justify-start",
      )}
    >
      {label}
    </span>
  )
}

type FindingsDataTableProps = {
  findings: readonly FindingPublic[]
  findingDirection: FindingsDirection
  onOpenSheet: (finding: FindingPublic) => void
  onOpenWhy: (finding: FindingPublic) => void
  onSort: (sort: QueueSort) => void
  queueSort: QueueSort
}

type FindingsDataTableColumn = {
  id: string
  header: ReactNode
  cell: (finding: FindingPublic) => ReactNode
  ariaSort?: "ascending" | "descending"
  className?: string
  headerClassName?: string
}

export function FindingsDataTable({
  findings,
  findingDirection,
  onOpenSheet,
  onOpenWhy,
  onSort,
  queueSort,
}: FindingsDataTableProps) {
  const columns: readonly FindingsDataTableColumn[] = [
    {
      id: "priority",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="Priority"
          onSort={onSort}
          sort="priority"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "priority"),
      cell: (finding) => <PriorityBadge priority={finding.priority} />,
      className: "w-[6%]",
      headerClassName: "w-[6%]",
    },
    {
      id: "score",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="Score"
          onSort={onSort}
          sort="score"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "score"),
      cell: (finding) => <RiskScore value={finding.risk_score} />,
      className: "w-[5%]",
      headerClassName: "w-[5%]",
    },
    {
      id: "cve",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="CVE"
          onSort={onSort}
          sort="cve"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "cve"),
      cell: (finding) => (
        <>
          <Link
            className="finding-cve-link"
            params={{ findingId: finding.id }}
            title={`Open finding ${finding.cve_id}`}
            to="/findings/$findingId"
          >
            {finding.cve_id}
          </Link>
          {finding.attack_mapped ? (
            <span className="remediation-subtext">ATT&amp;CK mapped</span>
          ) : null}
        </>
      ),
      className: "w-[8%]",
      headerClassName: "w-[8%]",
    },
    {
      id: "component",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="Component / Service"
          onSort={onSort}
          sort="component"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "component"),
      cell: (finding) => (
        <div className="min-w-0">
          <strong className="block truncate" title={componentLabel(finding)}>
            {componentLabel(finding)}
          </strong>
          <span
            className="remediation-subtext truncate"
            title={`${serviceLabel(finding)} / ${assetLabel(finding)}`}
          >
            {serviceLabel(finding)} / {assetLabel(finding)}
          </span>
        </div>
      ),
      className: "w-[19%] min-w-0",
      headerClassName: "w-[19%]",
    },
    {
      id: "owner",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="Owner"
          onSort={onSort}
          sort="owner"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "owner"),
      cell: (finding) => (
        <>
          <strong>{ownerLabel(finding)}</strong>
          {finding.exposure ? (
            <span className="remediation-subtext">
              {labelize(finding.exposure)}
            </span>
          ) : null}
        </>
      ),
      className: "w-[10%]",
      headerClassName: "w-[10%]",
    },
    {
      id: "status",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="Status"
          onSort={onSort}
          sort="status"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "status"),
      cell: (finding) => (
        <div className="grid justify-items-start gap-1.5">
          <FindingStatusBadge status={finding.status} />
          <span
            className="remediation-subtext"
            title={`Last seen ${formatDateTime(finding.last_seen_at)}`}
          >
            {formatShortDate(finding.last_seen_at)}
          </span>
        </div>
      ),
      className: "w-[8%]",
      headerClassName: "w-[8%]",
    },
    {
      id: "signals",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="Signals"
          onSort={onSort}
          sort="epss"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "epss"),
      cell: (finding) => (
        <div className="flex flex-wrap items-center gap-1.5 min-[1500px]:flex-nowrap">
          <span className="inline-flex min-h-6 items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-2 text-[0.72rem] font-extrabold leading-none text-slate-600">
            <span>EPSS</span>
            <strong className="font-black text-slate-950">
              <EpssBadge value={finding.epss} />
            </strong>
          </span>
          <span className="inline-flex min-h-6 items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-2 text-[0.72rem] font-extrabold leading-none text-slate-600">
            <span>CVSS</span>
            <strong className="font-black text-slate-950">
              <CvssBadge value={finding.cvss_base_score} />
            </strong>
          </span>
          <KevBadge matched={finding.in_kev} />
        </div>
      ),
      className: "w-[13%]",
      headerClassName: "w-[13%]",
    },
    {
      id: "why",
      header: <StaticHeader label="Why now" />,
      cell: (finding) => (
        <>
          <span className="remediation-why-now">{findingWhyNow(finding)}</span>
          <button
            className="mt-1 border-0 bg-transparent p-0 text-[0.78rem] font-extrabold text-slate-900 hover:text-teal-700"
            onClick={() => onOpenWhy(finding)}
            type="button"
          >
            Why now
          </button>
        </>
      ),
      className: "w-[25%]",
      headerClassName: "w-[25%]",
    },
    {
      id: "view",
      header: <StaticHeader align="right" label="View" />,
      cell: (finding) => (
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              aria-label={`Quick view ${finding.cve_id}`}
              className="finding-view-action"
              onClick={() => onOpenSheet(finding)}
              type="button"
              variant="ghost"
            >
              <Eye aria-hidden="true" size={16} />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="left">Quick view</TooltipContent>
        </Tooltip>
      ),
      className:
        "sticky right-0 z-10 w-16 min-w-16 bg-[var(--vpw-bg-card)] pr-4 text-right",
      headerClassName:
        "sticky right-0 z-20 w-16 min-w-16 bg-[var(--vpw-bg-panel)] pr-4 text-right",
    },
  ]

  return (
    <div className="vpw-table-wrap remediation-table-wrap shadow-none">
      <table className="vpw-table min-w-[1240px] table-fixed [&_td]:py-3 [&_th]:py-3">
        <caption className="sr-only">Findings remediation queue</caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                aria-sort={column.ariaSort}
                className={cn("vpw-table-header-cell", column.headerClassName)}
                key={column.id}
                scope="col"
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr
              className="vpw-table-row transition-colors hover:[&>td]:bg-[var(--vpw-bg-panel)]"
              key={finding.id}
            >
              {columns.map((column) => (
                <td
                  className={cn("vpw-table-cell", column.className)}
                  key={column.id}
                >
                  {column.cell(finding)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
