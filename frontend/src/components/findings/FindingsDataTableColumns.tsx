import { Link } from "@/lib/router"
import { Eye } from "lucide-react"
import type { ReactNode } from "react"

import type { FindingPublic } from "@/api-client"
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
import { VpwBadge } from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"
import { SortHeader, StaticHeader } from "./FindingsDataTableHeaders"
import {
  assetLabel,
  componentLabel,
  findingWhyNow,
  formatDateTime,
  formatShortDate,
  ownerLabel,
  serviceLabel,
  sortAriaState,
} from "./FindingsDataTableModel"
import type { FindingsUrlSearch } from "./findings-search-state"
import type { FindingsDirection, QueueSort } from "./remediation-queue-model"

export type FindingsDataTableColumn = {
  id: string
  header: ReactNode
  cell: (finding: FindingPublic) => ReactNode
  ariaSort?: "ascending" | "descending"
  className?: string
  headerClassName?: string
  width?: string
}

type BuildFindingsColumnsOptions = {
  findingDirection: FindingsDirection
  findingSearch: FindingsUrlSearch
  onOpenSheet: (finding: FindingPublic) => void
  onOpenWhy: (finding: FindingPublic) => void
  onSort: (sort: QueueSort) => void
  queueSort: QueueSort
}

export function buildFindingsDataTableColumns({
  findingDirection,
  findingSearch,
  onOpenSheet,
  onOpenWhy,
  onSort,
  queueSort,
}: BuildFindingsColumnsOptions): readonly FindingsDataTableColumn[] {
  return [
    {
      id: "finding",
      header: (
        <fieldset className="finding-sort-stack">
          <legend className="sr-only">Finding sort controls</legend>
          <SortHeader
            currentDirection={findingDirection}
            currentSort={queueSort}
            label="Priority"
            onSort={onSort}
            sort="priority"
          />
          <SortHeader
            currentDirection={findingDirection}
            currentSort={queueSort}
            label="Score"
            onSort={onSort}
            sort="score"
          />
          <SortHeader
            currentDirection={findingDirection}
            currentSort={queueSort}
            label="CVE"
            onSort={onSort}
            sort="cve"
          />
        </fieldset>
      ),
      cell: (finding) => (
        <div className="finding-primary-cell">
          <div className="finding-primary-badges">
            <PriorityBadge priority={finding.priority} />
            <RiskScore value={finding.risk_score} />
          </div>
          <Link
            className="finding-cve-link"
            params={{ findingId: finding.id }}
            search={findingSearch}
            title={`Open finding ${finding.cve_id}`}
            to="/findings/$findingId"
          >
            {finding.cve_id}
          </Link>
          {finding.attack_mapped ? (
            <span className="remediation-subtext">ATT&amp;CK mapped</span>
          ) : null}
        </div>
      ),
      className: "w-[22%]",
      headerClassName: "w-[22%]",
      width: "22%",
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
      className: "w-[20%] min-w-0",
      headerClassName: "w-[20%]",
      width: "20%",
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
      className: "w-[12%]",
      headerClassName: "w-[12%]",
      width: "12%",
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
      className: "w-[10%]",
      headerClassName: "w-[10%]",
      width: "10%",
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
          <VpwBadge className="min-h-6 gap-1.5 px-2 text-[0.72rem]" tone="info">
            <span>EPSS</span>
            <strong className="font-black text-[var(--vpw-text-primary)]">
              <EpssBadge value={finding.epss} />
            </strong>
          </VpwBadge>
          <VpwBadge className="min-h-6 gap-1.5 px-2 text-[0.72rem]" tone="info">
            <span>CVSS</span>
            <strong className="font-black text-[var(--vpw-text-primary)]">
              <CvssBadge value={finding.cvss_base_score} />
            </strong>
          </VpwBadge>
          <KevBadge matched={finding.in_kev} />
        </div>
      ),
      className: "w-[15%]",
      headerClassName: "w-[15%]",
      width: "15%",
    },
    {
      id: "why",
      header: <StaticHeader label="Why now" />,
      cell: (finding) => (
        <>
          <span className="remediation-why-now">{findingWhyNow(finding)}</span>
          <Button
            className="mt-1 h-auto justify-start p-0 text-[0.78rem] font-extrabold text-[var(--vpw-text-primary)]"
            onClick={() => onOpenWhy(finding)}
            size="sm"
            type="button"
            variant="link"
          >
            Why now
          </Button>
        </>
      ),
      className: "w-[17%]",
      headerClassName: "w-[17%]",
      width: "17%",
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
      width: "4%",
    },
  ]
}
