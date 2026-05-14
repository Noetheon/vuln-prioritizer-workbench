import { Link } from "@/lib/router"
import { ExternalLink, Eye } from "lucide-react"
import type { ReactNode } from "react"
import type { FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  MetaTag,
  RiskBadge,
  RiskScoreBadge,
  SignalChip,
  StatusLozenge,
  VpwSignalCluster,
} from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"
import { SortHeader, StaticHeader } from "./FindingsDataTableHeaders"
import {
  assetLabel,
  componentLabel,
  formatDateTime,
  formatShortDate,
  findingSlaLabel,
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
  onSort: (sort: QueueSort) => void
  queueSort: QueueSort
}

export function buildFindingsDataTableColumns({
  findingDirection,
  findingSearch,
  onOpenSheet,
  onSort,
  queueSort,
}: BuildFindingsColumnsOptions): readonly FindingsDataTableColumn[] {
  return [
    {
      id: "priority",
      header: (
        <fieldset className="finding-sort-stack">
          <legend className="sr-only">Priority sort controls</legend>
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
        </fieldset>
      ),
      cell: (finding) => (
        <div className="finding-priority-cell">
          <RiskBadge density="compact" level={finding.priority} />
          <RiskScoreBadge density="compact" value={finding.risk_score} />
        </div>
      ),
      className: "w-[13%]",
      headerClassName: "w-[13%]",
      width: "13%",
    },
    {
      id: "finding",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="Finding"
          onSort={onSort}
          sort="cve"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "cve"),
      cell: (finding) => (
        <div className="finding-primary-cell">
          <Link
            className="finding-cve-link"
            params={{ findingId: finding.id }}
            search={findingSearch}
            title={`Open finding ${finding.cve_id}`}
            to="/findings/$findingId"
          >
            {finding.cve_id}
          </Link>
          <strong className="finding-component-name" title={componentLabel(finding)}>
            {componentLabel(finding)}
          </strong>
          {finding.component_purl ? (
            <span className="remediation-subtext truncate" title={finding.component_purl}>
              {finding.component_purl}
            </span>
          ) : null}
        </div>
      ),
      className: "w-[22%] min-w-0",
      headerClassName: "w-[22%]",
      width: "22%",
    },
    {
      id: "asset",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="Asset / Service"
          onSort={onSort}
          sort="component"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "component"),
      cell: (finding) => (
        <div className="finding-asset-cell">
          <strong className="block truncate" title={assetLabel(finding)}>
            {assetLabel(finding)}
          </strong>
          <span className="remediation-subtext truncate" title={serviceLabel(finding)}>
            {serviceLabel(finding)}
          </span>
          <div className="finding-meta-tags">
            {finding.asset_environment ? (
              <MetaTag label={labelize(finding.asset_environment)} />
            ) : null}
            {finding.exposure ? (
              <MetaTag label={labelize(finding.exposure)} />
            ) : null}
          </div>
        </div>
      ),
      className: "w-[18%] min-w-0",
      headerClassName: "w-[18%]",
      width: "18%",
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
        <div className="finding-owner-cell">
          <strong>{ownerLabel(finding)}</strong>
          {finding.business_service ? (
            <span className="remediation-subtext">
              {finding.business_service}
            </span>
          ) : null}
        </div>
      ),
      className: "w-[11%]",
      headerClassName: "w-[11%]",
      width: "11%",
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
        <VpwSignalCluster className="min-[1500px]:flex-nowrap" maxVisible={3}>
          {finding.in_kev ? <SignalChip kind="kev" /> : null}
          {finding.epss !== null && finding.epss !== undefined ? (
            <SignalChip kind="epss" value={finding.epss} />
          ) : null}
          {finding.cvss_base_score !== null &&
          finding.cvss_base_score !== undefined ? (
            <SignalChip kind="cvss" value={finding.cvss_base_score} />
          ) : null}
          {finding.attack_mapped ? <SignalChip kind="attack" /> : null}
          {finding.suppressed_by_vex ? <SignalChip kind="vex" /> : null}
        </VpwSignalCluster>
      ),
      className: "w-[15%]",
      headerClassName: "w-[15%]",
      width: "15%",
    },
    {
      id: "status",
      header: (
        <SortHeader
          currentDirection={findingDirection}
          currentSort={queueSort}
          label="Status / SLA"
          onSort={onSort}
          sort="status"
        />
      ),
      ariaSort: sortAriaState(findingDirection, queueSort, "status"),
      cell: (finding) => (
        <div className="finding-status-cell">
          <StatusLozenge density="compact" status={finding.status} />
          <span
            className="remediation-subtext"
            title={`Last seen ${formatDateTime(finding.last_seen_at)}`}
          >
            {formatShortDate(finding.last_seen_at)}
          </span>
          <div className="finding-meta-tags">
            <MetaTag label={findingSlaLabel(finding.priority)} />
            {finding.waived ? <MetaTag label="Accepted risk" /> : null}
            {finding.under_investigation ? (
              <MetaTag label="Under review" />
            ) : null}
          </div>
        </div>
      ),
      className: "w-[13%]",
      headerClassName: "w-[13%]",
      width: "13%",
    },
    {
      id: "view",
      header: <StaticHeader align="right" label="Actions" />,
      cell: (finding) => (
        <div className="finding-row-actions">
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
            <TooltipContent side="left">Open drawer</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                asChild
                className="finding-view-action"
                type="button"
                variant="ghost"
              >
                <Link
                  aria-label={`Open full detail ${finding.cve_id}`}
                  params={{ findingId: finding.id }}
                  search={findingSearch}
                  to="/findings/$findingId"
                >
                  <ExternalLink aria-hidden="true" size={16} />
                </Link>
              </Button>
            </TooltipTrigger>
            <TooltipContent side="left">Full detail</TooltipContent>
          </Tooltip>
        </div>
      ),
      className: "w-20 min-w-20 bg-[var(--vpw-bg-card)] px-2 text-right",
      headerClassName: "w-20 min-w-20 bg-[var(--vpw-bg-panel)] px-2 text-right",
      width: "8%",
    },
  ]
}
