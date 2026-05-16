import { Link } from "@/lib/router"
import { ExternalLink, Eye } from "lucide-react"
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
  type VpwDataTableColumn,
} from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"
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
}: BuildFindingsColumnsOptions): readonly VpwDataTableColumn<FindingPublic>[] {
  const sortable = (sort: QueueSort, label: string) => ({
    active: queueSort === sort,
    direction: queueSort === sort ? findingDirection : undefined,
    label,
    onSort: () => onSort(sort),
  })

  return [
    {
      id: "priority",
      header: "Priority",
      ariaSort: sortAriaState(findingDirection, queueSort, "priority"),
      cell: (finding) => (
        <RiskBadge density="compact" level={finding.priority} />
      ),
      className: "w-[9%]",
      headerClassName: "w-[9%]",
      sort: sortable("priority", "Priority"),
      width: "9%",
    },
    {
      id: "score",
      header: "Score",
      ariaSort: sortAriaState(findingDirection, queueSort, "score"),
      cell: (finding) => (
        <RiskScoreBadge density="compact" value={finding.risk_score} />
      ),
      className: "w-[7%]",
      headerClassName: "w-[7%]",
      sort: sortable("score", "Score"),
      width: "7%",
    },
    {
      id: "finding",
      header: "Finding",
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
      className: "w-[20%] min-w-0",
      headerClassName: "w-[20%]",
      sort: sortable("cve", "Finding"),
      width: "20%",
    },
    {
      id: "asset",
      header: "Asset / Service",
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
      sort: sortable("component", "Asset / Service"),
      width: "18%",
    },
    {
      id: "owner",
      header: "Owner",
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
      sort: sortable("owner", "Owner"),
      width: "11%",
    },
    {
      id: "signals",
      header: "Signals",
      ariaSort: sortAriaState(findingDirection, queueSort, "epss"),
      cell: (finding) => (
        <VpwSignalCluster maxVisible={3}>
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
      className: "w-[14%]",
      headerClassName: "w-[14%]",
      sort: sortable("epss", "Signals"),
      width: "14%",
    },
    {
      id: "status",
      header: "Status / SLA",
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
      className: "w-[14%]",
      headerClassName: "w-[14%]",
      sort: sortable("status", "Status / SLA"),
      width: "14%",
    },
    {
      id: "view",
      header: "Actions",
      cell: (finding) => (
        <div className="vpw-table-actions finding-row-actions">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                aria-label={`Quick view ${finding.cve_id}`}
                className="vpw-table-action-button finding-view-action"
                onClick={() => onOpenSheet(finding)}
                size="icon-sm"
                type="button"
                variant="outline"
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
                className="vpw-table-action-button finding-view-action"
                size="icon-sm"
                type="button"
                variant="outline"
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
      className: "w-20 min-w-20 px-2 text-center",
      headerClassName: "w-20 min-w-20 px-2 text-center",
      width: "7%",
    },
  ]
}
