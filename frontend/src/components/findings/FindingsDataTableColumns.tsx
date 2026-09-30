import { Link } from "@/lib/router"
import { ExternalLink, Eye } from "lucide-react"
import type { FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
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
  type VpwDataTableSort,
} from "@/components/vpw"
import { VpwTableSortButton } from "@/components/vpw/VpwDataTableHeaderContent"
import { formatDate } from "@/lib/date-format"
import { isActionableFinding } from "@/lib/finding-queue-labels"
import type { SelectAllState } from "@/lib/finding-bulk-selection"
import { formatLabel as labelize } from "@/lib/ui-copy"
import {
  assetLabel,
  componentLabel,
  findingActionLabel,
  findingWhyNow,
  findingWhyNowCompact,
  formatDateTime,
  findingSlaLabel,
  ownerLabel,
  serviceLabel,
  sortAriaState,
} from "./FindingsDataTableModel"
import type { FindingsUrlSearch } from "./findings-search-state"
import { SlaDueBadge } from "./SlaDueBadge"
import type { FindingsDirection, QueueSort } from "./remediation-queue-model"

export type FindingsTableSelection = {
  allState: SelectAllState
  isSelected: (findingId: string) => boolean
  onToggle: (findingId: string, checked: boolean) => void
  onToggleAll: (checked: boolean) => void
}

type BuildFindingsColumnsOptions = {
  findingDirection: FindingsDirection
  findingSearch: FindingsUrlSearch
  onOpenSheet: (finding: FindingPublic) => void
  onSort: (sort: QueueSort) => void
  queueSort: QueueSort
  selection?: FindingsTableSelection
}

function selectionColumn(
  selection: FindingsTableSelection,
): VpwDataTableColumn<FindingPublic> {
  return {
    id: "select",
    header: (
      <Checkbox
        aria-label="Select all findings on this page"
        checked={selection.allState}
        onCheckedChange={(checked) => selection.onToggleAll(checked === true)}
      />
    ),
    cell: (finding) => (
      <Checkbox
        aria-label={`Select ${findingActionLabel(finding)}`}
        checked={selection.isSelected(finding.id)}
        onCheckedChange={(checked) =>
          selection.onToggle(finding.id, checked === true)
        }
      />
    ),
    className: "w-[2.75rem] px-2",
    headerClassName: "w-[2.75rem] px-2",
    width: "2.75rem",
  }
}

export function buildFindingsDataTableColumns({
  findingDirection,
  findingSearch,
  onOpenSheet,
  onSort,
  queueSort,
  selection,
}: BuildFindingsColumnsOptions): readonly VpwDataTableColumn<FindingPublic>[] {
  const sortable = (sort: QueueSort, label: string): VpwDataTableSort => ({
    active: queueSort === sort,
    direction: queueSort === sort ? findingDirection : undefined,
    label,
    onSort: () => onSort(sort),
  })
  const ariaSort = (...sorts: QueueSort[]) =>
    sorts
      .map((sort) => sortAriaState(findingDirection, queueSort, sort))
      .find(Boolean)

  // Eight columns fit a 1,280 px laptop screen: priority and score share a
  // cell, "why now" sits under the finding, and the owner under the asset.
  return [
    ...(selection ? [selectionColumn(selection)] : []),
    {
      id: "priority",
      header: (
        <div className="finding-sort-pair">
          <VpwTableSortButton sort={sortable("priority", "Priority")}>
            Priority
          </VpwTableSortButton>
          <VpwTableSortButton sort={sortable("score", "Score")}>
            Score
          </VpwTableSortButton>
        </div>
      ),
      ariaSort: ariaSort("priority", "score"),
      cell: (finding) => <FindingPriorityCell finding={finding} />,
      width: "6.75rem",
    },
    {
      id: "finding",
      header: (
        <div className="finding-sort-pair">
          <VpwTableSortButton sort={sortable("cve", "Finding")}>
            Finding
          </VpwTableSortButton>
          <VpwTableSortButton sort={sortable("component", "Component")}>
            Component
          </VpwTableSortButton>
        </div>
      ),
      ariaSort: ariaSort("cve", "component"),
      cell: (finding) => {
        const actionLabel = findingActionLabel(finding)
        const whyNow = findingWhyNow(finding)
        return (
          <div className="finding-primary-cell">
            <Link
              className="finding-cve-link"
              params={{ findingId: finding.id }}
              search={findingSearch}
              title={`Open finding ${actionLabel}`}
              to="/findings/$findingId"
            >
              {finding.cve_id}
            </Link>
            <strong
              className="finding-component-name"
              title={finding.component_purl ?? componentLabel(finding)}
            >
              {componentLabel(finding)}
            </strong>
            {isActionableFinding(finding) ? (
              <span className="finding-why-now" title={whyNow}>
                {findingWhyNowCompact(finding)}
              </span>
            ) : null}
          </div>
        )
      },
      className: "min-w-0",
    },
    {
      id: "asset",
      header: "Asset / Owner",
      ariaSort: ariaSort("owner"),
      cell: (finding) => (
        <div className="finding-asset-cell">
          <strong className="block truncate" title={assetLabel(finding)}>
            {assetLabel(finding)}
          </strong>
          <span
            className="remediation-subtext truncate"
            title={`Service: ${serviceLabel(finding)}`}
          >
            {serviceLabel(finding)}
          </span>
          <span
            className="remediation-subtext truncate"
            title={`Owner: ${ownerLabel(finding)}`}
          >
            <span className="sr-only">Owner: </span>
            {ownerLabel(finding)}
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
      className: "min-w-0",
      sort: sortable("owner", "Owner"),
      width: "19%",
    },
    {
      id: "signals",
      header: "Signals",
      ariaSort: ariaSort("epss"),
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
      sort: sortable("epss", "Signals"),
      width: "7.25rem",
    },
    {
      id: "status",
      header: "Status / SLA",
      ariaSort: ariaSort("status"),
      cell: (finding) => <FindingStatusCell finding={finding} />,
      sort: sortable("status", "Status / SLA"),
      width: "11.5rem",
    },
    {
      id: "view",
      header: "Actions",
      cell: (finding) => {
        const actionLabel = findingActionLabel(finding)
        return (
          <div className="vpw-table-actions">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  aria-label={`Quick view ${actionLabel}`}
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
                    aria-label={`Open full detail ${actionLabel}`}
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
        )
      },
      // Stays in view when a narrow screen scrolls the table sideways.
      className: "finding-actions-column px-2 text-right",
      headerClassName:
        "finding-actions-column finding-actions-header px-2 text-right",
      width: "5.25rem",
    },
  ]
}

/** Priority and score for open work; closed findings are no longer ranked. */
function FindingPriorityCell({ finding }: { finding: FindingPublic }) {
  if (!isActionableFinding(finding)) {
    return (
      <span
        className="finding-priority-closed"
        title="Closed findings are not ranked; the score applies to open work."
      >
        {labelize(finding.priority ?? "unknown")}
      </span>
    )
  }
  return (
    <div className="finding-priority-cell">
      <RiskBadge density="compact" level={finding.priority} />
      <RiskScoreBadge density="compact" value={finding.risk_score} />
    </div>
  )
}

/** Status, the SLA of open work, and when the finding was last seen. */
function FindingStatusCell({ finding }: { finding: FindingPublic }) {
  const open = isActionableFinding(finding)
  return (
    <div className="finding-status-cell">
      <div className="finding-meta-tags">
        <StatusLozenge density="compact" status={finding.status} />
        {finding.under_investigation ? <MetaTag label="Under review" /> : null}
        {finding.waived ? <MetaTag label="Accepted risk" /> : null}
      </div>
      <SlaDueBadge finding={finding} overflow="wrap" />
      {open ? (
        <span className="remediation-subtext">
          SLA {findingSlaLabel(finding)}
        </span>
      ) : null}
      <span
        className="remediation-subtext"
        title={`Last seen ${formatDateTime(finding.last_seen_at)}`}
      >
        Last seen {formatDate(finding.last_seen_at)}
      </span>
    </div>
  )
}
