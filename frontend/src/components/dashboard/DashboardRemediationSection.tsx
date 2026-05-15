import { Link } from "@/lib/router"
import { ArrowUpRight, Eye, Search } from "lucide-react"
import type { FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  VpwDataTable,
  type VpwDataTableColumn,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { RiskScore } from "../risk/RiskScore"
import { SeverityBadge } from "../risk/SeverityBadge"
import { EmptyState, ErrorState } from "../states"
import { findingWhyNow } from "./dashboard-model"

type DashboardRemediationSectionProps = {
  findingsError: string
  findingsLoading: boolean
  onQueueSearchChange: (value: string) => void
  queueFindings: readonly FindingPublic[]
  queueSearch: string
  selectedProjectId: string
}

export function DashboardRemediationSection({
  findingsError,
  findingsLoading,
  onQueueSearchChange,
  queueFindings,
  queueSearch,
  selectedProjectId,
}: DashboardRemediationSectionProps) {
  const previewFindings = queueFindings.slice(0, 5)
  const queueProjectId = selectedProjectId || queueFindings[0]?.project_id || ""
  const fullQueueSearch = selectedProjectRouteSearch(queueProjectId)
  const columns: readonly VpwDataTableColumn<FindingPublic>[] = [
    {
      id: "priority",
      header: "Priority",
      cell: (finding) => <SeverityBadge severity={finding.priority} />,
      className: "w-20",
      headerClassName: "w-20",
    },
    {
      id: "score",
      header: (
        <Tooltip>
          <TooltipTrigger className="cursor-default underline decoration-dotted underline-offset-2">
            Risk Score
          </TooltipTrigger>
          <TooltipContent className="max-w-56 text-xs" side="top">
            Composite score (0-10) combining CVSS severity, EPSS exploitation
            probability, KEV status, and asset exposure.
          </TooltipContent>
        </Tooltip>
      ),
      cell: (finding) => <RiskScore value={finding.risk_score} />,
      className: "w-20",
      headerClassName: "w-20",
    },
    {
      id: "cve",
      header: "CVE",
      cell: (finding) => (
        <Button
          asChild
          className="h-auto px-0 font-mono text-sm"
          variant="link"
        >
          <Link
            params={{ findingId: finding.id }}
            search={selectedProjectRouteSearch(finding.project_id)}
            to="/findings/$findingId"
          >
            {finding.cve_id}
          </Link>
        </Button>
      ),
      className: "w-36",
      headerClassName: "w-36",
    },
    {
      id: "component",
      header: "Component / Service",
      cell: (finding) => (
        <div className="max-w-[140px] min-w-0">
          <p className="truncate text-sm font-medium">
            {optionalText(finding.component_name)}
          </p>
          <p className="truncate text-xs text-muted-foreground">
            {optionalText(finding.business_service)}
          </p>
        </div>
      ),
      className: "w-36",
      headerClassName: "w-36",
    },
    {
      id: "owner",
      header: "Owner",
      cell: (finding) => optionalText(finding.owner),
      className: "w-24 text-sm",
      headerClassName: "w-24",
    },
    {
      id: "why",
      header: "Why now",
      cell: (finding) => (
        <span className="dashboard-queue-why" title={findingWhyNow(finding)}>
          {findingWhyNow(finding)}
        </span>
      ),
      className: "w-52",
      headerClassName: "w-52",
    },
    {
      id: "view",
      header: <span className="sr-only">View</span>,
      cell: (finding) => (
        <Sheet>
          <SheetTrigger asChild>
            <Button
              aria-label="View finding"
              className="size-8"
              size="icon"
              variant="default"
            >
              <Eye aria-hidden="true" className="size-3.5" />
            </Button>
          </SheetTrigger>
          <SheetContent className="w-[calc(100vw-2rem)] max-w-[460px] overflow-y-auto sm:w-[460px]">
            <SheetHeader>
              <SheetTitle className="font-mono">
                {finding.cve_id ?? "Finding"}
              </SheetTitle>
              <SheetDescription>
                Quick view - open full detail for complete context.
              </SheetDescription>
            </SheetHeader>
            <div className="mt-6 flex flex-col gap-5">
              <div className="flex flex-wrap gap-2">
                <SeverityBadge severity={finding.priority} />
                <RiskScore value={finding.risk_score} />
              </div>
              <dl className="flex flex-col gap-3 text-sm">
                <div>
                  <dt className="text-xs font-semibold uppercase text-muted-foreground">
                    Component
                  </dt>
                  <dd className="mt-0.5">{finding.component_name ?? "-"}</dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold uppercase text-muted-foreground">
                    Service
                  </dt>
                  <dd className="mt-0.5">{finding.business_service ?? "-"}</dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold uppercase text-muted-foreground">
                    Owner
                  </dt>
                  <dd className="mt-0.5">{finding.owner ?? "-"}</dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold uppercase text-muted-foreground">
                    Why now
                  </dt>
                  <dd className="mt-0.5 text-muted-foreground">
                    {findingWhyNow(finding)}
                  </dd>
                </div>
              </dl>
              <Button asChild className="w-full" size="sm" variant="outline">
                <Link
                  params={{ findingId: finding.id }}
                  search={selectedProjectRouteSearch(finding.project_id)}
                  to="/findings/$findingId"
                >
                  Open full detail
                </Link>
              </Button>
            </div>
          </SheetContent>
        </Sheet>
      ),
      className: "w-12",
      headerClassName: "w-12",
    },
  ]

  return (
    <VpwSurface className="gap-2 py-4">
      <VpwSurfaceHeader className="px-4">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <VpwSurfaceTitle>Top Remediation Queue</VpwSurfaceTitle>
            <VpwSurfaceDescription>
              Prioritized items ranked by risk score for immediate action.
            </VpwSurfaceDescription>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <Input
              aria-label="Filter remediation queue"
              className="w-56 max-w-full"
              onChange={(event) =>
                onQueueSearchChange(event.currentTarget.value)
              }
              placeholder="Filter CVE, owner, component…"
              value={queueSearch}
            />
            <Button
              aria-label="Search"
              size="icon"
              type="button"
              variant="secondary"
            >
              <Search className="size-4" />
            </Button>
            <Button asChild size="sm" variant="outline">
              <Link search={fullQueueSearch} to="/findings">
                View full queue
                <ArrowUpRight aria-hidden="true" className="size-3.5" />
              </Link>
            </Button>
          </div>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody className="px-0 pb-2">
        {findingsLoading ? (
          <div className="px-6">
            <Skeleton className="h-64" />
          </div>
        ) : findingsError ? (
          <div className="px-6">
            <ErrorState message={findingsError} />
          </div>
        ) : previewFindings.length === 0 ? (
          <div className="px-6">
            <EmptyState
              ariaLabel="No remediation queue items"
              compact
              detail={
                queueSearch
                  ? "No rows match the current filter."
                  : "No items are currently available for remediation from this project."
              }
              title={queueSearch ? "No matching findings" : "No findings"}
            />
          </div>
        ) : (
          <VpwDataTable
            ariaLabel="Top remediation queue"
            caption="Dashboard remediation table"
            className="rounded-none border-x-0 border-b-0 shadow-none"
            columns={columns}
            data={previewFindings}
            getRowKey={(finding) => finding.id}
            minWidth="1060px"
            tableClassName="table-fixed"
          />
        )}
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
