import { Link } from "@/lib/router"
import { Eye } from "lucide-react"
import type { FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import type { VpwDataTableColumn } from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { RiskScore } from "../risk/RiskScore"
import { SeverityBadge } from "../risk/SeverityBadge"
import { findingWhyNow } from "./dashboard-model"

export function buildDashboardRemediationColumns(): readonly VpwDataTableColumn<FindingPublic>[] {
  return [
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
        <div className="vpw-table-actions">
          <Sheet>
            <SheetTrigger asChild>
              <Button
                aria-label={`View ${finding.cve_id}`}
                className="vpw-table-action-button"
                size="icon-sm"
                variant="outline"
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
                    <dd className="mt-0.5">
                      {finding.business_service ?? "-"}
                    </dd>
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
        </div>
      ),
      className: "w-12",
      headerClassName: "w-12",
    },
  ]
}
