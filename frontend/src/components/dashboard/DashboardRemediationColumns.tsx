import { Link } from "@/lib/router"
import { Eye } from "lucide-react"
import type { FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  DefinitionList,
  DetailDrawer,
  type VpwDataTableColumn,
} from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { RiskScore } from "../risk/RiskScore"
import { SeverityBadge } from "../risk/SeverityBadge"
import {
  findingAssetServiceLabel,
  findingPlannedAction,
  findingWhyNow,
} from "./dashboard-model"

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
            Composite score (0-100) combining CVSS severity, EPSS exploitation
            probability, KEV status, and the asset context of this occurrence.
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
      header: "Component / Asset",
      cell: (finding) => (
        <div className="max-w-[180px] min-w-0">
          <p className="truncate text-sm font-medium">
            {optionalText(finding.component_name)}
          </p>
          <p className="truncate text-xs text-muted-foreground">
            {findingAssetServiceLabel(finding)}
          </p>
        </div>
      ),
      className: "w-44",
      headerClassName: "w-44",
    },
    {
      id: "owner",
      header: "Owner",
      cell: (finding) => optionalText(finding.owner),
      className: "w-24 text-sm",
      headerClassName: "w-24",
    },
    {
      id: "action",
      header: "Planned action",
      cell: (finding) => (
        <span
          className="dashboard-queue-why"
          title={findingPlannedAction(finding)}
        >
          {findingPlannedAction(finding)}
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
          <DetailDrawer
            className="w-[calc(100vw-2rem)] max-w-[460px] sm:w-[460px]"
            description="Quick view - open full detail for complete context."
            footer={
              <Button asChild className="w-full" size="sm" variant="outline">
                <Link
                  params={{ findingId: finding.id }}
                  search={selectedProjectRouteSearch(finding.project_id)}
                  to="/findings/$findingId"
                >
                  Open full detail
                </Link>
              </Button>
            }
            status={
              <>
                <SeverityBadge severity={finding.priority} />
                <RiskScore value={finding.risk_score} />
              </>
            }
            title={
              <span className="font-mono">{finding.cve_id ?? "Finding"}</span>
            }
            trigger={
              <Button
                aria-label={`View ${finding.cve_id}`}
                className="vpw-table-action-button"
                size="icon-sm"
                variant="outline"
              >
                <Eye aria-hidden="true" className="size-3.5" />
              </Button>
            }
          >
            <DefinitionList
              items={[
                {
                  label: "Component",
                  value: finding.component_name ?? "-",
                },
                {
                  label: "Asset",
                  value: finding.asset_name ?? finding.asset_key ?? "-",
                },
                {
                  label: "Service",
                  value: finding.business_service ?? "-",
                },
                {
                  label: "Owner",
                  value: finding.owner ?? "-",
                },
                {
                  label: "Planned action",
                  value: findingPlannedAction(finding),
                },
                {
                  label: "Why now",
                  value: findingWhyNow(finding),
                },
              ]}
            />
          </DetailDrawer>
        </div>
      ),
      className: "w-12",
      headerClassName: "w-12",
    },
  ]
}
