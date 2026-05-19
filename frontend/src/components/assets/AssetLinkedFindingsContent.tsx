import { Link } from "@/lib/router"
import { Database } from "lucide-react"

import type { AssetPublic, FindingPublic } from "../../api-client"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"
import { selectedProjectRouteSearch } from "../../workbench/selected-project-search"
import { Button } from "../ui/button"
import {
  RiskBadge,
  StatusLozenge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwTableCard,
} from "../vpw"
import { assetFindingsHref, findingAssetLabel } from "./asset-model"

export function AssetLinkedFindingsContent({
  assetFindings,
  assetFindingsError,
  assetFindingsLoading,
  selectedAsset,
}: {
  assetFindings: FindingPublic[]
  assetFindingsError: string
  assetFindingsLoading: boolean
  selectedAsset: AssetPublic
}) {
  const findingColumns: readonly VpwDataTableColumn<FindingPublic>[] = [
    {
      cell: (finding) => <RiskBadge level={finding.priority} />,
      header: "Priority",
      id: "priority",
      width: "7rem",
    },
    {
      cell: (finding) => (
        <Link
          className="font-mono text-sm font-semibold text-[var(--vpw-blue)] hover:underline"
          params={{ findingId: finding.id }}
          search={selectedProjectRouteSearch(finding.project_id)}
          to="/findings/$findingId"
        >
          {finding.cve_id}
        </Link>
      ),
      header: "CVE",
      id: "cve",
      width: "10rem",
    },
    {
      cell: (finding) => optionalText(finding.component_name),
      header: "Component",
      id: "component",
    },
    {
      cell: (finding) => findingAssetLabel(finding),
      header: "Asset",
      id: "asset",
    },
    {
      cell: (finding) => (
        <StatusLozenge
          label={labelize(finding.status)}
          status={finding.status}
        />
      ),
      header: "Status",
      id: "status",
      width: "8rem",
    },
  ]

  return (
    <VpwTableCard
      actions={
        <Button asChild variant="outline">
          <a href={assetFindingsHref(selectedAsset)}>Open findings</a>
        </Button>
      }
      description="Findings returned by the existing project findings API for this asset."
      eyebrow="Linked findings"
      title="Findings for asset"
    >
      {assetFindingsError ? (
        <VpwStatusBanner title="Asset findings unavailable" tone="critical">
          {assetFindingsError}
        </VpwStatusBanner>
      ) : null}
      {assetFindingsLoading ? <VpwSkeletonStack rows={4} /> : null}
      {!assetFindingsLoading && assetFindings.length === 0 ? (
        <VpwEmptyState
          description="Import occurrence data that references this asset."
          icon={<Database aria-hidden="true" />}
          title={`No findings for ${selectedAsset.name}`}
        />
      ) : null}
      {assetFindings.length > 0 ? (
        <VpwDataTable
          caption="Asset findings table"
          columns={findingColumns}
          data={assetFindings}
          density="compact"
          getRowKey={(finding) => finding.id}
          minWidth="760px"
        />
      ) : null}
    </VpwTableCard>
  )
}
