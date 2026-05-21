import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"
import { uniqueFindingDataQualityRows } from "./finding-detail-model"

export type FindingDataQualityRow = {
  code: string
  key: string
  message: string
  severity: string
  source: string
}

type FindingDataQualityPanelProps = {
  dataQualityRows: readonly FindingDataQualityRow[]
}

export function FindingDataQualityPanel({
  dataQualityRows,
}: FindingDataQualityPanelProps) {
  const uniqueRows = uniqueFindingDataQualityRows(dataQualityRows)

  return (
    <VpwSurface
      aria-label="Data quality notes"
      className="finding-tab-card finding-data-quality-card"
    >
      <VpwSurfaceHeader>
        <VpwSurfaceDescription>Provider data</VpwSurfaceDescription>
        <VpwSurfaceTitle>Data quality notes</VpwSurfaceTitle>
      </VpwSurfaceHeader>
      <VpwSurfaceBody>
        {uniqueRows.length > 0 ? (
          <ul className="finding-data-quality-list">
            {uniqueRows.map((flag) => (
              <li key={flag.key}>
                <strong>{labelize(flag.code)}</strong>
                <span>
                  {flag.source} / {labelize(flag.severity)}
                </span>
                <p>{flag.message}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">
            No data quality flags recorded.
          </p>
        )}
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
