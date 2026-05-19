import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"

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
        {dataQualityRows.length > 0 ? (
          <ul className="finding-data-quality-list">
            {dataQualityRows.map((flag) => (
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
