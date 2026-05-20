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

function uniqueDataQualityRows(rows: readonly FindingDataQualityRow[]) {
  const seen = new Set<string>()
  return rows.filter((row) => {
    const key = `${row.severity}:${row.source}:${row.message}`
    if (seen.has(key)) {
      return false
    }
    seen.add(key)
    return true
  })
}

export function FindingDataQualityPanel({
  dataQualityRows,
}: FindingDataQualityPanelProps) {
  const uniqueRows = uniqueDataQualityRows(dataQualityRows)

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
