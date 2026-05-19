import {
  VpwBadge,
  VpwDataTable,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { stringValue } from "@/lib/app-errors"
import type { FindingOccurrenceRow } from "./finding-detail-model"
import { buildFindingOccurrenceColumns } from "./FindingOccurrencesColumns"

type FindingOccurrencesPanelProps = {
  occurrences: readonly FindingOccurrenceRow[]
}

export function FindingOccurrencesPanel({
  occurrences,
}: FindingOccurrencesPanelProps) {
  return (
    <VpwSurface
      aria-label="Scanner occurrences"
      className="finding-tab-card finding-occurrences-card"
    >
      <VpwSurfaceHeader>
        <div className="finding-card-heading">
          <div>
            <VpwSurfaceDescription>Scanner evidence</VpwSurfaceDescription>
            <VpwSurfaceTitle>Occurrences</VpwSurfaceTitle>
          </div>
          <VpwBadge tone="info">{occurrences.length} source row(s)</VpwBadge>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody>
        {occurrences.length > 0 ? (
          <VpwDataTable
            caption="Occurrences table"
            className="finding-detail-table-wrap"
            columns={buildFindingOccurrenceColumns()}
            data={occurrences}
            getRowKey={(occurrence, index) =>
              stringValue(occurrence.id) ?? `occurrence-${index + 1}`
            }
            minWidth="960px"
            variant="detail"
          />
        ) : (
          <p className="text-sm text-muted-foreground">
            No source occurrences have been recorded for this finding.
          </p>
        )}
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
