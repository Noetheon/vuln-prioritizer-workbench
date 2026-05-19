import type {
  FindingDetailRow,
  FindingOccurrenceRow,
} from "./finding-detail-model"
import {
  FindingDataQualityPanel,
  type FindingDataQualityRow,
} from "./FindingDataQualityPanel"
import { FindingEvidenceSummaryGrid } from "./FindingEvidenceSummaryGrid"
import { FindingOccurrencesPanel } from "./FindingOccurrencesPanel"

export type FindingEvidenceTabProps = {
  dataQualityRows: readonly FindingDataQualityRow[]
  evidenceRows: readonly FindingDetailRow[]
  occurrences: readonly FindingOccurrenceRow[]
}

export function FindingEvidenceTab({
  dataQualityRows,
  evidenceRows,
  occurrences,
}: FindingEvidenceTabProps) {
  return (
    <section
      aria-label="Evidence workspace"
      className="finding-evidence-tab-layout"
    >
      <FindingEvidenceSummaryGrid evidenceRows={evidenceRows} />

      <section
        aria-label="Evidence detail"
        className="finding-evidence-detail-grid"
      >
        <FindingOccurrencesPanel occurrences={occurrences} />
        <FindingDataQualityPanel dataQualityRows={dataQualityRows} />
      </section>
    </section>
  )
}
