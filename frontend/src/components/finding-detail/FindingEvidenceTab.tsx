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
      <div className="finding-tab-intro">
        <span>Evidence</span>
        <h3>Evidence used for this decision</h3>
        <p>
          Provider facts, imported source evidence, occurrence rows, data
          quality notes, and artifact references that support the recorded
          priority.
        </p>
      </div>
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
