import type { FindingOccurrenceRow } from "./finding-detail-model"
import { FindingOccurrencesPanel } from "./FindingOccurrencesPanel"

export type FindingOccurrencesTabProps = {
  occurrences: readonly FindingOccurrenceRow[]
}

export function FindingOccurrencesTab({
  occurrences,
}: FindingOccurrencesTabProps) {
  return (
    <section
      aria-label="Affected occurrences"
      className="finding-occurrences-tab-layout"
    >
      <div className="finding-tab-intro">
        <span>Occurrences</span>
        <h3>Affected components and assets</h3>
        <p>
          Source occurrence rows that connect this CVE to components, package
          identifiers, assets, owners, service context, exposure, and fix or VEX
          state.
        </p>
      </div>
      <FindingOccurrencesPanel occurrences={occurrences} />
    </section>
  )
}
