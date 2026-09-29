import { VpwTimeline } from "@/components/vpw"
import { FindingDecisionRevisions } from "./FindingDecisionRevisions"
import { FindingLifecycleHistory } from "./FindingLifecycleHistory"
import type { FindingDetailRow } from "./finding-detail-model"

export type FindingHistoryTabProps = {
  historyRows: readonly FindingDetailRow[]
  findingId: string
  projectId: string
}

export function FindingHistoryTab({
  historyRows,
  findingId,
  projectId,
}: FindingHistoryTabProps) {
  return (
    <section className="finding-history-tab-layout">
      <div className="finding-tab-intro">
        <span>History</span>
        <h3>Lifecycle and evidence timeline</h3>
        <p>
          First seen, last seen, current status, status changes with their
          reasons, and the VEX or waiver state recorded for this finding.
        </p>
      </div>
      <FindingLifecycleHistory
        key={`lifecycle:${findingId}`}
        findingId={findingId}
        projectId={projectId}
      />
      <FindingDecisionRevisions key={findingId} findingId={findingId} />
      <section
        className="finding-history-timeline"
        aria-label="Finding history"
      >
        <VpwTimeline
          items={historyRows.map((row) => ({
            description: row.detail,
            id: `${row.label}:${row.value}`,
            meta: row.label,
            title: row.value,
          }))}
        />
      </section>
    </section>
  )
}
