import {
  VpwKeyValueList,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
  VpwTimeline,
} from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"
import type { FindingWaiverEvidence } from "@/lib/waiver-view"

import type { FindingDetailRow } from "./finding-detail-model"

export type FindingHistoryTabProps = {
  historyRows: readonly FindingDetailRow[]
  waiverEvidence: FindingWaiverEvidence | null
}

export function FindingHistoryTab({
  historyRows,
  waiverEvidence,
}: FindingHistoryTabProps) {
  return (
    <>
      <section
        className="finding-history-timeline"
        aria-label="Finding history"
      >
        <VpwTimeline
          items={historyRows.map((row) => ({
            description: row.detail,
            meta: row.label,
            title: row.value,
          }))}
        />
      </section>
      {waiverEvidence ? (
        <VpwSurface
          aria-label="Accepted risk"
          className="finding-tab-card finding-accepted-risk-card"
        >
          <VpwSurfaceHeader>
            <VpwSurfaceDescription>Risk acceptance</VpwSurfaceDescription>
            <VpwSurfaceTitle>Accepted risk</VpwSurfaceTitle>
          </VpwSurfaceHeader>
          <VpwSurfaceBody>
            <VpwKeyValueList
              className="finding-decision-definition-list compact"
              columns={2}
              items={[
                {
                  label: "Owner",
                  value: optionalText(waiverEvidence.owner),
                },
                {
                  label: "Reason",
                  value: optionalText(waiverEvidence.reason),
                },
                {
                  label: "Expires",
                  value: optionalText(waiverEvidence.expiresOn),
                },
                {
                  label: "Review",
                  value: optionalText(waiverEvidence.reviewOn),
                },
                {
                  label: "Scope",
                  value: optionalText(
                    waiverEvidence.matchedScope ?? waiverEvidence.scope,
                  ),
                },
                {
                  label: "Approval",
                  value: optionalText(waiverEvidence.approvalRef),
                },
              ]}
            />
          </VpwSurfaceBody>
        </VpwSurface>
      ) : null}
    </>
  )
}
