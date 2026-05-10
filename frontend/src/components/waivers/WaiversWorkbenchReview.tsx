import {
  type VpwBadgeTone,
  VpwEmptyState,
  VpwGrid,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwTimeline,
  VpwWaiverDecisionCard,
} from "@/components/vpw"
import { timelineItems } from "./waivers-workbench-model"

type ReviewQueueItem = {
  id: string
  owner: string
  reason: string
  reviewDate: string
  scope: string
  status: string
  statusTone: VpwBadgeTone
}

export function WaiverReviewSection({
  acceptedFindings,
  expired,
  expiringSoon,
  queue,
  reviewDue,
}: {
  acceptedFindings: string
  expired: string
  expiringSoon: string
  queue: readonly ReviewQueueItem[]
  reviewDue: string
}) {
  return (
    <VpwGrid columns={2}>
      <VpwPanel className="flex flex-col gap-5 p-5">
        <VpwSectionHeader
          description="Lifecycle checkpoints for accepted risk decisions."
          eyebrow="Review workflow"
          title="Governance timeline"
        />
        <VpwTimeline
          items={timelineItems({
            acceptedFindings,
            expired,
            expiringSoon,
            reviewDue,
          })}
        />
      </VpwPanel>

      <VpwSection>
        <VpwSectionHeader
          description="Waivers nearest review or expiry."
          eyebrow="Review queue"
          title="Owner follow-up"
        />
        {queue.length === 0 ? (
          <VpwPanel>
            <VpwEmptyState
              description="No waiver lifecycle debt is currently recorded for this project."
              title="No review queue"
            />
          </VpwPanel>
        ) : (
          <div className="grid gap-4">
            {queue.map((item) => (
              <VpwWaiverDecisionCard
                key={item.id}
                owner={item.owner}
                reason={`${item.scope}. ${item.reason}`}
                reviewDate={item.reviewDate}
                status={item.status}
                statusTone={item.statusTone}
              />
            ))}
          </div>
        )}
      </VpwSection>
    </VpwGrid>
  )
}
