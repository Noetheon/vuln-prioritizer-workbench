import {
  CountBadge,
  type VpwBadgeTone,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwWaiverDecisionCard,
} from "@/components/vpw"
import {
  ownerRollups,
  type WaiverOwnerRollup,
  type WaiversWorkbenchProps,
} from "./waivers-workbench-model"

type ReviewQueueItem = {
  id: string
  owner: string
  reason: string
  reviewDate: string
  scope: string
  status: string
  statusTone: VpwBadgeTone
}

const ownerColumns: readonly VpwDataTableColumn<WaiverOwnerRollup>[] = [
  {
    cell: (row) => (
      <div className="grid gap-0.5">
        <strong className="text-sm text-[var(--vpw-text-primary)]">
          {row.owner}
        </strong>
        <span className="text-xs text-[var(--vpw-text-muted)]">
          accountable owner
        </span>
      </div>
    ),
    header: "Owner",
    id: "owner",
    width: "34%",
  },
  {
    cell: (row) => <CountBadge value={row.active} />,
    header: "Active",
    id: "active",
    width: "20%",
  },
  {
    cell: (row) => (
      <CountBadge
        tone={row.reviewDue > 0 ? "warning" : "neutral"}
        value={row.reviewDue}
      />
    ),
    header: "Review due",
    id: "review-due",
    width: "22%",
  },
  {
    cell: (row) => <CountBadge value={row.acceptedFindings} />,
    header: "Accepted findings",
    id: "accepted-findings",
    width: "24%",
  },
]

export function WaiverReviewSection({
  acceptedFindings,
  expired,
  expiringSoon,
  missingApprovals,
  queue,
  reviewDue,
  waivers,
}: {
  acceptedFindings: string
  expired: string
  expiringSoon: string
  missingApprovals: number
  queue: readonly ReviewQueueItem[]
  reviewDue: string
  waivers: WaiversWorkbenchProps["waivers"]
}) {
  const rollups = ownerRollups(waivers)

  return (
    <VpwSection>
      <VpwPanel className="flex flex-col gap-5 p-5">
        <VpwSectionHeader
          description="Review queue and owner accountability for current accepted-risk decisions."
          eyebrow="Governance"
          title="Governance overview"
        />
        <VpwGrid columns={2}>
          <div className="flex flex-col gap-4">
            <VpwSectionHeader
              description="Decision lifecycle debt that needs owner follow-up."
              eyebrow="Review queue"
              title="Review queue"
            />
            <VpwKeyValueList
              columns={2}
              density="compact"
              items={[
                {
                  label: "Review due",
                  tone: Number(reviewDue) > 0 ? "warning" : "neutral",
                  value: reviewDue,
                },
                {
                  label: "Expiring soon",
                  tone: Number(expiringSoon) > 0 ? "warning" : "neutral",
                  value: expiringSoon,
                },
                {
                  label: "Expired",
                  tone: Number(expired) > 0 ? "critical" : "neutral",
                  value: expired,
                },
                {
                  label: "Evidence incomplete",
                  tone: missingApprovals > 0 ? "warning" : "success",
                  value: missingApprovals,
                },
                {
                  label: "Accepted findings",
                  value: acceptedFindings,
                },
              ]}
            />
            {queue.length === 0 ? (
              <VpwEmptyState
                description="No accepted-risk lifecycle debt is currently recorded for this project."
                title="No review queue"
              />
            ) : (
              <div className="grid gap-3">
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
          </div>

          <div className="flex flex-col gap-4">
            <VpwSectionHeader
              description="Owners ranked by review pressure and accepted finding exposure."
              eyebrow="Owner rollup"
              title="Owner rollup"
            />
            <VpwDataTable
              ariaLabel="Accepted risk owner rollup"
              columns={ownerColumns}
              data={rollups}
              density="compact"
              emptyState={
                <VpwEmptyState
                  description="Record accepted risk to build owner accountability."
                  title="No owner rollup"
                />
              }
              getRowKey={(row) => row.owner}
              minWidth="560px"
            />
          </div>
        </VpwGrid>
      </VpwPanel>
    </VpwSection>
  )
}
