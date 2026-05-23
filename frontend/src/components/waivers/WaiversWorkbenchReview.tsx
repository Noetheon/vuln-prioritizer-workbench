import {
  CountBadge,
  VpwBadge,
  type VpwBadgeTone,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwGrid,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
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
      <div className="vpw-table-cell-stack">
        <strong
          className="vpw-table-cell-primary vpw-table-cell-nowrap"
          title={row.owner}
        >
          {row.owner}
        </strong>
        <span className="vpw-table-cell-secondary">
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
  queue,
  waivers,
}: {
  queue: readonly ReviewQueueItem[]
  waivers: WaiversWorkbenchProps["waivers"]
}) {
  const rollups = ownerRollups(waivers)

  return (
    <VpwSection>
      <VpwPanel className="waivers-governance-panel">
        <div className="waivers-governance-header">
          <VpwSectionHeader
            description="Review queue and owner accountability for current accepted-risk decisions."
            eyebrow="Governance"
            title="Governance overview"
          />
        </div>
        <VpwGrid columns={2} className="waivers-governance-grid">
          <div className="waivers-governance-column">
            <VpwSectionHeader
              description="Decision lifecycle debt that needs owner follow-up."
              eyebrow="Review queue"
              title="Review queue"
            />
            {queue.length === 0 ? (
              <VpwEmptyState
                description="No accepted-risk lifecycle debt is currently recorded for this project."
                title="No review queue"
              />
            ) : (
              <ol className="waivers-review-queue-list">
                {queue.map((item) => (
                  <li className="waivers-review-row" key={item.id}>
                    <div className="waivers-review-row__main">
                      <div className="waivers-review-row__header">
                        <strong title={item.scope}>{item.scope}</strong>
                        <VpwBadge density="compact" tone={item.statusTone}>
                          {item.status}
                        </VpwBadge>
                      </div>
                      <p>{item.reason}</p>
                    </div>
                    <dl className="waivers-review-row__meta">
                      <div>
                        <dt>Owner</dt>
                        <dd>{item.owner}</dd>
                      </div>
                      <div>
                        <dt>Review</dt>
                        <dd>{item.reviewDate}</dd>
                      </div>
                    </dl>
                  </li>
                ))}
              </ol>
            )}
          </div>

          <div className="waivers-governance-column">
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
              className="waivers-owner-rollup-table"
              minWidth="520px"
            />
          </div>
        </VpwGrid>
      </VpwPanel>
    </VpwSection>
  )
}
