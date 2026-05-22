import { cn } from "@/lib/utils"
import type { FindingDetailRow } from "./finding-detail-model"

type FindingEvidenceSummaryGridProps = {
  evidenceRows: readonly FindingDetailRow[]
}

export function FindingEvidenceSummaryGrid({
  evidenceRows,
}: FindingEvidenceSummaryGridProps) {
  return (
    <section className="finding-evidence-grid" aria-label="Evidence summary">
      {evidenceRows.map((row, index) => (
        <dl
          className={cn(
            "finding-evidence-summary-card",
            index === 0 ? "finding-evidence-summary-card-primary" : undefined,
            index > 0 ? "finding-evidence-summary-card-secondary" : undefined,
          )}
          key={row.label}
        >
          <dt className="finding-evidence-summary-description">{row.label}</dt>
          <dd className="finding-evidence-summary-title">{row.value}</dd>
          {row.detail ? <dd>{row.detail}</dd> : null}
        </dl>
      ))}
    </section>
  )
}
