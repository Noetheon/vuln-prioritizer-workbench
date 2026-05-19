import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
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
        <VpwSurface
          className={cn(
            "finding-evidence-summary-card",
            index === 0 ? "finding-evidence-summary-card-primary" : undefined,
            index > 0 ? "finding-evidence-summary-card-secondary" : undefined,
          )}
          key={row.label}
        >
          <VpwSurfaceHeader>
            <VpwSurfaceDescription className="finding-evidence-summary-description">
              {row.label}
            </VpwSurfaceDescription>
            <VpwSurfaceTitle className="finding-evidence-summary-title">
              {row.value}
            </VpwSurfaceTitle>
          </VpwSurfaceHeader>
          <VpwSurfaceBody>
            <p>{row.detail}</p>
          </VpwSurfaceBody>
        </VpwSurface>
      ))}
    </section>
  )
}
