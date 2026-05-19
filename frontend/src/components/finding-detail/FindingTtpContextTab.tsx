import {
  VpwBadge,
  type VpwBadgeTone,
  VpwStatusBanner,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"

import type { FindingAttackContext } from "./finding-detail-model"
import {
  attackContextEmptyState,
  attackCoverageStatusLabel,
  attackSourceLabel,
  attackTacticsLabel,
  attackTechniqueRows,
  defensiveActionItems,
} from "./finding-detail-model"
import {
  FindingTtpContextHero,
  FindingTtpDecisionCards,
  FindingTtpDecisionFlow,
} from "./FindingTtpContextSections"
import { FindingTtpTechnicalEvidence } from "./FindingTtpTechnicalEvidence"

function mappingTone(
  context: FindingAttackContext | null,
  source: string | null | undefined,
): VpwBadgeTone {
  if (source?.toLowerCase().includes("demo")) {
    return "support"
  }
  return context?.mapped ? "success" : "neutral"
}

export type FindingTtpContextTabProps = {
  attackContext: FindingAttackContext | null
}

export function FindingTtpContextTab({
  attackContext,
}: FindingTtpContextTabProps) {
  const attackTechniques = attackTechniqueRows(attackContext)
  const primaryTechnique = attackTechniques[0] ?? null
  const actionItems = defensiveActionItems(primaryTechnique?.defensive_note)
  const coverageStatus = attackCoverageStatusLabel(attackContext)
  const tacticLabel = attackTacticsLabel(
    primaryTechnique?.tactics ?? attackContext?.tactics,
  )
  const techniqueId = primaryTechnique?.technique_id ?? "Technique"
  const techniqueName = primaryTechnique?.name ?? "Technique"
  const techniqueLabel = `${techniqueId} ${techniqueName}`
  const attackSource = attackSourceLabel(
    primaryTechnique?.source ?? attackContext?.source,
    attackContext,
  )
  const attackRationale =
    primaryTechnique?.rationale ?? attackContext?.rationale
  const attackEmpty = attackContextEmptyState(attackContext)

  return (
    <VpwSurface
      aria-label="TTP Context"
      className="finding-tab-card finding-ttp-card"
    >
      <VpwSurfaceHeader className="finding-ttp-card-header">
        <div className="finding-card-heading">
          <div>
            <VpwSurfaceDescription>ATT&amp;CK</VpwSurfaceDescription>
            <VpwSurfaceTitle>TTP Context</VpwSurfaceTitle>
          </div>
          <VpwBadge tone={mappingTone(attackContext, attackSource)}>
            {attackSource?.toLowerCase().includes("demo")
              ? "Curated demo mapping"
              : attackContext?.mapped
                ? "Mapped context"
                : "No approved mapping"}
          </VpwBadge>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody className="finding-ttp-card-content">
        {attackEmpty ? (
          <section
            aria-label="TTP context empty state"
            className="finding-empty-panel-shell"
          >
            <VpwStatusBanner
              className="finding-empty-panel"
              title="Defensive context"
              tone="info"
            >
              No approved ATT&amp;CK mapping is stored for this finding.
              Workbench does not infer tactics or techniques for unmapped CVEs.
              Add a reviewed CTID or curated local mapping before using
              ATT&amp;CK context in queue decisions.
            </VpwStatusBanner>
          </section>
        ) : (
          <>
            <FindingTtpContextHero
              attackContext={attackContext}
              attackSource={attackSource}
              coverageStatus={coverageStatus}
              tacticLabel={tacticLabel}
              techniqueLabel={techniqueLabel}
            />

            <FindingTtpDecisionFlow
              coverageStatus={coverageStatus}
              techniqueId={techniqueId}
            />

            <FindingTtpDecisionCards actionItems={actionItems} />

            <FindingTtpTechnicalEvidence
              attackContext={attackContext}
              attackRationale={attackRationale}
              attackTechniques={attackTechniques}
            />
          </>
        )}
        {attackEmpty ? (
          <VpwStatusBanner
            className="finding-detection-note"
            title="Detection coverage"
            tone="warning"
          >
            {optionalText(
              attackContext?.defensive_note ??
                "Coverage controls are not connected to this finding yet. Record detection and mitigation evidence when available.",
            )}
          </VpwStatusBanner>
        ) : null}
        <VpwStatusBanner
          className="finding-defensive-note"
          title="Defensive context only"
          tone="info"
        >
          No exploit steps, payloads, PoC guidance, active probing, or offensive
          procedure instructions.
        </VpwStatusBanner>
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
