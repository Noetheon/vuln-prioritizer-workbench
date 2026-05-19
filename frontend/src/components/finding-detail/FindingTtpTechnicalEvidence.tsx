import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
} from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"

import type { FindingAttackContext } from "./finding-detail-model"
import {
  attackConfidenceLabel,
  attackSourceLabel,
  attackTacticsLabel,
  defensiveActionItems,
  type attackTechniqueRows,
} from "./finding-detail-model"
import { confidenceTone } from "./FindingTtpContextSections"

type FindingAttackTechnique = ReturnType<typeof attackTechniqueRows>[number]

function techniqueColumns(
  context: FindingAttackContext | null,
): readonly VpwDataTableColumn<FindingAttackTechnique>[] {
  return [
    {
      cell: (technique) => (
        <>
          <span className="font-medium">{technique.technique_id}</span>
          <small className="vpw-table-subtext">
            {optionalText(technique.name)}
          </small>
        </>
      ),
      header: "Technique",
      id: "technique",
    },
    {
      cell: (technique) => attackTacticsLabel(technique.tactics),
      header: "Tactic",
      id: "tactic",
    },
    {
      cell: (technique) => (
        <VpwBadge tone={confidenceTone(technique.confidence)}>
          {attackConfidenceLabel(technique.confidence)}
        </VpwBadge>
      ),
      header: "Confidence",
      id: "confidence",
    },
    {
      cell: (technique) =>
        optionalText(attackSourceLabel(technique.source, context)),
      header: "Source",
      id: "source",
    },
    {
      cell: (technique) => optionalText(technique.rationale),
      header: "Rationale",
      id: "rationale",
    },
    {
      cell: (technique) => {
        const actionItems = defensiveActionItems(technique.defensive_note)
        return actionItems.length > 1 ? (
          <ul className="finding-ttp-actions-list">
            {actionItems.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          optionalText(technique.defensive_note)
        )
      },
      header: "Defensive actions",
      id: "actions",
    },
  ]
}

export type FindingTtpTechnicalEvidenceProps = {
  attackContext: FindingAttackContext | null
  attackRationale: string | null | undefined
  attackTechniques: readonly FindingAttackTechnique[]
}

export function FindingTtpTechnicalEvidence({
  attackContext,
  attackRationale,
  attackTechniques,
}: FindingTtpTechnicalEvidenceProps) {
  return (
    <details className="finding-ttp-technical-evidence finding-ttp-technical-details">
      <summary className="finding-ttp-technical-heading">
        <div>
          <span>Secondary evidence</span>
          <strong>Technical mapping details</strong>
        </div>
        <VpwBadge tone="info">Source, confidence, rationale</VpwBadge>
      </summary>

      <div className="finding-ttp-technical-body">
        <p>{optionalText(attackRationale)}</p>
        <VpwDataTable
          caption="TTP Context techniques"
          className="finding-detail-table-wrap"
          columns={techniqueColumns(attackContext)}
          data={attackTechniques}
          getRowKey={(technique) => technique.technique_id}
          minWidth="960px"
          variant="detail"
        />
      </div>
    </details>
  )
}
