import { Badge } from "@/components/ui/badge"
import {
  VpwDataTable,
  type VpwDataTableColumn,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { optionalText } from "@/lib/ui-copy"
import { cn } from "@/lib/utils"

import type { FindingAttackContext } from "./finding-detail-model"
import {
  attackConfidenceLabel,
  attackContextEmptyState,
  attackCoverageStatusLabel,
  attackSourceLabel,
  attackTacticsLabel,
  attackTechniqueRows,
  defensiveActionItems,
} from "./finding-detail-model"

type FindingAttackTechnique = ReturnType<typeof attackTechniqueRows>[number]

function confidenceBadgeClass(value: string | null | undefined) {
  return value === "high"
    ? "bg-green-100 text-green-700 border-green-200"
    : value === "low"
      ? "bg-red-100 text-red-700 border-red-200"
      : "bg-yellow-100 text-yellow-700 border-yellow-200"
}

function techniqueColumns(
  context: FindingAttackContext | null,
): readonly VpwDataTableColumn<FindingAttackTechnique>[] {
  return [
    {
      cell: (technique) => (
        <>
          <span className="font-medium">{technique.technique_id}</span>
          <small>{optionalText(technique.name)}</small>
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
        <Badge className={cn(confidenceBadgeClass(technique.confidence))}>
          {attackConfidenceLabel(technique.confidence)}
        </Badge>
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
      <VpwSurfaceHeader>
        <div className="finding-card-heading">
          <div>
            <VpwSurfaceDescription>ATT&amp;CK</VpwSurfaceDescription>
            <VpwSurfaceTitle>TTP Context</VpwSurfaceTitle>
          </div>
          <Badge variant="outline">
            {attackSource?.toLowerCase().includes("demo")
              ? "Curated demo mapping"
              : attackContext?.mapped
                ? "Mapped context"
                : "No approved mapping"}
          </Badge>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody>
        {attackEmpty ? (
          <section
            aria-label="TTP context empty state"
            className="finding-empty-panel"
          >
            <div className="finding-empty-panel-heading">
              <Badge variant="outline">Defensive context</Badge>
              <strong>
                No approved ATT&amp;CK mapping is stored for this finding.
              </strong>
            </div>
            <p>
              Workbench does not infer tactics or techniques for unmapped CVEs.
              Add a reviewed CTID or curated local mapping before using
              ATT&amp;CK context in queue decisions.
            </p>
          </section>
        ) : (
          <>
            <section
              className="finding-ttp-context-hero finding-ttp-context-hero-simple"
              aria-label="Threat informed context"
            >
              <div className="finding-ttp-main-copy">
                <span>Threat informed context</span>
                <h3>{techniqueLabel}</h3>
                <p>
                  This mapping explains why the finding is treated as an
                  internet-facing Initial Access risk. It supports remediation
                  priority and detection coverage review, but does not prove
                  exploitation.
                </p>
              </div>
              <dl className="finding-ttp-main-facts">
                <div>
                  <dt>Tactic</dt>
                  <dd>{tacticLabel}</dd>
                </div>
                <div>
                  <dt>Confidence</dt>
                  <dd>
                    <Badge
                      className={cn(
                        confidenceBadgeClass(attackContext?.confidence),
                      )}
                    >
                      {attackConfidenceLabel(attackContext?.confidence)}
                    </Badge>
                  </dd>
                </div>
                <div>
                  <dt>Source</dt>
                  <dd>{optionalText(attackSource)}</dd>
                </div>
                <div>
                  <dt>Coverage</dt>
                  <dd>{coverageStatus}</dd>
                </div>
              </dl>
            </section>

            <ol
              className="finding-ttp-chain finding-ttp-chain-compact"
              aria-label="Attack chain and decision flow"
            >
              <li data-tone="signal">
                <span className="finding-ttp-chain-index">1</span>
                <div>
                  <small>CVE signal</small>
                  <strong>High priority signal</strong>
                </div>
              </li>
              <li data-tone="exposure">
                <span className="finding-ttp-chain-index">2</span>
                <div>
                  <small>Internet-facing asset</small>
                  <strong>Internet facing asset</strong>
                </div>
              </li>
              <li data-tone="technique">
                <span className="finding-ttp-chain-index">3</span>
                <div>
                  <small>ATT&amp;CK technique</small>
                  <strong>{techniqueId}</strong>
                </div>
              </li>
              <li data-tone="coverage">
                <span className="finding-ttp-chain-index">4</span>
                <div>
                  <small>Detection gap</small>
                  <strong>{coverageStatus}</strong>
                </div>
              </li>
              <li data-tone="decision">
                <span className="finding-ttp-chain-index">5</span>
                <div>
                  <small>Remediation priority</small>
                  <strong>Emergency remediation</strong>
                </div>
              </li>
            </ol>

            <section
              className="finding-ttp-decision-grid finding-ttp-decision-grid-simple"
              aria-label="Threat informed decision context"
            >
              <article className="finding-ttp-narrative-card">
                <span>Why this matters</span>
                <strong>Decision support</strong>
                <ul className="finding-ttp-meaning-list">
                  <li>Frames the CVE as an Initial Access risk.</li>
                  <li>Explains why internet exposure raises urgency.</li>
                  <li>Connects remediation priority with detection review.</li>
                  <li>Keeps the boundary clear: no proof of exploitation.</li>
                </ul>
              </article>
              <article className="finding-ttp-narrative-card finding-ttp-actions-card">
                <span>Recommended defensive actions</span>
                <strong>Close exposure and validate coverage</strong>
                <ul className="finding-ttp-checklist">
                  {(actionItems.length > 0
                    ? actionItems
                    : [
                        "Patch or mitigate the vulnerable service.",
                        "Restrict exposure while remediation is in progress.",
                        "Validate web, proxy, WAF, EDR and application telemetry.",
                        "Document detection coverage and residual risk.",
                      ]
                  ).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </article>
            </section>

            <details className="finding-ttp-technical-evidence finding-ttp-technical-details">
              <summary className="finding-ttp-technical-heading">
                <div>
                  <span>Secondary evidence</span>
                  <strong>Technical mapping details</strong>
                </div>
                <Badge variant="outline">Source, confidence, rationale</Badge>
              </summary>

              <div className="finding-ttp-technical-body">
                <p>{optionalText(attackRationale)}</p>
                <VpwDataTable
                  caption="TTP Context techniques"
                  className="finding-detail-table-wrap"
                  columns={techniqueColumns(attackContext)}
                  data={attackTechniques}
                  getRowKey={(technique) => technique.technique_id}
                />
              </div>
            </details>
          </>
        )}
        {attackEmpty ? (
          <section
            className="finding-detection-note"
            aria-label="Detection coverage"
          >
            <span>Detection coverage</span>
            <p>
              {optionalText(
                attackContext?.defensive_note ??
                  "Coverage controls are not connected to this finding yet. Record detection and mitigation evidence when available.",
              )}
            </p>
          </section>
        ) : null}
        <p className="finding-defensive-note">
          Defensive context only. No exploit steps, payloads, PoC guidance,
          active probing, or offensive procedure instructions.
        </p>
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
