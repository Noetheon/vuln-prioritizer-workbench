import {
  VpwBadge,
  type VpwBadgeTone,
  VpwDataTable,
  type VpwDataTableColumn,
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
  attackConfidenceLabel,
  attackContextEmptyState,
  attackCoverageStatusLabel,
  attackSourceLabel,
  attackTacticsLabel,
  attackTechniqueRows,
  defensiveActionItems,
} from "./finding-detail-model"

type FindingAttackTechnique = ReturnType<typeof attackTechniqueRows>[number]

function confidenceTone(value: string | null | undefined): VpwBadgeTone {
  return value === "high" ? "success" : value === "low" ? "critical" : "warning"
}

function mappingTone(
  context: FindingAttackContext | null,
  source: string | null | undefined,
): VpwBadgeTone {
  if (source?.toLowerCase().includes("demo")) {
    return "support"
  }
  return context?.mapped ? "success" : "neutral"
}

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
                    <VpwBadge tone={confidenceTone(attackContext?.confidence)}>
                      {attackConfidenceLabel(attackContext?.confidence)}
                    </VpwBadge>
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
