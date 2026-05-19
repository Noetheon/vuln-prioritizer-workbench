import { VpwBadge, type VpwBadgeTone } from "@/components/vpw"

import type { FindingAttackContext } from "./finding-detail-model"
import { attackConfidenceLabel } from "./finding-detail-model"

export function confidenceTone(value: string | null | undefined): VpwBadgeTone {
  return value === "high" ? "success" : value === "low" ? "critical" : "warning"
}

export function FindingTtpContextHero({
  attackContext,
  attackSource,
  coverageStatus,
  tacticLabel,
  techniqueLabel,
}: {
  attackContext: FindingAttackContext | null
  attackSource: string | null
  coverageStatus: string
  tacticLabel: string
  techniqueLabel: string
}) {
  return (
    <section
      aria-label="Threat informed context"
      className="finding-ttp-context-hero finding-ttp-context-hero-simple"
    >
      <div className="finding-ttp-main-copy">
        <span>Threat informed context</span>
        <h3>{techniqueLabel}</h3>
        <p>
          This mapping explains why the finding is treated as an internet-facing
          Initial Access risk. It supports remediation priority and detection
          coverage review, but does not prove exploitation.
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
          <dd>{attackSource ?? "Not supplied"}</dd>
        </div>
        <div>
          <dt>Coverage</dt>
          <dd>{coverageStatus}</dd>
        </div>
      </dl>
    </section>
  )
}

export function FindingTtpDecisionFlow({
  coverageStatus,
  techniqueId,
}: {
  coverageStatus: string
  techniqueId: string
}) {
  return (
    <ol
      aria-label="Attack chain and decision flow"
      className="finding-ttp-chain finding-ttp-chain-compact"
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
  )
}

export function FindingTtpDecisionCards({
  actionItems,
}: {
  actionItems: readonly string[]
}) {
  const defensiveActions =
    actionItems.length > 0
      ? actionItems
      : [
          "Patch or mitigate the vulnerable service.",
          "Restrict exposure while remediation is in progress.",
          "Validate web, proxy, WAF, EDR and application telemetry.",
          "Document detection coverage and residual risk.",
        ]

  return (
    <section
      aria-label="Threat informed decision context"
      className="finding-ttp-decision-grid finding-ttp-decision-grid-simple"
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
          {defensiveActions.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </article>
    </section>
  )
}
