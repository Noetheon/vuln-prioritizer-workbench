import { Link } from "@/lib/router"
import { ShieldCheck } from "lucide-react"
import type { FindingDetailPublic, FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  RiskBadge,
  StatusLozenge,
  VpwBadge,
} from "@/components/vpw"
import {
  attackConfidenceLabel,
  attackTacticsLabel,
  findingSlaLabel,
  type FindingAttackContext,
  type FindingDetailRow,
  type FindingOccurrenceRow,
} from "@/components/finding-detail/finding-detail-model"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import type { ProjectUrlSearch } from "@/workbench/selected-project-search"
import {
  cvssText,
  DrawerFact,
  drawerAssetLabel,
  epssText,
  governanceCopy,
  occurrenceAssetLabel,
  occurrenceComponentLabel,
  occurrenceRowKey,
  occurrenceSourceLabel,
} from "./RemediationQueueQuickViewModel"

type QuickViewFinding = FindingPublic | FindingDetailPublic

type QuickViewDataQualityRow = {
  key: string
  message: string
  severity: string
}

type QuickViewAttackTechnique = {
  name?: string | null
  tactics?: string[] | null
  technique_id?: string | null
}

function compactDrawerText(value: string, maxLength = 260) {
  const compact = value.replace(/\s+/g, " ").trim()
  if (compact.length <= maxLength) return compact
  const sentence = compact.match(/^(.+?[.!?])(?:\s|$)/)?.[1]
  const candidate = sentence && sentence.length <= maxLength ? sentence : compact
  const words = candidate.split(/\s+/)
  let output = ""
  for (const word of words) {
    const next = output ? `${output} ${word}` : word
    if (next.length > maxLength - 3) break
    output = next
  }
  return `${output || candidate.slice(0, maxLength - 3).trimEnd()}...`
}

function uniqueDataQualityRows(rows: readonly QuickViewDataQualityRow[]) {
  const seen = new Set<string>()
  return rows.filter((row) => {
    const key = `${row.severity}:${row.message}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function actionParts(value: string) {
  if (/CISA KEV required action/i.test(value)) {
    return {
      detail:
        "CISA KEV requires remediation or removal where updates exist. Validate affected assets, then record the fix path in Triage.",
      title: "Apply fixed version or remove affected asset",
    }
  }
  const [label, ...rest] = value.split(":")
  const title = label.trim()
  if (title && rest.length > 0 && title.length <= 72) {
    return {
      detail: rest.join(":").trim(),
      title,
    }
  }
  return {
    detail: value,
    title: "Recommended remediation",
  }
}

function riskScoreLabel(value: QuickViewFinding["risk_score"]) {
  if (typeof value === "number") return `Risk ${value.toFixed(1)}`
  return value ? `Risk ${value}` : "Risk not scored"
}

function signalItems(finding: QuickViewFinding) {
  return [
    finding.in_kev
      ? {
          detail: "Known exploited vulnerability signal is present.",
          label: "CISA KEV",
          tone: "critical" as const,
        }
      : null,
    finding.epss !== null && finding.epss !== undefined
      ? {
          detail:
            finding.epss >= 0.7
              ? "Elevated exploitation probability."
              : "Provider probability signal recorded.",
          label: `EPSS ${epssText(finding)}`,
          tone: "warning" as const,
        }
      : null,
    finding.cvss_base_score !== null &&
    finding.cvss_base_score !== undefined
      ? {
          detail: "Impact severity score from vulnerability provider data.",
          label: `CVSS ${cvssText(finding)}`,
          tone: "critical" as const,
        }
      : null,
    finding.attack_mapped
      ? {
          detail: "Reviewed defensive mapping is available.",
          label: "ATT&CK mapped",
          tone: "support" as const,
        }
      : null,
    finding.suppressed_by_vex
      ? {
          detail: "Suppression state is recorded and should be validated.",
          label: "VEX state",
          tone: "info" as const,
        }
      : null,
  ].filter(
    (
      item,
    ): item is {
      detail: string
      label: string
      tone: "critical" | "warning" | "info" | "support"
    } => Boolean(item),
  )
}

function evidenceLabel(row: FindingDetailRow) {
  switch (row.label) {
    case "Provider snapshot":
      return "Provider signals"
    case "Input source":
      return "Input row"
    case "Scanner evidence":
      return "Scanner source"
    case "Data quality notes":
      return "Data quality"
    case "Report / artifact references":
      return "Artifact reference"
    default:
      return row.label
  }
}

function evidenceValue(row: FindingDetailRow) {
  if (
    row.label === "Provider snapshot" &&
    /field\(s\) recorded/.test(row.value)
  ) {
    return "CVSS, EPSS and CISA KEV signals recorded"
  }
  return row.value
}

function evidenceDetail(row: FindingDetailRow) {
  if (row.label === "Provider snapshot") {
    return row.detail?.includes("No provider gaps")
      ? "No provider signal gaps recorded."
      : row.detail
  }
  if (
    row.label === "Report / artifact references" &&
    row.value === "Not supplied"
  ) {
    return "No report artifact was supplied by the input data."
  }
  return row.detail
}

export function QuickViewStatusRow({ finding }: { finding: QuickViewFinding }) {
  return (
    <div className="finding-drawer-status-row">
      <RiskBadge density="compact" level={finding.priority} />
      <StatusLozenge density="compact" status={finding.status} />
      <VpwBadge density="compact" tone="critical">
        {riskScoreLabel(finding.risk_score)}
      </VpwBadge>
    </div>
  )
}

export function QuickViewDecisionSummary({
  finding,
  rationale,
  recommendedAction,
}: {
  finding: QuickViewFinding
  rationale: string
  recommendedAction: string
}) {
  const action = actionParts(recommendedAction)
  const assignment = [
    { label: "Owner", value: optionalText(finding.owner) },
    { label: "Service", value: optionalText(finding.business_service) },
    { label: "Asset", value: drawerAssetLabel(finding) },
    { label: "SLA", value: findingSlaLabel(finding.priority) },
  ]

  return (
    <section
      aria-label="Decision summary"
      className="finding-drawer-section finding-drawer-section--decision"
    >
      <div className="finding-drawer-decision-hero">
        <div className="finding-drawer-primary-action">
          <span>Recommended action</span>
          <strong>{action.title}</strong>
          <p title={recommendedAction}>{compactDrawerText(action.detail)}</p>
        </div>
      </div>
      <dl className="finding-drawer-assignment-strip">
        {assignment.map((item) => (
          <DrawerFact key={item.label} label={item.label} value={item.value} />
        ))}
      </dl>
      <div className="finding-drawer-why-now">
        <span>Why now</span>
        <p title={rationale}>{compactDrawerText(rationale, 320)}</p>
      </div>
    </section>
  )
}

export function QuickViewSignalBrief({
  finding,
}: {
  finding: QuickViewFinding
}) {
  const items = signalItems(finding)
  if (items.length === 0) return null

  return (
    <section
      aria-label="Risk signals"
      className="finding-drawer-section finding-drawer-section--signals"
    >
      <div className="finding-drawer-section-heading">
        <h3>Signals</h3>
        <span className="finding-drawer-section-meta">
          {items.length} active
        </span>
      </div>
      <ul className="finding-drawer-signal-grid">
        {items.map((item) => (
          <li data-tone={item.tone} key={item.label}>
            <strong>{item.label}</strong>
            <span>{item.detail}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

export function QuickViewEvidenceSnapshot({
  dataQualityRows,
  evidenceRows,
}: {
  dataQualityRows: readonly QuickViewDataQualityRow[]
  evidenceRows: readonly FindingDetailRow[]
}) {
  const dataQuality = uniqueDataQualityRows(dataQualityRows)

  return (
    <section
      aria-label="Evidence snapshot"
      className="finding-drawer-section finding-drawer-section--evidence"
    >
      <div className="finding-drawer-section-heading">
        <h3>Evidence snapshot</h3>
      </div>
      <dl className="finding-drawer-rows">
        {evidenceRows.slice(0, 5).map((row) => (
          <div key={row.label}>
            <dt>{evidenceLabel(row)}</dt>
            <dd>{evidenceValue(row)}</dd>
            {evidenceDetail(row) ? (
              <dd className="finding-drawer-evidence-detail">
                {evidenceDetail(row)}
              </dd>
            ) : null}
          </div>
        ))}
      </dl>
      {dataQuality.length > 0 ? (
        <ul className="finding-drawer-inline-list">
          {dataQuality.slice(0, 3).map((row) => (
            <li key={row.key}>
              {labelize(row.severity)}: {row.message}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  )
}

export function QuickViewOccurrencesPreview({
  occurrences,
}: {
  occurrences: readonly FindingOccurrenceRow[]
}) {
  return (
    <section aria-label="Occurrences preview" className="finding-drawer-section">
      <h3>Affected scope</h3>
      {occurrences.length > 0 ? (
        <ul className="finding-drawer-occurrences">
          {occurrences.slice(0, 3).map((occurrence, index) => (
            <li key={occurrenceRowKey(occurrence, index)}>
              <div>
                <strong>{occurrenceAssetLabel(occurrence)}</strong>
                <span>{occurrenceComponentLabel(occurrence)}</span>
              </div>
              <small>{occurrenceSourceLabel(occurrence)}</small>
            </li>
          ))}
        </ul>
      ) : (
        <p>No source occurrences are recorded for this finding.</p>
      )}
      {occurrences.length > 3 ? (
        <p className="finding-drawer-muted">
          {occurrences.length - 3} additional occurrence(s) are available in
          full detail.
        </p>
      ) : null}
    </section>
  )
}

export function QuickViewAttackContextSection({
  attackContext,
  attackEmpty,
  attackTechniques,
}: {
  attackContext: FindingAttackContext | null
  attackEmpty: boolean
  attackTechniques: readonly QuickViewAttackTechnique[]
}) {
  if (attackEmpty) return null

  return (
    <section
      aria-label="Defensive ATT&CK context"
      className="finding-drawer-section"
    >
      <div className="finding-drawer-section-title">
        <ShieldCheck aria-hidden="true" size={16} />
        <h3>Defensive ATT&CK context</h3>
      </div>
      <div className="finding-drawer-attack-compact">
        <strong>
          {`${attackTechniques[0]?.technique_id ?? "Mapped"} ${
            attackTechniques[0]?.name ?? ""
          }`.trim()}
        </strong>
        <span>
          {attackTacticsLabel(attackTechniques[0]?.tactics)} · confidence{" "}
          {attackConfidenceLabel(attackContext?.confidence).toLowerCase()} ·{" "}
          {labelize(attackContext?.review_status).toLowerCase()}
        </span>
      </div>
      <p className="finding-drawer-muted finding-drawer-muted--compact">
        Defensive planning context only; it does not prove compromise or active
        exploitation.
      </p>
    </section>
  )
}

export function QuickViewGovernanceSection({
  finding,
  projectSearch,
}: {
  finding: QuickViewFinding
  projectSearch: ProjectUrlSearch
}) {
  if (!finding.waived && !finding.suppressed_by_vex) return null

  return (
    <section aria-label="Governance" className="finding-drawer-section">
      <h3>Risk acceptance</h3>
      <p>{governanceCopy(finding)}</p>
      <div className="finding-drawer-actions-inline">
        <Button asChild size="sm" variant="outline">
          <Link search={projectSearch} to="/waivers">
            Open Risk Acceptance
          </Link>
        </Button>
      </div>
    </section>
  )
}
