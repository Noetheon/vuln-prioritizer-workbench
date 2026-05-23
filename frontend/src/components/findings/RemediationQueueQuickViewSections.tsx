import { Link } from "@/lib/router"
import { ShieldCheck } from "lucide-react"
import type { FindingDetailPublic, FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Callout,
  DecisionSummary,
  DefinitionList,
  EvidenceRow,
  RiskBadge,
  StatusLozenge,
  VpwBadge,
} from "@/components/vpw"
import {
  attackConfidenceLabel,
  attackTacticsLabel,
  findingSlaLabel,
  compactFindingText,
  findingRecommendedActionParts,
  type FindingAttackContext,
  type FindingDetailRow,
  type FindingOccurrenceRow,
  uniqueFindingDataQualityRows,
} from "@/components/finding-detail/finding-detail-model"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import type { ProjectUrlSearch } from "@/workbench/selected-project-search"
import {
  cvssText,
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
  const action = findingRecommendedActionParts(recommendedAction)
  const assignment = [
    { label: "Owner", value: optionalText(finding.owner) },
    { label: "Service", value: optionalText(finding.business_service) },
    { label: "Asset", value: drawerAssetLabel(finding) },
    { label: "SLA", value: findingSlaLabel(finding.priority) },
  ]

  return (
    <DecisionSummary
      aria-label="Decision summary"
      className="finding-drawer-section finding-drawer-section--decision"
      evidence={
        <DefinitionList
          columns={2}
          items={assignment.map((item) => ({
            label: item.label,
            value: item.value,
          }))}
        />
      }
      primaryDriver={<RiskBadge density="compact" level={finding.priority} />}
      recommendedAction={
        <span title={recommendedAction}>
          {action.title}: {compactFindingText(action.detail)}
        </span>
      }
      riskScore={riskScoreLabel(finding.risk_score)}
      status={<StatusLozenge density="compact" status={finding.status} />}
      title="Triage decision"
      whyThisPriority={
        <span title={rationale}>{compactFindingText(rationale, 320)}</span>
      }
    />
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
      <DefinitionList
        columns={2}
        items={items.map((item) => ({
          description: item.detail,
          label: item.label,
          tone: item.tone,
          value: item.label,
        }))}
      />
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
  const dataQuality = uniqueFindingDataQualityRows(dataQualityRows)

  return (
    <section
      aria-label="Evidence snapshot"
      className="finding-drawer-section finding-drawer-section--evidence"
    >
      <div className="finding-drawer-section-heading">
        <h3>Evidence snapshot</h3>
      </div>
      <div className="finding-drawer-evidence-list">
        {evidenceRows.slice(0, 5).map((row) => (
          <EvidenceRow
            description={evidenceDetail(row)}
            key={row.label}
            source={evidenceLabel(row)}
            title={evidenceValue(row)}
          />
        ))}
      </div>
      {dataQuality.length > 0 ? (
        <DefinitionList
          items={dataQuality.slice(0, 3).map((row) => ({
            label: labelize(row.severity),
            value: row.message,
          }))}
        />
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
        <DefinitionList
          items={occurrences.slice(0, 3).map((occurrence, index) => ({
            description: occurrenceSourceLabel(occurrence),
            id: String(occurrenceRowKey(occurrence, index)),
            label: occurrenceAssetLabel(occurrence),
            value: occurrenceComponentLabel(occurrence),
          }))}
        />
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
      <EvidenceRow
        caveat="Defensive planning context only; it does not prove compromise or active exploitation."
        confidence={attackConfidenceLabel(attackContext?.confidence)}
        description={`${attackTacticsLabel(attackTechniques[0]?.tactics)} / ${labelize(
          attackContext?.review_status,
        ).toLowerCase()}`}
        source="ATT&CK"
        title={`${attackTechniques[0]?.technique_id ?? "Mapped"} ${
          attackTechniques[0]?.name ?? ""
        }`.trim()}
      />
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
    <Callout
      aria-label="Governance"
      className="finding-drawer-section"
      severity="warning"
      title="Risk acceptance"
    >
      <p>{governanceCopy(finding)}</p>
      <div className="finding-drawer-actions-inline">
        <Button asChild size="sm" variant="outline">
          <Link search={projectSearch} to="/waivers">
            Open Risk Acceptance
          </Link>
        </Button>
      </div>
    </Callout>
  )
}
