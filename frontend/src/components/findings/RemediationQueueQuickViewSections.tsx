import { Link } from "@/lib/router"
import { ShieldCheck } from "lucide-react"
import type { FindingDetailPublic, FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Callout,
  DecisionSummary,
  DefinitionList,
  EvidenceRow,
  SignalBadge,
  StatusBadge,
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

type QuickViewSignalItem = {
  detail: string
  kind: "kev" | "epss" | "cvss" | "attack" | "vex"
  label: string
  value?: number
}

function riskScoreLabel(value: QuickViewFinding["risk_score"]) {
  if (typeof value === "number") return `Risk ${value.toFixed(1)}`
  return value ? `Risk ${value}` : "Risk not scored"
}

function signalItems(finding: QuickViewFinding) {
  const items: Array<QuickViewSignalItem | null> = [
    finding.in_kev
      ? {
          detail: "Known exploited vulnerability signal is present.",
          kind: "kev" as const,
          label: "CISA KEV",
        }
      : null,
    finding.epss !== null && finding.epss !== undefined
      ? {
          detail:
            finding.epss >= 0.7
              ? "Elevated exploitation probability."
              : "Provider probability signal recorded.",
          kind: "epss" as const,
          label: `EPSS ${epssText(finding)}`,
          value: finding.epss,
        }
      : null,
    finding.cvss_base_score !== null &&
    finding.cvss_base_score !== undefined
      ? {
          detail: "Impact severity score from vulnerability provider data.",
          kind: "cvss" as const,
          label: `CVSS ${cvssText(finding)}`,
          value: finding.cvss_base_score,
        }
      : null,
    finding.attack_mapped
      ? {
          detail: "Reviewed defensive mapping is available.",
          kind: "attack" as const,
          label: "ATT&CK mapped",
        }
      : null,
    finding.suppressed_by_vex
      ? {
          detail: "Suppression state is recorded and should be validated.",
          kind: "vex" as const,
          label: "VEX state",
        }
      : null,
  ]
  return items.filter((item): item is QuickViewSignalItem => item !== null)
}

function primaryDriver(finding: QuickViewFinding) {
  if (finding.in_kev) return <SignalBadge kind="kev" />
  if (finding.epss !== null && finding.epss !== undefined) {
    return <SignalBadge kind="epss" value={finding.epss} />
  }
  if (
    finding.cvss_base_score !== null &&
    finding.cvss_base_score !== undefined
  ) {
    return <SignalBadge kind="cvss" value={finding.cvss_base_score} />
  }
  if (finding.attack_mapped) return <SignalBadge kind="attack" />
  if (finding.waived) return <SignalBadge kind="accepted-risk" />
  return <StatusBadge status={finding.status} />
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
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      <SignalBadge kind="priority" value={finding.priority} />
      <StatusBadge status={finding.status} />
      <SignalBadge
        kind="risk-score"
        label={riskScoreLabel(finding.risk_score)}
        value={finding.risk_score}
      />
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
    { label: "Status", value: labelize(finding.status) },
  ]

  return (
    <section
      aria-label="Decision summary"
      className="flex min-w-0 flex-col gap-3"
    >
      <DecisionSummary
        decisionBasis="Prioritization combines supplied evidence, provider signals, affected context, and lifecycle state."
        primaryDriver={primaryDriver(finding)}
        recommendedAction={`${action.title}. ${compactFindingText(action.detail)}`}
        riskScore={
          <SignalBadge kind="risk-score" value={finding.risk_score} />
        }
        title="Priority decision"
        whyThisPriority={compactFindingText(rationale, 320)}
      />
      <DefinitionList columns={2} items={assignment} />
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
      className="flex min-w-0 flex-col"
    >
      <p className="vpw-label mb-1">Signals</p>
      <div className="min-w-0">
        {items.map((item) => (
          <EvidenceRow
            description={item.detail}
            key={item.label}
            signal={{
              kind: item.kind,
              label: item.label,
              value: item.value,
            }}
            source="Provider signal"
            title={item.label}
          />
        ))}
      </div>
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
      className="flex min-w-0 flex-col"
    >
      <p className="vpw-label mb-1">Evidence snapshot</p>
      <div className="min-w-0">
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
        <div className="mt-3 grid min-w-0 gap-2">
          {dataQuality.slice(0, 3).map((row) => (
            <Callout
              key={row.key}
              severity={row.severity === "error" ? "critical" : "warning"}
              title={labelize(row.severity)}
            >
              {labelize(row.severity)}: {row.message}
            </Callout>
          ))}
        </div>
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
    <section aria-label="Occurrences preview" className="flex min-w-0 flex-col">
      <p className="vpw-label mb-1">Affected scope</p>
      {occurrences.length > 0 ? (
        <div className="min-w-0">
          {occurrences.slice(0, 3).map((occurrence, index) => (
            <EvidenceRow
              description={occurrenceComponentLabel(occurrence)}
              key={occurrenceRowKey(occurrence, index)}
              source={occurrenceSourceLabel(occurrence)}
              title={occurrenceAssetLabel(occurrence)}
            />
          ))}
        </div>
      ) : (
        <p className="text-sm text-[var(--vpw-text-secondary)]">
          No source occurrences are recorded for this finding.
        </p>
      )}
      {occurrences.length > 3 ? (
        <p className="mt-2 text-xs leading-5 text-[var(--vpw-text-muted)]">
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
      className="flex min-w-0 flex-col gap-3"
    >
      <div className="flex min-w-0 items-center gap-2">
        <ShieldCheck aria-hidden="true" size={16} />
        <p className="vpw-label">Defensive ATT&CK context</p>
      </div>
      <EvidenceRow
        description={`${attackTacticsLabel(
          attackTechniques[0]?.tactics,
        )} - confidence ${attackConfidenceLabel(
          attackContext?.confidence,
        ).toLowerCase()} - ${labelize(attackContext?.review_status).toLowerCase()}`}
        signal={{ kind: "attack" }}
        source="Defensive ATT&CK context"
        title={`${attackTechniques[0]?.technique_id ?? "Mapped"} ${
          attackTechniques[0]?.name ?? ""
        }`.trim()}
      />
      <Callout severity="info" title="Defensive context only">
        Defensive planning context only; it does not prove compromise or active
        exploitation.
      </Callout>
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
    <section aria-label="Governance" className="flex min-w-0 flex-col gap-3">
      <EvidenceRow
        description={governanceCopy(finding)}
        signal={{
          kind: finding.waived ? "accepted-risk" : "vex",
          label: finding.waived ? "Accepted risk" : "VEX state",
        }}
        source="Governance"
        title={finding.waived ? "Risk acceptance recorded" : "Suppression state recorded"}
      />
      <div className="flex min-w-0 flex-wrap gap-2">
        <Button asChild size="sm" variant="outline">
          <Link search={projectSearch} to="/waivers">
            Open Risk Acceptance
          </Link>
        </Button>
      </div>
    </section>
  )
}
