import { Link } from "@/lib/router"
import type { FindingDetailPublic, FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  MetaTag,
  RiskBadge,
  RiskScoreBadge,
  SignalChip,
  StatusLozenge,
  VpwSignalCluster,
  VpwStatusBanner,
} from "@/components/vpw"
import {
  attackConfidenceLabel,
  attackTacticsLabel,
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

export function QuickViewStatusRow({ finding }: { finding: QuickViewFinding }) {
  return (
    <div className="finding-drawer-status-row">
      <RiskBadge density="compact" level={finding.priority} />
      <RiskScoreBadge density="compact" value={finding.risk_score} />
      <StatusLozenge density="compact" status={finding.status} />
      <VpwSignalCluster maxVisible={3}>
        {finding.in_kev ? <SignalChip kind="kev" /> : null}
        {finding.epss !== null && finding.epss !== undefined ? (
          <SignalChip kind="epss" value={finding.epss} />
        ) : null}
        {finding.cvss_base_score !== null &&
        finding.cvss_base_score !== undefined ? (
          <SignalChip kind="cvss" value={finding.cvss_base_score} />
        ) : null}
        {finding.attack_mapped ? <SignalChip kind="attack" /> : null}
        {finding.suppressed_by_vex ? <SignalChip kind="vex" /> : null}
      </VpwSignalCluster>
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
  return (
    <section aria-label="Decision summary" className="finding-drawer-section">
      <h3>Decision summary</h3>
      <VpwStatusBanner title="Recommended action" tone="success">
        {recommendedAction}
      </VpwStatusBanner>
      <p>{rationale}</p>
      <dl className="finding-drawer-facts">
        <DrawerFact label="Owner" value={optionalText(finding.owner)} />
        <DrawerFact
          label="Service"
          value={optionalText(finding.business_service)}
        />
        <DrawerFact label="Asset" value={drawerAssetLabel(finding)} />
        <DrawerFact label="Exposure" value={labelize(finding.exposure)} />
      </dl>
    </section>
  )
}

export function QuickViewEvidenceSnapshot({
  dataQualityRows,
  evidenceRows,
  finding,
}: {
  dataQualityRows: readonly QuickViewDataQualityRow[]
  evidenceRows: readonly FindingDetailRow[]
  finding: QuickViewFinding
}) {
  return (
    <section aria-label="Evidence snapshot" className="finding-drawer-section">
      <div className="finding-drawer-section-heading">
        <h3>Evidence snapshot</h3>
        <div className="finding-meta-tags">
          <MetaTag label={`CVSS ${cvssText(finding)}`} />
          <MetaTag label={`EPSS ${epssText(finding)}`} />
          <MetaTag label={finding.in_kev ? "KEV listed" : "No KEV"} />
        </div>
      </div>
      <dl className="finding-drawer-evidence-grid">
        {evidenceRows.slice(0, 4).map((row) => (
          <div key={row.label}>
            <dt>{row.label}</dt>
            <dd>{row.value}</dd>
            {row.detail ? (
              <dd className="finding-drawer-evidence-detail">{row.detail}</dd>
            ) : null}
          </div>
        ))}
      </dl>
      {dataQualityRows.length > 0 ? (
        <ul className="finding-drawer-inline-list">
          {dataQualityRows.slice(0, 3).map((row) => (
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
      <h3>Occurrences preview</h3>
      {occurrences.length > 0 ? (
        <ul className="finding-drawer-occurrences">
          {occurrences.slice(0, 3).map((occurrence, index) => (
            <li key={occurrenceRowKey(occurrence, index)}>
              <strong>{occurrenceAssetLabel(occurrence)}</strong>
              <span>{occurrenceComponentLabel(occurrence)}</span>
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
  return (
    <section
      aria-label="Defensive ATT&CK context"
      className="finding-drawer-section"
    >
      <h3>Defensive ATT&CK context</h3>
      <p>
        This context is defensive planning evidence only; it does not prove
        compromise or active exploitation.
      </p>
      {attackEmpty ? (
        <p className="finding-drawer-muted">
          No reviewed ATT&CK technique mapping is recorded for this finding.
        </p>
      ) : (
        <dl className="finding-drawer-facts">
          <DrawerFact
            label="Technique"
            value={`${attackTechniques[0]?.technique_id ?? "Mapped"} ${
              attackTechniques[0]?.name ?? ""
            }`.trim()}
          />
          <DrawerFact
            label="Tactics"
            value={attackTacticsLabel(attackTechniques[0]?.tactics)}
          />
          <DrawerFact
            label="Confidence"
            value={attackConfidenceLabel(attackContext?.confidence)}
          />
          <DrawerFact
            label="Coverage"
            value={labelize(attackContext?.review_status)}
          />
        </dl>
      )}
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
  return (
    <section aria-label="Governance" className="finding-drawer-section">
      <h3>Governance</h3>
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
