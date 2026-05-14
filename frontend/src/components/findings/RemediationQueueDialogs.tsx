import { Link } from "@/lib/router"
import type {
  FindingDetailPublic,
  FindingExplanationPublic,
  FindingPublic,
} from "@/api-client"
import {
  EpssBadge,
  KevBadge,
  PriorityBadge,
} from "@/components/risk"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import {
  MetaTag,
  RiskBadge,
  RiskScoreBadge,
  SignalChip,
  StatusLozenge,
  VpwSignalCluster,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import {
  attackConfidenceLabel,
  attackContextEmptyState,
  attackTacticsLabel,
  attackTechniqueRows,
  findingComponentDetailLabel,
  findingDataQualityRows,
  findingEvidenceRows,
  findingOccurrenceRows,
  findingProviderGaps,
  findingRecommendedAction,
  findingWhyText,
  type FindingOccurrenceRow,
} from "@/components/finding-detail/finding-detail-model"
import { stringValue } from "@/lib/app-errors"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { FindingsUrlSearch } from "./findings-search-state"
import { componentLabel } from "./remediation-queue-model"

type WhyDialogProps = {
  finding: FindingPublic | null
  open: boolean
  onClose: () => void
}

export function WhyDialog({ finding, open, onClose }: WhyDialogProps) {
  if (!finding) return null
  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-lg text-[var(--vpw-text-primary)]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <PriorityBadge priority={finding.priority} />
            <span className="font-mono text-sm">{finding.cve_id}</span>
          </DialogTitle>
          <DialogDescription className="sr-only">
            Priority rationale, risk signals, and recommended remediation action
            for {finding.cve_id}.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4 text-sm">
          {finding.rationale ? (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase text-[var(--vpw-text-secondary)]">
                Why now
              </p>
              <p className="leading-relaxed">{finding.rationale}</p>
            </div>
          ) : (
            <p className="text-[var(--vpw-text-secondary)]">
              No rationale recorded for this finding.
            </p>
          )}
          {finding.recommended_action ? (
            <VpwStatusBanner title="Recommended action" tone="success">
              {finding.recommended_action}
            </VpwStatusBanner>
          ) : null}
          <dl className="grid grid-cols-3 gap-3 rounded-md border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3 text-xs text-[var(--vpw-text-primary)]">
            <div>
              <dt className="text-[var(--vpw-text-secondary)]">Risk Score</dt>
              <dd className="font-bold text-sm text-[var(--vpw-text-primary)]">
                {finding.risk_score?.toFixed(1) ?? "Not scored"}
              </dd>
            </div>
            <div>
              <dt className="text-[var(--vpw-text-secondary)]">EPSS</dt>
              <dd className="font-semibold text-sm">
                <EpssBadge value={finding.epss} />
              </dd>
            </div>
            <div>
              <dt className="text-[var(--vpw-text-secondary)]">KEV</dt>
              <dd className="font-semibold text-sm">
                <KevBadge matched={finding.in_kev} />
              </dd>
            </div>
          </dl>
        </div>
      </DialogContent>
    </Dialog>
  )
}

type QuickViewSheetProps = {
  detail: FindingDetailPublic | null
  error: string
  explanation: FindingExplanationPublic | null
  explanationWarning: string
  finding: FindingPublic | null
  findingSearch: FindingsUrlSearch
  loading: boolean
  open: boolean
  onClose: () => void
  onRefresh: () => void
}

export function QuickViewSheet({
  detail,
  error,
  explanation,
  explanationWarning,
  finding,
  findingSearch,
  loading,
  open,
  onClose,
  onRefresh,
}: QuickViewSheetProps) {
  if (!finding) return null
  const effectiveFinding = detail ?? finding
  const component = detail ? findingComponentDetailLabel(detail) : componentLabel(finding)
  const occurrences = findingOccurrenceRows(detail, explanation)
  const dataQualityRows = findingDataQualityRows(detail, explanation)
  const providerGaps = findingProviderGaps(detail, explanation)
  const evidenceRows = findingEvidenceRows(
    detail,
    explanation,
    occurrences,
    dataQualityRows,
    providerGaps,
  )
  const attackContext = detail?.attack_context ?? null
  const attackTechniques = attackTechniqueRows(attackContext)
  const attackEmpty = attackContextEmptyState(attackContext)
  const recommendedAction = detail
    ? findingRecommendedAction(detail, explanation)
    : finding.recommended_action ?? "No recommended action has been recorded."
  const rationale = detail
    ? findingWhyText(detail, explanation)
    : finding.rationale ?? "No priority explanation has been recorded for this finding."
  const projectSearch = selectedProjectRouteSearch(effectiveFinding.project_id)

  return (
    <Sheet open={open} onOpenChange={(v) => !v && onClose()}>
      <SheetContent className="vpw-sheet-content finding-detail-drawer w-[min(100vw,44rem)] gap-0 overflow-hidden p-0 sm:max-w-none">
        <SheetHeader className="border-b border-[var(--vpw-border-default)] px-5 py-4 pr-12 text-left">
          <SheetTitle className="text-base leading-tight text-[var(--vpw-text-primary)]">
            <span className="font-mono">{finding.cve_id}</span>
            <span className="font-normal text-[var(--vpw-text-muted)]">
              {" "}
              · {component}
            </span>
          </SheetTitle>
          <SheetDescription>
            Decision preview with evidence, affected context, governance state,
            and full detail access.
          </SheetDescription>
        </SheetHeader>

        <div className="finding-drawer-body">
          <div className="finding-drawer-status-row">
            <RiskBadge density="compact" level={effectiveFinding.priority} />
            <RiskScoreBadge
              density="compact"
              value={effectiveFinding.risk_score}
            />
            <StatusLozenge density="compact" status={effectiveFinding.status} />
            <VpwSignalCluster maxVisible={3}>
              {effectiveFinding.in_kev ? <SignalChip kind="kev" /> : null}
              {effectiveFinding.epss !== null &&
              effectiveFinding.epss !== undefined ? (
                <SignalChip kind="epss" value={effectiveFinding.epss} />
              ) : null}
              {effectiveFinding.cvss_base_score !== null &&
              effectiveFinding.cvss_base_score !== undefined ? (
                <SignalChip
                  kind="cvss"
                  value={effectiveFinding.cvss_base_score}
                />
              ) : null}
              {effectiveFinding.attack_mapped ? (
                <SignalChip kind="attack" />
              ) : null}
              {effectiveFinding.suppressed_by_vex ? (
                <SignalChip kind="vex" />
              ) : null}
            </VpwSignalCluster>
          </div>

          {error ? (
            <VpwStatusBanner title={error} tone="critical">
              <Button
                className="mt-2 h-8 px-2"
                onClick={onRefresh}
                size="sm"
                type="button"
                variant="outline"
              >
                Retry detail
              </Button>
            </VpwStatusBanner>
          ) : null}
          {explanationWarning ? (
            <VpwStatusBanner title={explanationWarning} tone="critical" />
          ) : null}

          {loading ? (
            <section aria-label="Loading finding drawer detail" role="status">
              <VpwSkeletonStack rows={4} />
            </section>
          ) : null}

          <section
            aria-label="Decision summary"
            className="finding-drawer-section"
          >
            <h3>Decision summary</h3>
            <VpwStatusBanner title="Recommended action" tone="success">
              {recommendedAction}
            </VpwStatusBanner>
            <p>{rationale}</p>
            <dl className="finding-drawer-facts">
              <DrawerFact
                label="Owner"
                value={optionalText(effectiveFinding.owner)}
              />
              <DrawerFact
                label="Service"
                value={optionalText(effectiveFinding.business_service)}
              />
              <DrawerFact
                label="Asset"
                value={drawerAssetLabel(effectiveFinding)}
              />
              <DrawerFact
                label="Exposure"
                value={labelize(effectiveFinding.exposure)}
              />
            </dl>
          </section>

          <section
            aria-label="Evidence snapshot"
            className="finding-drawer-section"
          >
            <div className="finding-drawer-section-heading">
              <h3>Evidence snapshot</h3>
              <div className="finding-meta-tags">
                <MetaTag label={`CVSS ${cvssText(effectiveFinding)}`} />
                <MetaTag label={`EPSS ${epssText(effectiveFinding)}`} />
                <MetaTag
                  label={effectiveFinding.in_kev ? "KEV listed" : "No KEV"}
                />
              </div>
            </div>
            <dl className="finding-drawer-evidence-grid">
              {evidenceRows.slice(0, 4).map((row) => (
                <div key={row.label}>
                  <dt>{row.label}</dt>
                  <dd>{row.value}</dd>
                  {row.detail ? (
                    <dd className="finding-drawer-evidence-detail">
                      {row.detail}
                    </dd>
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

          <section
            aria-label="Occurrences preview"
            className="finding-drawer-section"
          >
            <h3>Occurrences preview</h3>
            {occurrences.length > 0 ? (
              <ul className="finding-drawer-occurrences">
                {occurrences.slice(0, 3).map((occurrence, index) => (
                  <li key={stringValue(occurrence.id) ?? index}>
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
                {occurrences.length - 3} additional occurrence(s) are available
                in full detail.
              </p>
            ) : null}
          </section>

          <section
            aria-label="Defensive ATT&CK context"
            className="finding-drawer-section"
          >
            <h3>Defensive ATT&CK context</h3>
            <p>
              This context is defensive planning evidence only; it does not
              prove compromise or active exploitation.
            </p>
            {attackEmpty ? (
              <p className="finding-drawer-muted">
                No reviewed ATT&CK technique mapping is recorded for this
                finding.
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

          <section aria-label="Governance" className="finding-drawer-section">
            <h3>Governance</h3>
            <p>{governanceCopy(effectiveFinding)}</p>
            <div className="finding-drawer-actions-inline">
              <Button asChild size="sm" variant="outline">
                <Link search={projectSearch} to="/waivers">
                  Open Risk Acceptance
                </Link>
              </Button>
            </div>
          </section>
        </div>

        <SheetFooter className="border-t border-[var(--vpw-border-default)] px-5 py-4">
          <Button
            className="sm:order-1"
            onClick={onClose}
            type="button"
            variant="outline"
          >
            Close
          </Button>
          <Button asChild className="sm:order-2">
              <Link
                params={{ findingId: finding.id }}
                search={findingSearch}
                to="/findings/$findingId"
              >
                Open full detail
              </Link>
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

function DrawerFact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  )
}

function drawerAssetLabel(finding: FindingPublic | FindingDetailPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.asset_target_ref ??
    "Not supplied"
  )
}

function cvssText(finding: FindingPublic | FindingDetailPublic) {
  return finding.cvss_base_score !== null &&
    finding.cvss_base_score !== undefined
    ? finding.cvss_base_score.toFixed(1)
    : "Not supplied"
}

function epssText(finding: FindingPublic | FindingDetailPublic) {
  return finding.epss !== null && finding.epss !== undefined
    ? `${Math.round(finding.epss * 1000) / 10}%`
    : "Not supplied"
}

function occurrenceAssetLabel(occurrence: FindingOccurrenceRow) {
  return (
    stringValue(occurrence.asset_ref) ??
    stringValue(occurrence.target_ref) ??
    stringValue(occurrence.raw_reference) ??
    "Affected occurrence"
  )
}

function occurrenceComponentLabel(occurrence: FindingOccurrenceRow) {
  return [
    stringValue(occurrence.component_name),
    stringValue(occurrence.component_version),
  ]
    .filter(Boolean)
    .join(" ") || "Component not supplied"
}

function occurrenceSourceLabel(occurrence: FindingOccurrenceRow) {
  return (
    stringValue(occurrence.source_format) ??
    stringValue(occurrence.source) ??
    stringValue(occurrence.scanner) ??
    "Source not supplied"
  )
}

function governanceCopy(finding: FindingPublic | FindingDetailPublic) {
  if (finding.waived) {
    return "Accepted risk is recorded for this finding. Review the acceptance register before changing remediation priority."
  }
  if (finding.suppressed_by_vex) {
    return "A VEX or suppression state is recorded. Validate scope and expiry in the acceptance workflow."
  }
  return "No accepted-risk state is recorded. Use Risk Acceptance only when the organization has approved a time-bound exception."
}
