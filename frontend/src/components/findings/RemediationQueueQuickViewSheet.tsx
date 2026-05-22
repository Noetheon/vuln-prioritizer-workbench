import { Link } from "@/lib/router"
import type {
  FindingDetailPublic,
  FindingExplanationPublic,
  FindingPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import { Callout, DetailDrawer, VpwSkeletonStack } from "@/components/vpw"
import {
  attackContextEmptyState,
  attackTechniqueRows,
  findingComponentDetailLabel,
  findingDataQualityRows,
  findingEvidenceRows,
  findingOccurrenceRows,
  findingProviderGaps,
  findingRecommendedAction,
  findingWhyText,
} from "@/components/finding-detail/finding-detail-model"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { FindingsUrlSearch } from "./findings-search-state"
import {
  QuickViewAttackContextSection,
  QuickViewDecisionSummary,
  QuickViewEvidenceSnapshot,
  QuickViewGovernanceSection,
  QuickViewOccurrencesPreview,
  QuickViewSignalBrief,
  QuickViewStatusRow,
} from "./RemediationQueueQuickViewSections"
import { componentLabel } from "./remediation-queue-model"

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
  const component = detail
    ? findingComponentDetailLabel(detail)
    : componentLabel(finding)
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
    : finding.rationale ??
      "No priority explanation has been recorded for this finding."
  const projectSearch = selectedProjectRouteSearch(effectiveFinding.project_id)

  return (
    <DetailDrawer
      className="max-sm:left-0 max-sm:right-0 max-sm:w-auto max-sm:max-w-none w-[min(100vw,39rem)] sm:max-w-none"
      description={component}
      footer={
        <>
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
        </>
      }
      onOpenChange={(value) => {
        if (!value) onClose()
      }}
      open={open}
      status={<QuickViewStatusRow finding={effectiveFinding} />}
      title={
        <>
          <span className="font-mono">{finding.cve_id}</span>
          <span className="font-normal text-[var(--vpw-text-muted)]">
            {" "}
            - {component}
          </span>
        </>
      }
    >
      <section
        aria-label="Finding quick view content"
        className="flex min-w-0 flex-col gap-4"
      >
        {error ? (
          <Callout
            action={
              <Button
                onClick={onRefresh}
                size="sm"
                type="button"
                variant="outline"
              >
                Retry detail
              </Button>
            }
            severity="critical"
            title={error}
          />
        ) : null}
        {explanationWarning ? (
          <Callout severity="critical" title={explanationWarning} />
        ) : null}

        {loading ? (
          <section aria-label="Loading finding drawer detail" role="status">
            <VpwSkeletonStack rows={4} />
          </section>
        ) : null}

        <QuickViewDecisionSummary
          finding={effectiveFinding}
          rationale={rationale}
          recommendedAction={recommendedAction}
        />
        <QuickViewSignalBrief finding={effectiveFinding} />
        <QuickViewEvidenceSnapshot
          dataQualityRows={dataQualityRows}
          evidenceRows={evidenceRows}
        />
        <QuickViewOccurrencesPreview occurrences={occurrences} />
        <QuickViewAttackContextSection
          attackContext={attackContext}
          attackEmpty={attackEmpty}
          attackTechniques={attackTechniques}
        />
        <QuickViewGovernanceSection
          finding={effectiveFinding}
          projectSearch={projectSearch}
        />
      </section>
    </DetailDrawer>
  )
}
