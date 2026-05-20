import { Link } from "@/lib/router"
import { ArrowLeft, RefreshCcw } from "lucide-react"

import type {
  FindingDetailPublic,
  FindingExplanationPublic,
} from "@/api-client"
import type { FindingsUrlSearch } from "@/components/findings/findings-search-state"
import {
  FindingStatusBadge,
  KevBadge,
  PriorityBadge,
} from "@/components/risk"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VpwSkeletonStack, VpwStatusBanner } from "@/components/vpw"
import type { FindingDetailTab } from "@/lib/app-defaults"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import { findingWaiverEvidence } from "@/lib/waiver-view"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"

import { FindingDetailHero } from "./FindingDetailHero"
import { FindingEvidenceTab } from "./FindingEvidenceTab"
import { FindingHistoryTab } from "./FindingHistoryTab"
import { FindingTtpContextTab } from "./FindingTtpContextTab"
import {
  findingDataQualityRows,
  findingDecisionReasonRows,
  findingEvidenceRows,
  findingHistoryRows,
  findingOccurrenceRows,
  findingProviderGaps,
  findingComponentDetailLabel,
  findingNextStepLabel,
  findingOwnerDetailLabel,
  findingSlaLabel,
  findingReasonRows,
  isDemoFindingDetail,
} from "./finding-detail-model"
import { WhyPriorityPanel } from "./WhyPriorityPanel"

export type FindingDetailRouteProps = {
  error: string
  explanation: FindingExplanationPublic | null
  explanationWarning: string
  finding: FindingDetailPublic | null
  findingsBackSearch: FindingsUrlSearch
  loading: boolean
  tab: FindingDetailTab
  onRefresh: () => void
  onTabChange: (tab: FindingDetailTab) => void
}

export function FindingDetailRoute({
  error,
  explanation,
  explanationWarning,
  finding,
  findingsBackSearch,
  loading,
  onRefresh,
  onTabChange,
  tab,
}: FindingDetailRouteProps) {
  const occurrences = findingOccurrenceRows(finding, explanation)
  const dataQualityRows = findingDataQualityRows(finding, explanation)
  const providerGaps = findingProviderGaps(finding, explanation)
  const reasonRows = findingReasonRows(explanation)
  const attackContext = finding?.attack_context ?? null
  const waiverEvidence = findingWaiverEvidence(finding)
  const decisionReasons = findingDecisionReasonRows(
    finding,
    explanation,
    attackContext,
  )
  const evidenceRows = findingEvidenceRows(
    finding,
    explanation,
    occurrences,
    dataQualityRows,
    providerGaps,
  )
  const historyRows = findingHistoryRows(finding, occurrences, waiverEvidence)

  return (
    <section
      className="finding-decision-workflow"
      aria-label="Finding priority decision"
    >
      <div className="finding-detail-backbar">
        <Button variant="outline" size="sm" asChild>
          <Link search={findingsBackSearch} to="/findings">
            <ArrowLeft aria-hidden="true" size={16} />
            <span>Back to Triage</span>
          </Link>
        </Button>
      </div>

      {error ? <VpwStatusBanner title={error} tone="critical" /> : null}
      {explanationWarning ? (
        <VpwStatusBanner title={explanationWarning} tone="critical" />
      ) : null}
      {loading ? (
        <section
          aria-label="Loading finding detail"
          className="finding-decision-loading"
          role="status"
        >
          <VpwSkeletonStack rows={6} />
        </section>
      ) : null}

      {!loading && !error && finding ? (
        <>
          <FindingDetailHero
            explanation={explanation}
            finding={finding}
            isDemo={isDemoFindingDetail(finding)}
            occurrences={occurrences}
          />

          <div className="finding-detail-workspace-grid">
            <main className="finding-detail-workspace-main">
              <WhyPriorityPanel
                decisionReasons={decisionReasons}
                explanation={explanation}
                finding={finding}
                occurrences={occurrences}
                onRefresh={onRefresh}
                reasonRows={reasonRows}
                waiverEvidence={waiverEvidence}
              />

              <Tabs
                className="finding-detail-tabs-shell"
                value={tab}
                onValueChange={(value) => onTabChange(value as FindingDetailTab)}
              >
                <div className="finding-tabs-toolbar">
                  <div className="finding-tabs-heading">
                    <span>Investigation record</span>
                    <strong>Evidence, ATT&amp;CK context, and lifecycle</strong>
                    <p>
                      Provider-backed facts used to explain and defend the
                      priority decision.
                    </p>
                  </div>
                  <TabsList className="finding-detail-tabs-list">
                    <TabsTrigger
                      className="finding-detail-tab-trigger"
                      value="evidence"
                    >
                      Evidence
                    </TabsTrigger>
                    <TabsTrigger
                      className="finding-detail-tab-trigger"
                      value="ttp"
                    >
                      ATT&amp;CK
                    </TabsTrigger>
                    <TabsTrigger
                      className="finding-detail-tab-trigger"
                      value="history"
                    >
                      History
                    </TabsTrigger>
                  </TabsList>
                </div>

                <TabsContent
                  className="finding-detail-tab-panel"
                  value="evidence"
                >
                  <FindingEvidenceTab
                    dataQualityRows={dataQualityRows}
                    evidenceRows={evidenceRows}
                    occurrences={occurrences}
                  />
                </TabsContent>

                <TabsContent className="finding-detail-tab-panel" value="ttp">
                  <FindingTtpContextTab attackContext={attackContext} />
                </TabsContent>

                <TabsContent
                  className="finding-detail-tab-panel"
                  value="history"
                >
                  <FindingHistoryTab
                    historyRows={historyRows}
                    waiverEvidence={waiverEvidence}
                  />
                </TabsContent>
              </Tabs>
            </main>

            <FindingDetailActionRail
              finding={finding}
              occurrences={occurrences}
              onRefresh={onRefresh}
              waiverEvidence={waiverEvidence}
            />
          </div>
        </>
      ) : null}
    </section>
  )
}

function FindingDetailActionRail({
  finding,
  occurrences,
  onRefresh,
  waiverEvidence,
}: {
  finding: FindingDetailPublic
  occurrences: ReturnType<typeof findingOccurrenceRows>
  onRefresh: () => void
  waiverEvidence: ReturnType<typeof findingWaiverEvidence>
}) {
  const projectSearch = selectedProjectRouteSearch(finding.project_id)
  const scopeRows = [
    {
      label: "Owner",
      value: findingOwnerDetailLabel(finding, occurrences),
    },
    {
      label: "Service",
      value: optionalText(finding.business_service),
    },
    {
      label: "Asset",
      value: optionalText(finding.asset_name ?? finding.asset_key),
    },
    {
      label: "Exposure",
      value: labelize(finding.exposure),
    },
  ]
  const decisionRows = [
    {
      label: "SLA",
      value: findingSlaLabel(finding.priority),
    },
    {
      label: "Status",
      value: labelize(finding.status),
    },
    {
      label: "Acceptance",
      value: waiverEvidence
        ? `${optionalText(waiverEvidence.status)} · ${optionalText(
            waiverEvidence.reason,
          )}`
        : "Not recorded",
    },
  ]

  return (
    <aside className="finding-detail-action-rail" aria-label="Triage summary">
      <div className="finding-detail-action-rail__header">
        <span>Triage state</span>
        <strong>{findingComponentDetailLabel(finding)}</strong>
      </div>

      <div className="finding-detail-action-rail__badges">
        <PriorityBadge priority={finding.priority} />
        <FindingStatusBadge status={finding.status} />
        <KevBadge matched={finding.in_kev} />
      </div>

      <div className="finding-detail-action-block">
        <span>Next step</span>
        <p>{findingNextStepLabel(finding)}</p>
      </div>

      <dl className="finding-detail-action-list">
        {scopeRows.map((row) => (
          <div key={row.label}>
            <dt>{row.label}</dt>
            <dd>{row.value}</dd>
          </div>
        ))}
      </dl>

      <dl className="finding-detail-action-list">
        {decisionRows.map((row) => (
          <div key={row.label}>
            <dt>{row.label}</dt>
            <dd>{row.value}</dd>
          </div>
        ))}
      </dl>

      <div className="finding-detail-action-buttons">
        <Button onClick={onRefresh} size="sm" type="button" variant="outline">
          <RefreshCcw aria-hidden="true" size={14} />
          Refresh evidence
        </Button>
        <Button asChild size="sm" variant="outline">
          <Link search={projectSearch} to="/waivers">
            Risk acceptance
          </Link>
        </Button>
      </div>
    </aside>
  )
}
