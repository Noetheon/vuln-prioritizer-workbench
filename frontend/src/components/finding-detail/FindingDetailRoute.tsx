import { Link } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"

import type {
  FindingDetailPublic,
  FindingExplanationPublic,
} from "@/api-client"
import type { FindingsUrlSearch } from "@/components/findings/findings-search-state"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VpwSkeletonStack, VpwStatusBanner } from "@/components/vpw"
import type { FindingDetailTab } from "@/lib/app-defaults"
import { findingWaiverEvidence } from "@/lib/waiver-view"

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
            <span>Back to Findings</span>
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
                <span>Decision evidence</span>
                <strong>Evidence, TTP context, and lifecycle</strong>
                <p>
                  Provider-backed facts used to explain and defend the priority
                  decision.
                </p>
              </div>
              <TabsList className="finding-detail-tabs-list">
                <TabsTrigger
                  className="finding-detail-tab-trigger"
                  value="evidence"
                >
                  Evidence
                </TabsTrigger>
                <TabsTrigger className="finding-detail-tab-trigger" value="ttp">
                  TTP Context
                </TabsTrigger>
                <TabsTrigger
                  className="finding-detail-tab-trigger"
                  value="history"
                >
                  History
                </TabsTrigger>
              </TabsList>
            </div>

            <TabsContent className="finding-detail-tab-panel" value="evidence">
              <FindingEvidenceTab
                dataQualityRows={dataQualityRows}
                evidenceRows={evidenceRows}
                occurrences={occurrences}
              />
            </TabsContent>

            <TabsContent className="finding-detail-tab-panel" value="ttp">
              <FindingTtpContextTab attackContext={attackContext} />
            </TabsContent>

            <TabsContent className="finding-detail-tab-panel" value="history">
              <FindingHistoryTab
                historyRows={historyRows}
                waiverEvidence={waiverEvidence}
              />
            </TabsContent>
          </Tabs>
        </>
      ) : null}
    </section>
  )
}
