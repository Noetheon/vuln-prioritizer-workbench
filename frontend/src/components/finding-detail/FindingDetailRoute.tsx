import { Link } from "@/lib/router"
import { ArrowLeft, RefreshCcw } from "lucide-react"
import { useState } from "react"

import type {
  FindingDetailPublic,
  FindingExplanationPublic,
  FindingStatus,
} from "@/api-client"
import { FindingsService } from "@/api-client"
import type { FindingsUrlSearch } from "@/components/findings/findings-search-state"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  DefinitionList,
  DetailRail,
  RiskBadge,
  SignalChip,
  StatusLozenge,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import type { FindingDetailTab } from "@/lib/app-defaults"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import { findingWaiverEvidence } from "@/lib/waiver-view"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"

import { FindingDetailContext } from "./FindingDetailContext"
import { FindingDecisionTab } from "./FindingDecisionTab"
import { FindingEvidenceTab } from "./FindingEvidenceTab"
import { FindingGovernanceTab } from "./FindingGovernanceTab"
import { FindingHistoryTab } from "./FindingHistoryTab"
import { FindingOccurrencesTab } from "./FindingOccurrencesTab"
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
} from "./finding-detail-model"

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
          <FindingDetailContext explanation={explanation} finding={finding} />

          <div className="finding-detail-workspace-grid">
            <main className="finding-detail-workspace-main">
              <Tabs
                className="finding-detail-tabs-shell"
                value={tab}
                onValueChange={(value) =>
                  onTabChange(value as FindingDetailTab)
                }
              >
                <div className="finding-tabs-toolbar">
                  <div className="finding-tabs-heading">
                    <span>Finding workspace</span>
                    <strong>
                      Decision, evidence, ATT&amp;CK / TTP, and governance
                    </strong>
                    <p>
                      Use these top-level sections to explain, validate, and
                      defend the recorded remediation decision.
                    </p>
                  </div>
                  <TabsList className="finding-detail-tabs-list">
                    <TabsTrigger
                      className="finding-detail-tab-trigger"
                      value="decision"
                    >
                      Decision
                    </TabsTrigger>
                    <TabsTrigger
                      className="finding-detail-tab-trigger"
                      value="evidence"
                    >
                      Evidence
                    </TabsTrigger>
                    <TabsTrigger
                      className="finding-detail-tab-trigger"
                      value="occurrences"
                    >
                      Occurrences
                    </TabsTrigger>
                    <TabsTrigger
                      className="finding-detail-tab-trigger"
                      value="ttp"
                    >
                      ATT&amp;CK / TTP
                    </TabsTrigger>
                    <TabsTrigger
                      className="finding-detail-tab-trigger"
                      value="history"
                    >
                      History
                    </TabsTrigger>
                    <TabsTrigger
                      className="finding-detail-tab-trigger"
                      value="governance"
                    >
                      Governance
                    </TabsTrigger>
                  </TabsList>
                </div>

                <TabsContent
                  className="finding-detail-tab-panel"
                  value="decision"
                >
                  <FindingDecisionTab
                    decisionReasons={decisionReasons}
                    explanation={explanation}
                    finding={finding}
                    reasonRows={reasonRows}
                  />
                </TabsContent>

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

                <TabsContent
                  className="finding-detail-tab-panel"
                  value="occurrences"
                >
                  <FindingOccurrencesTab occurrences={occurrences} />
                </TabsContent>

                <TabsContent className="finding-detail-tab-panel" value="ttp">
                  <FindingTtpContextTab attackContext={attackContext} />
                </TabsContent>

                <TabsContent
                  className="finding-detail-tab-panel"
                  value="history"
                >
                  <FindingHistoryTab historyRows={historyRows} />
                </TabsContent>

                <TabsContent
                  className="finding-detail-tab-panel"
                  value="governance"
                >
                  <FindingGovernanceTab
                    finding={finding}
                    occurrences={occurrences}
                    waiverEvidence={waiverEvidence}
                  />
                </TabsContent>
              </Tabs>
            </main>

            <FindingDetailActionRail
              finding={finding}
              findingsBackSearch={findingsBackSearch}
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
  findingsBackSearch,
  occurrences,
  onRefresh,
  waiverEvidence,
}: {
  finding: FindingDetailPublic
  findingsBackSearch: FindingsUrlSearch
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
      value: findingSlaLabel(finding.priority, finding.status),
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
    <DetailRail
      aria-label="Triage summary"
      className="finding-detail-action-rail"
      description={findingComponentDetailLabel(finding)}
      footer={
        <div className="finding-detail-action-buttons">
          <Button asChild size="sm">
            <Link search={findingsBackSearch} to="/findings">
              Open in Triage
            </Link>
          </Button>
          <Button asChild size="sm" variant="outline">
            <Link search={projectSearch} to="/waivers">
              Risk acceptance
            </Link>
          </Button>
          <Button onClick={onRefresh} size="sm" type="button" variant="outline">
            <RefreshCcw aria-hidden="true" size={14} />
            Refresh evidence
          </Button>
        </div>
      }
      status={
        <>
          <RiskBadge level={finding.priority} />
          <StatusLozenge status={finding.status} />
          {finding.in_kev ? <SignalChip kind="kev" /> : null}
        </>
      }
      title="Triage state"
    >
      <div className="finding-detail-action-block">
        <span>Next step</span>
        <p>{findingNextStepLabel(finding)}</p>
      </div>

      <FindingWorkflowStatusControl finding={finding} onRefresh={onRefresh} />

      <DefinitionList columns={1} items={scopeRows} />

      <DefinitionList
        columns={1}
        items={[
          {
            label: "VEX",
            value: finding.suppressed_by_vex
              ? "Suppressed by VEX"
              : (occurrences
                  .map((occurrence) =>
                    optionalText(String(occurrence.vex_status ?? "")),
                  )
                  .find((value) => value !== "Not supplied") ??
                "No VEX overlay"),
          },
          ...decisionRows,
        ]}
      />
    </DetailRail>
  )
}

const WORKFLOW_STATUS_OPTIONS: readonly { label: string; value: FindingStatus }[] = [
  { label: "Open", value: "open" },
  { label: "In review", value: "in_review" },
  { label: "Remediating", value: "remediating" },
]

function FindingWorkflowStatusControl({
  finding,
  onRefresh,
}: {
  finding: FindingDetailPublic
  onRefresh: () => void
}) {
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState("")
  const isWorkflowStatus = WORKFLOW_STATUS_OPTIONS.some(
    (option) => option.value === finding.status,
  )

  async function applyStatus(status: FindingStatus) {
    if (status === finding.status) {
      return
    }
    setSaving(true)
    setSaveError("")
    try {
      await FindingsService.updateFindingStatus({
        finding_id: finding.id,
        findingStatusUpdateRequest: { status },
      })
      onRefresh()
    } catch {
      setSaveError("Status update failed - refresh and try again.")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="finding-detail-action-block">
      <span>Workflow status</span>
      {isWorkflowStatus ? (
        <>
          <Select
            disabled={saving}
            onValueChange={(value) => applyStatus(value as FindingStatus)}
            value={finding.status}
          >
            <SelectTrigger
              aria-label="Workflow status"
              className="w-full bg-[var(--vpw-bg-card)]"
            >
              <SelectValue placeholder="Set status" />
            </SelectTrigger>
            <SelectContent>
              {WORKFLOW_STATUS_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {saveError ? (
            <p className="finding-detail-action-error" role="alert">
              {saveError}
            </p>
          ) : null}
        </>
      ) : (
        <p>
          Managed by governance evidence (waiver, VEX, or import) - use Risk
          acceptance or evidence updates to change it.
        </p>
      )}
    </div>
  )
}
