import {
  BriefcaseBusiness,
  Database,
  FileCheck2,
  GitBranch,
  ShieldCheck,
} from "lucide-react"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwCommandPanel,
  MetricStrip,
  type MetricStripMetric,
  VpwSection,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { formatReportDateTime } from "@/lib/report-format"
import { runStatusLabel } from "@/lib/risk-format"
import {
  evidenceReadinessLabel,
  evidenceReadinessTone,
  providerSnapshotLabel,
  runMetricTone,
  runShortId,
} from "./evidence-center-model"
import { ReportRunSelect } from "./EvidenceCenterRunSelectors"
import {
  currentProjectStateScope,
  reportRunScope,
} from "./report-run-scope-model"

type RunContextProps = {
  currentStateSelected?: boolean
  projectFindingCount?: number | null
  selectedProject: ProjectPublic | null
  selectedRunId: string
  onRunIdChange: (id: string) => void
  onOpenGenerateDrawer: () => void
  selectedReportRun: AnalysisRunPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  projectRuns: AnalysisRunPublic[]
  providerStatus: ProviderStatusPublic | null
  runsLoading: boolean
  reportActionsEnabled: boolean
}

export function RunContext({
  currentStateSelected = false,
  onOpenGenerateDrawer,
  projectFindingCount = null,
  onRunIdChange,
  projectRuns,
  providerStatus,
  reportActionsEnabled,
  runsLoading,
  selectedProject,
  selectedReportRun,
  selectedRunId,
  selectedRunSummary,
}: RunContextProps) {
  const run = selectedReportRun
  const readiness = currentStateSelected
    ? reportActionsEnabled
      ? "Ready for generation"
      : "Checking"
    : evidenceReadinessLabel({
        reportActionsEnabled,
        selectedReportRun,
      })
  const runStatus = selectedReportRun
    ? runStatusLabel(selectedReportRun.status)
    : runsLoading
      ? "Loading"
      : "No run selected"
  const runDetail = currentStateSelected
    ? "Recorded when a report is generated"
    : run
      ? `${runStatus.toLowerCase()} · ${formatReportDateTime(run.finished_at)}`
      : "Select a completed import run"
  const projectName = selectedProject?.name ?? "None selected"
  const snapshotLabel = providerSnapshotLabel(selectedReportRun, providerStatus)
  const readinessTone = evidenceReadinessTone(readiness)
  const runTone = runsLoading ? "neutral" : runMetricTone(run)
  const scope = currentStateSelected
    ? currentProjectStateScope(projectFindingCount)
    : reportRunScope(selectedReportRun, projectRuns, {
        projectStateCurrent: selectedRunSummary?.project_state_current,
      })
  const metrics: MetricStripMetric[] = [
    {
      description: "Artifact ownership scope",
      icon: <BriefcaseBusiness aria-hidden="true" />,
      label: "Project",
      tone: "neutral",
      value: projectName,
    },
    {
      description: runDetail,
      icon: <GitBranch aria-hidden="true" />,
      label: "Analysis run",
      tone: currentStateSelected ? "info" : runTone,
      value: currentStateSelected
        ? "Current project state"
        : run
          ? runShortId(run)
          : runStatus,
      visualMaskValue: Boolean(run) && !currentStateSelected,
    },
    {
      description: "Provider replay basis",
      icon: <Database aria-hidden="true" />,
      label: "Provider snapshot",
      tone: "support",
      value: currentStateSelected ? "Each finding's latest data" : snapshotLabel,
      visualMaskValue: Boolean(run?.provider_snapshot_id ?? providerStatus?.snapshot.id),
    },
    {
      description: "Generation readiness",
      icon: <ShieldCheck aria-hidden="true" />,
      label: "Evidence state",
      tone: readinessTone,
      value: readiness,
    },
  ]

  return (
    <VpwSection>
      <VpwCommandPanel
        actions={
          <VpwToolbar label="Evidence actions" variant="plain">
            <VpwToolbarGroup>
              <ReportRunSelect
                disabled={runsLoading && projectRuns.length === 0}
                onRunIdChange={onRunIdChange}
                runs={projectRuns}
                selectedRunId={selectedRunId}
              />
            </VpwToolbarGroup>
            <VpwToolbarGroup>
              <Button
                disabled={!reportActionsEnabled}
                onClick={onOpenGenerateDrawer}
                type="button"
              >
                <FileCheck2 aria-hidden="true" data-icon="inline-start" />
                Generate evidence
              </Button>
            </VpwToolbarGroup>
          </VpwToolbar>
        }
        className="evidence-run-context-panel"
        description="Reports describe the current state of the whole project unless you pick one run."
        eyebrow="Govern"
        title="Evidence run context"
      >
        <MetricStrip
          className="evidence-run-context-facts"
          metrics={metrics}
          minCardWidth="13rem"
        />
      </VpwCommandPanel>
      {scope ? (
        <VpwStatusBanner title={scope.title} tone={scope.tone}>
          {scope.message}
        </VpwStatusBanner>
      ) : null}
    </VpwSection>
  )
}
