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
  VpwDemoBanner,
  MetricStrip,
  type MetricStripMetric,
  VpwSection,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { DEMO_PROJECT, DEMO_RUNS } from "@/lib/demo-data"
import { formatReportDateTime } from "@/lib/report-format"
import { runStatusLabel } from "@/lib/risk-format"
import {
  evidenceReadinessLabel,
  evidenceReadinessTone,
  providerSnapshotLabel,
  runMetricTone,
  runShortId,
} from "./evidence-center-model"

type RunContextProps = {
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  projects: ProjectPublic[]
  projectListLoading: boolean
  onProjectChange: (id: string) => void
  selectedRunId: string
  onRunIdChange: (id: string) => void
  onOpenGenerateDrawer: () => void
  selectedReportRun: AnalysisRunPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  projectRuns: AnalysisRunPublic[]
  providerStatus: ProviderStatusPublic | null
  runsLoading: boolean
  reportActionsEnabled: boolean
  isDemo: boolean
}

export function RunContext({
  isDemo,
  onOpenGenerateDrawer,
  providerStatus,
  reportActionsEnabled,
  runsLoading,
  selectedProject,
  selectedReportRun,
}: RunContextProps) {
  const run = isDemo ? DEMO_RUNS[0] : selectedReportRun
  const readiness = evidenceReadinessLabel({
    isDemo,
    reportActionsEnabled,
    selectedReportRun,
  })
  const runStatus = isDemo
    ? "Succeeded"
    : selectedReportRun
      ? runStatusLabel(selectedReportRun.status)
      : runsLoading
        ? "Loading"
        : "No run selected"
  const runDetail = run
    ? `${runStatus.toLowerCase()} · ${formatReportDateTime(run.finished_at)}`
    : "Select a completed import run"
  const projectName = isDemo
    ? DEMO_PROJECT.name
    : (selectedProject?.name ?? "None selected")
  const snapshotLabel = isDemo
    ? "demo · locked"
    : providerSnapshotLabel(selectedReportRun, providerStatus)
  const readinessTone = evidenceReadinessTone(readiness)
  const runTone = runsLoading ? "neutral" : runMetricTone(run, isDemo)
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
      tone: runTone,
      value: run ? runShortId(run) : runStatus,
    },
    {
      description: "Provider replay basis",
      icon: <Database aria-hidden="true" />,
      label: "Provider snapshot",
      tone: "support",
      value: snapshotLabel,
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
      {isDemo ? (
        <VpwDemoBanner>
          <strong>Demo preview.</strong> Sample evidence data is visible only
          because no real project is selected. Connect a project and completed
          run to generate production evidence.
        </VpwDemoBanner>
      ) : null}
      <VpwCommandPanel
        actions={
          <VpwToolbar label="Evidence actions" variant="plain">
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
        description="Select the project and import run that generated artifacts should represent."
        eyebrow="Govern"
        title="Evidence run context"
      >
        <MetricStrip
          className="evidence-run-context-facts"
          metrics={metrics}
          minCardWidth="13rem"
        />
      </VpwCommandPanel>
    </VpwSection>
  )
}
