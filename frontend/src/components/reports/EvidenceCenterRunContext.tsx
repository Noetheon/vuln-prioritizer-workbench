import { ShieldCheck } from "lucide-react"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { ReactNode } from "react"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwDemoBanner,
  VpwPanel,
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
  runBadgeTone,
  runShortId,
} from "./evidence-center-model"
import { ReportProjectSelect, ReportRunSelect } from "./EvidenceCenterRunSelectors"

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
  onProjectChange,
  onRunIdChange,
  projectListLoading,
  projectRuns,
  projects,
  providerStatus,
  reportActionsEnabled,
  runsLoading,
  selectedProject,
  selectedProjectId,
  selectedReportRun,
  selectedRunId,
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
    ? `${runShortId(run)} · ${runStatus.toLowerCase()} · ${formatReportDateTime(run.finished_at)}`
    : "Select a completed import run"

  return (
    <VpwSection>
      {isDemo ? (
        <VpwDemoBanner>
          <strong>Demo preview.</strong> Sample evidence data is visible only
          because no real project is selected. Connect a project and completed
          run to generate production evidence.
        </VpwDemoBanner>
      ) : null}
      <VpwPanel className="sticky top-0 z-10 flex flex-col gap-4 bg-[var(--vpw-bg-page)] p-4">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-[1fr_1.4fr_1fr_1fr]">
          <ContextFact
            label="Project"
            value={
              isDemo
                ? DEMO_PROJECT.name
                : (selectedProject?.name ?? "None selected")
            }
          />
          <ContextFact label="Analysis run" value={runDetail}>
            {run ? (
              <VpwBadge tone={runBadgeTone(run.status)}>
                Run {runStatus.toLowerCase()}
              </VpwBadge>
            ) : null}
          </ContextFact>
          <ContextFact
            label="Provider snapshot"
            value={
              isDemo
                ? "demo · locked"
                : providerSnapshotLabel(selectedReportRun, providerStatus)
            }
          />
          <ContextFact label="Evidence state" value={readiness}>
            <VpwBadge tone={evidenceReadinessTone(readiness)}>
              <ShieldCheck aria-hidden="true" data-icon="inline-start" />
              {readiness}
            </VpwBadge>
          </ContextFact>
        </div>
        <VpwToolbar label="Run context actions" variant="plain">
          <VpwToolbarGroup className="min-w-0 flex-1">
            {!isDemo ? (
              <ReportProjectSelect
                disabled={projectListLoading || projects.length === 0}
                onProjectChange={onProjectChange}
                projects={projects}
                selectedProjectId={selectedProjectId}
              />
            ) : null}
            {!isDemo ? (
              <ReportRunSelect
                disabled={runsLoading || projectRuns.length === 0}
                onRunIdChange={onRunIdChange}
                runs={projectRuns}
                selectedRunId={selectedRunId}
              />
            ) : null}
          </VpwToolbarGroup>
          <VpwToolbarGroup>
            <Button
              disabled={isDemo || projectRuns.length === 0}
              onClick={() => {
                document
                  .querySelector<HTMLButtonElement>(
                    "[aria-label='Select analysis run']",
                  )
                  ?.focus()
              }}
              type="button"
              variant="outline"
            >
              Change run
            </Button>
            <Button
              disabled={!reportActionsEnabled}
              onClick={onOpenGenerateDrawer}
              type="button"
            >
              Generate evidence
            </Button>
          </VpwToolbarGroup>
        </VpwToolbar>
      </VpwPanel>
    </VpwSection>
  )
}

function ContextFact({
  children,
  label,
  value,
}: {
  children?: ReactNode
  label: string
  value: string
}) {
  return (
    <div className="min-w-0">
      <p className="vpw-label">{label}</p>
      <div className="mt-1 flex min-w-0 flex-wrap items-center gap-2">
        <p className="min-w-0 truncate text-sm font-semibold text-[var(--vpw-text-primary)]">
          {value}
        </p>
        {children}
      </div>
    </div>
  )
}
