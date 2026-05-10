import { ShieldCheck } from "lucide-react"
import type { AnalysisRunPublic, ProjectPublic } from "@/api-client"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwDemoBanner,
  VpwSection,
  VpwSectionHeader,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { DEMO_PROJECT, DEMO_RUNS } from "@/lib/demo-data"
import { runStatusLabel } from "@/lib/risk-format"
import { runBadgeTone, runFileLabel } from "./evidence-center-model"
import { ReportProjectSelect, ReportRunSelect } from "./EvidenceCenterRunSelectors"

type RunContextProps = {
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  projects: ProjectPublic[]
  projectListLoading: boolean
  onProjectChange: (id: string) => void
  selectedRunId: string
  onRunIdChange: (id: string) => void
  selectedReportRun: AnalysisRunPublic | null
  projectRuns: AnalysisRunPublic[]
  runsLoading: boolean
  reportActionsEnabled: boolean
  isDemo: boolean
}

export function RunContext({
  isDemo,
  onProjectChange,
  onRunIdChange,
  projectListLoading,
  projectRuns,
  projects,
  reportActionsEnabled,
  runsLoading,
  selectedProject,
  selectedProjectId,
  selectedReportRun,
  selectedRunId,
}: RunContextProps) {
  const runLabel = isDemo
    ? "Succeeded"
    : selectedReportRun
      ? runStatusLabel(selectedReportRun.status)
      : runsLoading
        ? "Loading"
        : "No run selected"
  const runDetail = isDemo
    ? "demo-run-0001"
    : selectedReportRun
      ? `${runFileLabel(selectedReportRun)} · ${selectedReportRun.id.slice(0, 8)}`
      : "Select a completed run"
  const readinessTone: VpwBadgeTone =
    reportActionsEnabled || isDemo ? "success" : "neutral"

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          isDemo ? <VpwBadge tone="warning">Demo preview</VpwBadge> : null
        }
        description="Generate audit-ready vulnerability evidence, executive summaries, and technical exports."
        eyebrow="Reports"
        title="Evidence Center"
      />
      {isDemo ? (
        <VpwDemoBanner>
          <strong>Demo preview.</strong> Sample evidence data is visible only
          because no real project is selected. Connect a project and completed
          run to generate production evidence.
        </VpwDemoBanner>
      ) : null}
      <VpwToolbar label="Report context">
        <VpwToolbarGroup>
          <div className="min-w-0">
            <p className="vpw-label">Project</p>
            <p className="truncate text-sm font-semibold text-[var(--vpw-text-primary)]">
              {isDemo
                ? DEMO_PROJECT.name
                : (selectedProject?.name ?? "None selected")}
            </p>
          </div>
          <div className="min-w-0">
            <p className="vpw-label">Analysis run</p>
            <div className="mt-1 flex min-w-0 flex-wrap items-center gap-2">
              <VpwBadge
                tone={
                  isDemo || selectedReportRun
                    ? runBadgeTone((selectedReportRun ?? DEMO_RUNS[0]).status)
                    : "neutral"
                }
              >
                {runLabel}
              </VpwBadge>
              <span className="min-w-0 truncate text-xs text-[var(--vpw-text-secondary)]">
                {runDetail}
              </span>
            </div>
          </div>
        </VpwToolbarGroup>
        <VpwToolbarGroup>
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
          <VpwBadge tone={readinessTone}>
            <ShieldCheck aria-hidden="true" className="h-3 w-3" />
            {reportActionsEnabled
              ? "Ready for generation"
              : isDemo
                ? "Demo mode"
                : "Select completed run"}
          </VpwBadge>
        </VpwToolbarGroup>
      </VpwToolbar>
    </VpwSection>
  )
}
