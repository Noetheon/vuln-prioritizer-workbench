import {
  CheckCircle2,
  Clock3,
  FolderKanban,
  Gauge,
  ShieldCheck,
} from "lucide-react"
import { VpwCompactMetric, VpwMetricStrip, VpwSection } from "@/components/vpw"
import {
  evidenceState,
  latestRunLabel,
  latestRunStatus,
  type ProjectsWorkbenchProps,
  runTone,
  totalOpenFindings,
} from "./projects-workbench-model"

export function ProjectMetrics({
  projectSummary,
  projectSummaryById,
  projects,
  selectedProject,
}: Pick<
  ProjectsWorkbenchProps,
  "projectSummary" | "projectSummaryById" | "projects" | "selectedProject"
>) {
  const evidence = evidenceState(projectSummary)
  const totalOpen = totalOpenFindings(projects, projectSummaryById)

  return (
    <VpwSection>
      <VpwMetricStrip minCardWidth="12rem">
        <VpwCompactMetric
          description="Workbench projects"
          icon={<FolderKanban aria-hidden="true" className="h-5 w-5" />}
          label="Total projects"
          tone="info"
          value={projects.length}
        />
        <VpwCompactMetric
          description={selectedProject?.name ?? "Create or select a project"}
          icon={<CheckCircle2 aria-hidden="true" className="h-5 w-5" />}
          label="Active project"
          tone={selectedProject ? "success" : "warning"}
          value={selectedProject ? "Selected" : "Required"}
        />
        <VpwCompactMetric
          description={latestRunLabel(projectSummary)}
          icon={<Clock3 aria-hidden="true" className="h-5 w-5" />}
          label="Latest import run"
          tone={runTone(projectSummary?.latest_run_status)}
          value={latestRunStatus(projectSummary)}
        />
        <VpwCompactMetric
          description="Open or total findings"
          icon={<Gauge aria-hidden="true" className="h-5 w-5" />}
          label="Open findings"
          tone={
            typeof totalOpen === "number"
              ? totalOpen > 0
                ? "warning"
                : "success"
              : "info"
          }
          value={totalOpen ?? "No data"}
        />
        <VpwCompactMetric
          description={evidence.detail}
          icon={<ShieldCheck aria-hidden="true" className="h-5 w-5" />}
          label="Evidence readiness"
          tone={evidence.tone === "neutral" ? "info" : evidence.tone}
          value={evidence.label}
        />
      </VpwMetricStrip>
    </VpwSection>
  )
}
