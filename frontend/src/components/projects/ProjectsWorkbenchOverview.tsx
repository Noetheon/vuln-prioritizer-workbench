import { Link } from "@/lib/router"
import {
  CheckCircle2,
  Clock3,
  FolderKanban,
  Gauge,
  Plus,
  ShieldCheck,
  Upload,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwBadge,
  VpwGrid,
  VpwMetricCard,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import {
  evidenceState,
  latestRunLabel,
  latestRunStatus,
  openFindings,
  type ProjectsWorkbenchProps,
  runTone,
  totalOpenFindings,
} from "./projects-workbench-model"

export function ProjectHero({
  projectSummary,
  projects,
  selectedProject,
}: Pick<
  ProjectsWorkbenchProps,
  "projectSummary" | "projects" | "selectedProject"
>) {
  const evidence = evidenceState(projectSummary)
  const projectSearch = selectedProjectRouteSearch(selectedProject?.id ?? "")

  return (
    <VpwSection>
      <VpwSectionHeader
        eyebrow="Projects"
        title="Projects"
        description="Manage workbench projects, imported findings, runs, and evidence readiness."
      />
      <VpwToolbar label="Project actions">
        <VpwToolbarGroup>
          <Button asChild>
            <a href="#create-project">
              <Plus aria-hidden="true" />
              Create project
            </a>
          </Button>
          <Button asChild variant="outline">
            <Link search={projectSearch} to="/imports">
              <Upload aria-hidden="true" />
              Import findings
            </Link>
          </Button>
        </VpwToolbarGroup>
        <VpwToolbarGroup>
          <VpwBadge
            className="max-w-full truncate"
            tone={selectedProject ? "success" : "neutral"}
          >
            {selectedProject?.name ?? "Project required"}
          </VpwBadge>
          <VpwBadge tone="info">{projects.length} project(s)</VpwBadge>
          <VpwBadge tone={runTone(projectSummary?.latest_run_status)}>
            {latestRunStatus(projectSummary)}
          </VpwBadge>
          <VpwBadge tone={evidence.tone}>{evidence.detail}</VpwBadge>
        </VpwToolbarGroup>
      </VpwToolbar>
    </VpwSection>
  )
}

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
      <VpwGrid columns={4} className="xl:grid-cols-5">
        <VpwMetricCard
          description="Workbench projects"
          icon={<FolderKanban aria-hidden="true" className="h-5 w-5" />}
          label="Total projects"
          tone="info"
          value={projects.length}
        />
        <VpwMetricCard
          description={selectedProject?.name ?? "Create or select a project"}
          icon={<CheckCircle2 aria-hidden="true" className="h-5 w-5" />}
          label="Active project"
          tone={selectedProject ? "success" : "warning"}
          value={selectedProject ? "Selected" : "Required"}
        />
        <VpwMetricCard
          description={latestRunLabel(projectSummary)}
          icon={<Clock3 aria-hidden="true" className="h-5 w-5" />}
          label="Latest import run"
          tone={runTone(projectSummary?.latest_run_status)}
          value={latestRunStatus(projectSummary)}
        />
        <VpwMetricCard
          description="Open or total findings"
          icon={<Gauge aria-hidden="true" className="h-5 w-5" />}
          label="Open findings"
          tone={
            typeof totalOpen === "number" && totalOpen > 0
              ? "warning"
              : "neutral"
          }
          value={totalOpen ?? "No data"}
        />
        <VpwMetricCard
          description={evidence.detail}
          icon={<ShieldCheck aria-hidden="true" className="h-5 w-5" />}
          label="Evidence readiness"
          tone={evidence.tone === "neutral" ? "info" : evidence.tone}
          value={evidence.label}
        />
      </VpwGrid>
    </VpwSection>
  )
}

export function ProjectSelectionStrip({
  onSelectProject,
  projectSummaryById,
  projects,
  selectedProjectId,
}: Pick<
  ProjectsWorkbenchProps,
  "onSelectProject" | "projectSummaryById" | "projects" | "selectedProjectId"
>) {
  if (projects.length === 0) return null

  return (
    <VpwSection>
      <VpwSectionHeader
        eyebrow="Active project"
        title="Select Workspace"
        description="Choose which project owns imports, finding review, and evidence generation."
      />
      <VpwGrid columns={4}>
        {projects.slice(0, 4).map((project) => {
          const summary = projectSummaryById[project.id] ?? null
          const evidence = evidenceState(summary)
          return (
            <VpwSelectionCard
              checked={project.id === selectedProjectId}
              key={project.id}
              meta={
                <span className="flex flex-wrap items-center gap-2">
                  <VpwBadge tone={evidence.tone}>{evidence.label}</VpwBadge>
                  <span>{openFindings(summary) ?? "No"} findings</span>
                </span>
              }
              onClick={() => onSelectProject(project.id)}
              title={project.name}
            >
              {project.description || latestRunLabel(summary)}
            </VpwSelectionCard>
          )
        })}
      </VpwGrid>
    </VpwSection>
  )
}
