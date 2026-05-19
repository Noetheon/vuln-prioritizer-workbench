import {
  VpwBadge,
  VpwGrid,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
} from "@/components/vpw"
import {
  evidenceState,
  latestRunLabel,
  openFindings,
  type ProjectsWorkbenchProps,
} from "./projects-workbench-model"

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
        description="Choose which project owns imports, finding review, and evidence generation."
        eyebrow="Active project"
        title="Select Workspace"
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
