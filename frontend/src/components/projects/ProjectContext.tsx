import { Link } from "@/lib/router"
import { Plus, Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwBadge,
  VpwCommandPanel,
  VpwSection,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import {
  evidenceState,
  latestRunStatus,
  type ProjectsWorkbenchProps,
  runTone,
} from "./projects-workbench-model"

export function ProjectContext({
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
      <VpwCommandPanel
        actions={
          <VpwToolbar label="Project actions" variant="plain">
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
        }
        description="Manage workbench projects, imported findings, runs, and evidence readiness."
        eyebrow="Project control"
        title="Workspace projects"
      />
    </VpwSection>
  )
}
