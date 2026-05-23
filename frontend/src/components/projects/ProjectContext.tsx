import { Plus, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  VpwCommandPanel,
  VpwSection,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import type { ProjectsWorkbenchProps } from "./projects-workbench-model"
import { ProjectMetrics } from "./ProjectMetrics"

export function ProjectContext({
  onCreateProjectDrawerOpenChange,
  onRefreshProjects,
  projectListLoading,
  projectSummary,
  projectSummaryById,
  projects,
  selectedProject,
}: Pick<
  ProjectsWorkbenchProps,
  | "onCreateProjectDrawerOpenChange"
  | "onRefreshProjects"
  | "projectListLoading"
  | "projectSummary"
  | "projectSummaryById"
  | "projects"
  | "selectedProject"
>) {
  return (
    <VpwSection>
      <VpwCommandPanel
        className="projects-context-panel"
        actions={
          <VpwToolbar label="Project actions" variant="plain">
            <VpwToolbarGroup>
              <Button
                onClick={() => onCreateProjectDrawerOpenChange(true)}
                type="button"
              >
                <Plus aria-hidden="true" data-icon="inline-start" />
                Create project
              </Button>
              <Button
                aria-label="Refresh projects"
                disabled={projectListLoading}
                onClick={onRefreshProjects}
                type="button"
                variant="outline"
              >
                <RefreshCw aria-hidden="true" data-icon="inline-start" />
                Refresh
              </Button>
            </VpwToolbarGroup>
          </VpwToolbar>
        }
        description="Manage workbench projects, imported findings, runs, and evidence readiness."
        eyebrow="Project control"
        title="Workspace projects"
      >
        <ProjectMetrics
          projectSummary={projectSummary}
          projectSummaryById={projectSummaryById}
          projects={projects}
          selectedProject={selectedProject}
        />
      </VpwCommandPanel>
    </VpwSection>
  )
}
