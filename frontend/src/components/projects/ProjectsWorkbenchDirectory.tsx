import { FolderKanban, Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwSection,
  VpwSkeletonStack,
  VpwTableCard,
} from "@/components/vpw"
import { buildProjectDirectoryColumns } from "./ProjectsWorkbenchDirectoryColumns"
import type { ProjectsWorkbenchProps } from "./projects-workbench-model"

export function ProjectDirectory({
  onCreateProjectDrawerOpenChange,
  onSelectProject,
  projectListLoading,
  projectSummaryById,
  projects,
  selectedProjectId,
  onStartEditProject,
}: Pick<
  ProjectsWorkbenchProps,
  | "onCreateProjectDrawerOpenChange"
  | "onSelectProject"
  | "projectListLoading"
  | "projectSummaryById"
  | "projects"
  | "selectedProjectId"
  | "onStartEditProject"
>) {
  const columns = buildProjectDirectoryColumns({
    onSelectProject,
    projectListLoading,
    projectSummaryById,
    selectedProjectId,
    onStartEditProject,
  })
  const projectCount = `${projects.length} project${
    projects.length === 1 ? "" : "s"
  }`

  return (
    <VpwSection className="projects-directory-section">
      <VpwTableCard
        className="projects-register-card"
        description={`${projectCount} available in the local workbench.`}
        eyebrow="Register"
        title="Project register"
      >
        {projectListLoading ? (
          <VpwSkeletonStack rows={4} />
        ) : (
          <VpwDataTable
            caption="Projects"
            columns={columns}
            data={projects}
            density="comfortable"
            emptyState={
              <VpwEmptyState
                action={
                  <Button
                    onClick={() => onCreateProjectDrawerOpenChange(true)}
                    type="button"
                  >
                    <Plus aria-hidden="true" />
                    Create project
                  </Button>
                }
                icon={<FolderKanban aria-hidden="true" className="h-5 w-5" />}
                title="No projects yet"
                description="Create a project to start importing findings and generating evidence."
              />
            }
            getRowKey={(project) => project.id}
            minWidth="860px"
          />
        )}
      </VpwTableCard>
    </VpwSection>
  )
}
