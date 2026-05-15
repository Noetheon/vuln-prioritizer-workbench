import { FolderKanban, GitBranch, Plus, Search } from "lucide-react"
import { useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSearchInput,
  VpwSkeletonStack,
} from "@/components/vpw"
import { buildProjectDirectoryColumns } from "./ProjectsWorkbenchDirectoryColumns"
import type { ProjectsWorkbenchProps } from "./projects-workbench-model"

export function ProjectDirectory({
  onRefreshProjects,
  onSelectProject,
  projectListLoading,
  projectSummaryById,
  projects,
  selectedProjectId,
}: Pick<
  ProjectsWorkbenchProps,
  | "onRefreshProjects"
  | "onSelectProject"
  | "projectListLoading"
  | "projectSummaryById"
  | "projects"
  | "selectedProjectId"
>) {
  const [projectSearch, setProjectSearch] = useState("")
  const trimmedProjectSearch = projectSearch.trim().toLowerCase()
  const filteredProjects = useMemo(() => {
    if (!trimmedProjectSearch) return projects

    return projects.filter((project) =>
      [project.name, project.description, project.id].some((field) =>
        field?.toLowerCase().includes(trimmedProjectSearch),
      ),
    )
  }, [projects, trimmedProjectSearch])

  const columns = buildProjectDirectoryColumns({
    onSelectProject,
    projectListLoading,
    projectSummaryById,
    selectedProjectId,
  })

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          <>
            <VpwSearchInput
              aria-label="Search projects"
              className="w-full sm:w-64"
              onChange={(event) => setProjectSearch(event.target.value)}
              placeholder="Search projects"
              value={projectSearch}
            />
            <Button
              disabled={projectListLoading}
              onClick={onRefreshProjects}
              type="button"
              variant="outline"
            >
              <GitBranch aria-hidden="true" />
              Refresh projects
            </Button>
          </>
        }
        eyebrow="Directory"
        title="Projects Directory"
        description="Search, select the active workspace, or jump into imports, findings, and evidence."
      />
      {projectListLoading ? (
        <VpwPanel>
          <VpwSkeletonStack rows={4} />
        </VpwPanel>
      ) : (
        <VpwDataTable
          caption="Projects"
          columns={columns}
          data={filteredProjects}
          density="comfortable"
          emptyState={
            trimmedProjectSearch ? (
              <VpwEmptyState
                icon={<Search aria-hidden="true" className="h-5 w-5" />}
                title="No matching projects"
                description="Adjust the search query to show more project rows."
              />
            ) : (
              <VpwEmptyState
                action={
                  <Button asChild>
                    <a href="#create-project">
                      <Plus aria-hidden="true" />
                      Create project
                    </a>
                  </Button>
                }
                icon={<FolderKanban aria-hidden="true" className="h-5 w-5" />}
                title="No projects yet"
                description="Create a project to start importing findings and generating evidence."
              />
            )
          }
          getRowKey={(project) => project.id}
        />
      )}
    </VpwSection>
  )
}
