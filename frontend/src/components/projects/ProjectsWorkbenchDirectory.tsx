import { FolderKanban, Plus, RefreshCw, Search } from "lucide-react"
import { useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwFilterBar,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwTableCard,
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
          <Button
            disabled={projectListLoading}
            onClick={onRefreshProjects}
            type="button"
            variant="outline"
          >
            <RefreshCw aria-hidden="true" />
            Refresh
          </Button>
        }
        eyebrow="Directory"
        title="Projects directory"
        description="Search, select the active workspace, or jump into imports, findings, and evidence."
      />
      <VpwFilterBar
        onSearchChange={setProjectSearch}
        searchClassName="vpw-filter-field--lg"
        searchLabel="Project search"
        searchPlaceholder="Search projects"
        searchTitle="Search"
        searchValue={projectSearch}
      />
      <VpwTableCard
        description={`${filteredProjects.length} project${
          filteredProjects.length === 1 ? "" : "s"
        } match the current directory view.`}
        title="Project register"
      >
        {projectListLoading ? (
          <VpwSkeletonStack rows={4} />
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
            minWidth="920px"
          />
        )}
      </VpwTableCard>
    </VpwSection>
  )
}
