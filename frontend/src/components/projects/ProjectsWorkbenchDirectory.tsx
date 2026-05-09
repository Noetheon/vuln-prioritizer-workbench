import { Link } from "@tanstack/react-router"
import { FolderKanban, GitBranch, Plus } from "lucide-react"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
} from "@/components/vpw"
import {
  evidenceState,
  formatDateTime,
  latestRunLabel,
  latestRunStatus,
  openFindings,
  type ProjectsWorkbenchProps,
  runTone,
} from "./projects-workbench-model"

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
  const columns: VpwDataTableColumn<ProjectPublic>[] = [
    {
      cell: (project) => (
        <div className="max-w-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold">{project.name}</span>
            {project.id === selectedProjectId ? (
              <VpwBadge tone="success">Active</VpwBadge>
            ) : null}
          </div>
          <p className="mt-1 line-clamp-2 text-sm text-[var(--vpw-text-secondary)]">
            {project.description || "No description"}
          </p>
        </div>
      ),
      header: "Project",
      id: "project",
    },
    {
      cell: (project) => {
        const summary = projectSummaryById[project.id] ?? null
        return (
          <div className="space-y-1">
            <p className="font-medium">{latestRunLabel(summary)}</p>
            <VpwBadge tone={runTone(summary?.latest_run_status)}>
              {latestRunStatus(summary)}
            </VpwBadge>
          </div>
        )
      },
      header: "Latest run",
      id: "latest-run",
    },
    {
      cell: (project) => {
        const summary = projectSummaryById[project.id] ?? null
        const count = openFindings(summary)
        return (
          <span className="font-medium">
            {typeof count === "number" ? count : "No data"}
          </span>
        )
      },
      header: "Findings",
      id: "findings",
    },
    {
      cell: (project) => {
        const state = evidenceState(projectSummaryById[project.id] ?? null)
        return <VpwBadge tone={state.tone}>{state.label}</VpwBadge>
      },
      header: "Evidence",
      id: "evidence",
    },
    {
      cell: (project) => (
        <div className="min-w-36">
          <p>{formatDateTime(project.updated_at)}</p>
          <p className="text-xs text-[var(--vpw-text-muted)]">
            Created {formatDateTime(project.created_at)}
          </p>
        </div>
      ),
      header: "Updated",
      id: "updated",
    },
    {
      cell: (project) => (
        <div className="flex flex-wrap items-center justify-end gap-2">
          <Button
            disabled={projectListLoading}
            onClick={() => onSelectProject(project.id)}
            size="sm"
            type="button"
            variant={project.id === selectedProjectId ? "secondary" : "outline"}
          >
            {project.id === selectedProjectId ? "Selected" : "Select"}
          </Button>
          <Button
            asChild
            onClick={() => onSelectProject(project.id)}
            size="sm"
            variant="ghost"
          >
            <Link to="/imports">Import</Link>
          </Button>
          <Button
            asChild
            onClick={() => onSelectProject(project.id)}
            size="sm"
            variant="ghost"
          >
            <Link to="/findings">Findings</Link>
          </Button>
          <Button
            asChild
            onClick={() => onSelectProject(project.id)}
            size="sm"
            variant="ghost"
          >
            <Link to="/reports">Evidence</Link>
          </Button>
        </div>
      ),
      className: "text-right",
      header: "Actions",
      headerClassName: "text-right",
      id: "actions",
    },
  ]

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
            <GitBranch aria-hidden="true" />
            Refresh projects
          </Button>
        }
        eyebrow="Directory"
        title="Projects Directory"
        description="Select the active workspace or jump into imports, findings, and evidence."
      />
      {projectListLoading ? (
        <VpwPanel>
          <VpwSkeletonStack rows={4} />
        </VpwPanel>
      ) : (
        <VpwDataTable
          caption="Projects"
          columns={columns}
          data={projects}
          density="comfortable"
          emptyState={
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
          }
          getRowKey={(project) => project.id}
        />
      )}
    </VpwSection>
  )
}
