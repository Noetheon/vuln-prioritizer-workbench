import { Link } from "@/lib/router"
import {
  FileInput,
  FileText,
  ListChecks,
  Settings,
} from "lucide-react"
import type { ReactNode } from "react"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { VpwBadge, type VpwDataTableColumn } from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  evidenceState,
  formatDateTime,
  latestRunLabel,
  latestRunStatus,
  openFindings,
  type ProjectsWorkbenchProps,
  runTone,
} from "./projects-workbench-model"

type BuildProjectDirectoryColumnsArgs = Pick<
  ProjectsWorkbenchProps,
  | "onSelectProject"
  | "projectListLoading"
  | "projectSummaryById"
  | "selectedProjectId"
  | "onStartEditProject"
>

function ProjectTableAction({
  children,
  label,
}: {
  children: ReactNode
  label: string
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

export function buildProjectDirectoryColumns({
  onSelectProject,
  projectListLoading,
  projectSummaryById,
  selectedProjectId,
  onStartEditProject,
}: BuildProjectDirectoryColumnsArgs): VpwDataTableColumn<ProjectPublic>[] {
  return [
    {
      cell: (project) => (
        <div className="projects-project-cell">
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
          <div className="flex flex-col gap-1">
            <p className="font-medium">
              {summary?.latest_run_id ? (
                <span
                  className="inline-block w-[5.75rem]"
                  data-vpw-visual-mask="true"
                >
                  {latestRunLabel(summary)}
                </span>
              ) : (
                latestRunLabel(summary)
              )}
            </p>
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
        const count = openFindings(projectSummaryById[project.id] ?? null)
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
      cell: (project) => {
        const projectSearch = selectedProjectRouteSearch(project.id)

        return (
          <div className="vpw-table-actions">
            <ProjectTableAction label="Workspace settings">
              <Button
                aria-label={`Settings for ${project.name}`}
                className="vpw-table-action-button"
                disabled={projectListLoading}
                onClick={() => onStartEditProject(project)}
                size="icon-sm"
                type="button"
                variant="outline"
              >
                <Settings className="size-4" aria-hidden="true" />
              </Button>
            </ProjectTableAction>
            {(["imports", "findings", "reports"] as const).map((route) => (
              <ProjectTableAction
                key={route}
                label={
                  route === "imports"
                    ? "Open imports"
                    : route === "findings"
                      ? "Open findings"
                      : "Open evidence"
                }
              >
                <Button
                  asChild
                  className="vpw-table-action-button"
                  onClick={() => onSelectProject(project.id)}
                  size="icon-sm"
                  variant="outline"
                >
                  <Link
                    aria-label={`Open ${
                      route === "reports" ? "evidence" : route
                    } for ${project.name}`}
                    search={projectSearch}
                    to={`/${route}`}
                  >
                    {route === "imports" ? (
                      <FileInput aria-hidden="true" />
                    ) : route === "findings" ? (
                      <ListChecks aria-hidden="true" />
                    ) : (
                      <FileText aria-hidden="true" />
                    )}
                  </Link>
                </Button>
              </ProjectTableAction>
            ))}
          </div>
        )
      },
      className: "min-w-[10rem] text-right",
      header: "Actions",
      headerClassName: "text-right",
      id: "actions",
      width: "10rem",
    },
  ]
}
