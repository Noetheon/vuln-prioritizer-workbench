import { Link } from "@/lib/router"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { VpwBadge, type VpwDataTableColumn } from "@/components/vpw"
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
>

export function buildProjectDirectoryColumns({
  onSelectProject,
  projectListLoading,
  projectSummaryById,
  selectedProjectId,
}: BuildProjectDirectoryColumnsArgs): VpwDataTableColumn<ProjectPublic>[] {
  return [
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
          <div className="flex flex-col gap-1">
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
          {(["imports", "findings", "reports"] as const).map((route) => (
            <Button
              asChild
              key={route}
              onClick={() => onSelectProject(project.id)}
              size="sm"
              variant="ghost"
            >
              <Link to={`/${route}`}>
                {route === "reports"
                  ? "Evidence"
                  : route[0].toUpperCase() + route.slice(1)}
              </Link>
            </Button>
          ))}
        </div>
      ),
      className: "text-right",
      header: "Actions",
      headerClassName: "text-right",
      id: "actions",
    },
  ]
}
