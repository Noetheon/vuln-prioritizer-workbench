import { Link } from "@/lib/router"
import {
  CheckCircle2,
  Circle,
  FileInput,
  FileText,
  ListChecks,
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
        <div className="vpw-table-actions">
          <ProjectTableAction
            label={
              project.id === selectedProjectId
                ? "Active project"
                : "Select project"
            }
          >
            <Button
              aria-current={
                project.id === selectedProjectId ? "true" : undefined
              }
              aria-label={
                project.id === selectedProjectId
                  ? `${project.name} is active`
                  : `Select ${project.name}`
              }
              className="vpw-table-action-button"
              disabled={projectListLoading}
              onClick={() => onSelectProject(project.id)}
              size="icon-sm"
              type="button"
              variant={
                project.id === selectedProjectId ? "secondary" : "outline"
              }
            >
              {project.id === selectedProjectId ? (
                <CheckCircle2 aria-hidden="true" />
              ) : (
                <Circle aria-hidden="true" />
              )}
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
      ),
      className: "text-right",
      header: "Actions",
      headerClassName: "text-right",
      id: "actions",
    },
  ]
}
