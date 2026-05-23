import { Check, Copy } from "lucide-react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  DetailDrawer,
  VpwBadge,
  VpwKeyValueList,
  VpwProgress,
} from "@/components/vpw"
import {
  ActiveProjectDeletePanel,
  ActiveProjectEditForm,
} from "./ProjectsWorkbenchActiveControls"
import {
  evidenceState,
  formatDateTime,
  readinessProgress,
  type ProjectsWorkbenchProps,
} from "./projects-workbench-model"

type ProjectDetailDrawerProps = Pick<
  ProjectsWorkbenchProps,
  | "deleteConfirmed"
  | "editProjectForm"
  | "editProjectId"
  | "onCancelEditProject"
  | "onDeleteConfirmedChange"
  | "onDeleteProject"
  | "onEditProjectDescriptionChange"
  | "onEditProjectNameChange"
  | "onSaveProject"
  | "onSelectProject"
  | "projectActionLoading"
  | "projectListLoading"
  | "projectSummaryById"
  | "projects"
  | "selectedProjectId"
>

export function ProjectDetailDrawer(props: ProjectDetailDrawerProps) {
  const [copied, setCopied] = useState(false)
  const editingProject =
    props.projects.find((project) => project.id === props.editProjectId) ??
    null

  if (!editingProject) return null

  const project = editingProject
  const summary = props.projectSummaryById[project.id] ?? null
  const evidence = evidenceState(summary)
  const readiness = readinessProgress(project, summary)
  const openFindingCount =
    summary?.open_finding_count ?? summary?.finding_count ?? null

  function copyProjectId() {
    void navigator.clipboard.writeText(project.id).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <DetailDrawer
      className="project-settings-drawer w-[min(100vw,40rem)] sm:max-w-none"
      description={project.description || "No description recorded."}
      onOpenChange={(open) => {
        if (!open) props.onCancelEditProject()
      }}
      open
      title={project.name}
    >
      <Tabs className="mt-4 w-full" defaultValue="overview">
        <TabsList className="mb-6 grid grid-cols-2">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
        </TabsList>
        <TabsContent className="flex flex-col gap-6" value="overview">
          <ProjectDrawerOverviewCard
            active={project.id === props.selectedProjectId}
            disabled={props.projectListLoading}
            onActivate={() => props.onSelectProject(project.id)}
          />
          <ProjectDrawerReadiness
            openFindingCount={openFindingCount}
            readiness={readiness}
            tone={evidence.tone === "critical" ? "critical" : "info"}
          />
          <VpwKeyValueList
            columns={2}
            density="compact"
            items={[
              {
                label: "Project ID",
                value: (
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="truncate">{project.id}</span>
                    <Button
                      aria-label="Copy project ID"
                      className="h-5 w-5 shrink-0 text-[var(--vpw-text-secondary)] hover:text-[var(--vpw-text-primary)]"
                      onClick={copyProjectId}
                      size="icon-xs"
                      type="button"
                      variant="ghost"
                    >
                      {copied ? (
                        <Check className="h-3.5 w-3.5 text-[var(--vpw-green)]" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                    </Button>
                  </div>
                ),
              },
              {
                label: "Evidence status",
                value: <VpwBadge tone={evidence.tone}>{evidence.label}</VpwBadge>,
              },
              { label: "Created", value: formatDateTime(project.created_at) },
              { label: "Updated", value: formatDateTime(project.updated_at) },
            ]}
          />
        </TabsContent>
        <TabsContent className="flex flex-col gap-6" value="config">
          <ProjectDrawerEditCard {...props} />
          <ProjectDrawerDangerCard {...props} selectedProject={project} />
        </TabsContent>
      </Tabs>
    </DetailDrawer>
  )
}

function ProjectDrawerOverviewCard({
  active,
  disabled,
  onActivate,
}: {
  active: boolean
  disabled: boolean
  onActivate: () => void
}) {
  return (
    <div className="project-drawer-card flex items-center justify-between rounded-xl border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] p-4">
      <div className="flex min-w-0 flex-col gap-1">
        <span className="font-semibold text-sm text-[var(--vpw-text-primary)]">
          Workspace scope
        </span>
        <span className="truncate text-xs text-[var(--vpw-text-muted)]">
          {active
            ? "This project is currently active."
            : "Activate this project to scope findings and evidence."}
        </span>
      </div>
      {active ? (
        <VpwBadge className="shrink-0" tone="success">
          Active
        </VpwBadge>
      ) : (
        <Button
          className="shrink-0 cursor-pointer"
          disabled={disabled}
          onClick={onActivate}
          size="sm"
          type="button"
        >
          Activate
        </Button>
      )}
    </div>
  )
}

function ProjectDrawerReadiness({
  openFindingCount,
  readiness,
  tone,
}: {
  openFindingCount: number | null
  readiness: number
  tone: "critical" | "info"
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="mb-1 flex items-baseline justify-between">
        <span className="font-semibold text-sm text-[var(--vpw-text-primary)]">
          Project readiness
        </span>
        <span className="text-xs text-[var(--vpw-text-muted)]">
          {openFindingCount === null
            ? "Summary data is still loading for this project."
            : `${openFindingCount} finding${
                openFindingCount === 1 ? "" : "s"
              } currently drive project follow-up.`}
        </span>
      </div>
      <VpwProgress label="Readiness score" tone={tone} value={readiness} />
    </div>
  )
}

function ProjectDrawerEditCard(
  props: Pick<
    ProjectsWorkbenchProps,
    | "editProjectForm"
    | "onCancelEditProject"
    | "onEditProjectDescriptionChange"
    | "onEditProjectNameChange"
    | "onSaveProject"
    | "projectActionLoading"
  >,
) {
  return (
    <div className="project-drawer-card flex flex-col gap-4 rounded-xl border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-5">
      <div className="flex flex-col gap-1">
        <h3 className="font-bold text-sm text-[var(--vpw-text-primary)]">
          Edit Workspace Metadata
        </h3>
        <p className="text-xs text-[var(--vpw-text-secondary)]">
          Update the project name and description context.
        </p>
      </div>
      <ActiveProjectEditForm {...props} />
    </div>
  )
}

function ProjectDrawerDangerCard(
  props: Pick<
    ProjectsWorkbenchProps,
    | "deleteConfirmed"
    | "onDeleteConfirmedChange"
    | "onDeleteProject"
    | "projectActionLoading"
  > & {
    selectedProject: NonNullable<ProjectsWorkbenchProps["selectedProject"]>
  },
) {
  return (
    <div className="project-drawer-card project-drawer-danger-zone flex flex-col gap-4 rounded-xl border border-[var(--vpw-border-default)] p-5">
      <div className="flex flex-col gap-1">
        <h3 className="font-bold text-sm text-[var(--vpw-red)]">
          Danger Zone
        </h3>
        <p className="text-xs text-[var(--vpw-text-secondary)]">
          Permanently delete this workspace and all associated findings.
        </p>
      </div>
      <ActiveProjectDeletePanel {...props} />
    </div>
  )
}
