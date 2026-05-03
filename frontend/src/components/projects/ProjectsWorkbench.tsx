import { Link } from "@tanstack/react-router"
import {
  Archive,
  CheckCircle2,
  Clock3,
  FolderKanban,
  Gauge,
  GitBranch,
  PlayCircle,
  Plus,
  ShieldCheck,
  Upload,
} from "lucide-react"
import type { FormEventHandler } from "react"
import type {
  ProjectDecisionSummaryPublic,
  ProjectPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwField,
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPageContainer,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { runStatusLabel, runStatusTone } from "@/lib/risk-format"

export type ProjectFormStateLike = {
  description: string
  name: string
}

export type ProjectsWorkbenchProps = {
  createProjectError: string
  createProjectForm: ProjectFormStateLike
  deleteConfirmed: boolean
  editProjectForm: ProjectFormStateLike
  editProjectId: string
  onCancelEditProject: () => void
  onCreateProject: FormEventHandler<HTMLFormElement>
  onCreateProjectDescriptionChange: (value: string) => void
  onCreateProjectNameChange: (value: string) => void
  onDeleteConfirmedChange: (checked: boolean) => void
  onDeleteProject: (project: ProjectPublic) => void
  onEditProjectDescriptionChange: (value: string) => void
  onEditProjectNameChange: (value: string) => void
  onRefreshProjects: () => void
  onSaveProject: FormEventHandler<HTMLFormElement>
  onSelectProject: (projectId: string) => void
  onStartEditProject: (project: ProjectPublic) => void
  projectActionError: string
  projectActionLoading: boolean
  projectActionMessage: string
  projectListLoading: boolean
  projectSummary: ProjectDecisionSummaryPublic | null
  projectSummaryById: Record<string, ProjectDecisionSummaryPublic>
  projects: ProjectPublic[]
  selectedProject: ProjectPublic | null
  selectedProjectId: string
}

function formatDateTime(value: string | null | undefined) {
  if (!value) return "Not recorded"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return "Not recorded"
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

function shortId(value: string | null | undefined) {
  return value ? value.slice(0, 8) : "Not recorded"
}

function runTone(
  status: ProjectDecisionSummaryPublic["latest_run_status"] | undefined,
): VpwBadgeTone {
  const tone = runStatusTone(status ?? undefined)
  if (tone === "succeeded") return "success"
  if (tone === "failed") return "critical"
  if (tone === "warning") return "warning"
  return "neutral"
}

function latestRunLabel(summary: ProjectDecisionSummaryPublic | null) {
  if (!summary?.latest_run_id) return "No runs yet"
  return `Run ${shortId(summary.latest_run_id)}`
}

function latestRunStatus(summary: ProjectDecisionSummaryPublic | null) {
  return summary?.latest_run_status
    ? runStatusLabel(summary.latest_run_status)
    : "No runs yet"
}

function openFindings(summary: ProjectDecisionSummaryPublic | null) {
  return summary?.open_finding_count ?? summary?.finding_count ?? null
}

function totalOpenFindings(
  projects: ProjectPublic[],
  summaryById: Record<string, ProjectDecisionSummaryPublic>,
) {
  let total = 0
  let hasKnownValue = false

  for (const project of projects) {
    const count = openFindings(summaryById[project.id] ?? null)
    if (typeof count === "number") {
      total += count
      hasKnownValue = true
    }
  }

  return hasKnownValue ? total : null
}

function evidenceState(summary: ProjectDecisionSummaryPublic | null) {
  if (!summary) {
    return {
      detail: "Project summary unavailable",
      label: "Checking",
      tone: "neutral" as VpwBadgeTone,
    }
  }
  if (summary.provider_degraded) {
    return {
      detail: "Provider data quality needs review",
      label: "Needs attention",
      tone: "warning" as VpwBadgeTone,
    }
  }
  if (summary.latest_run_id) {
    return {
      detail: "Evidence can be generated from current findings",
      label: "Ready",
      tone: "success" as VpwBadgeTone,
    }
  }
  return {
    detail: "Import findings before generating evidence",
    label: "Not generated yet",
    tone: "info" as VpwBadgeTone,
  }
}

function readinessProgress(
  selectedProject: ProjectPublic | null,
  summary: ProjectDecisionSummaryPublic | null,
) {
  if (!selectedProject) return 0
  let value = 25
  if (summary?.latest_run_id) value += 30
  if ((summary?.finding_count ?? 0) > 0) value += 25
  if (!summary?.provider_degraded) value += 20
  return Math.min(value, 100)
}

function ProjectHero({
  projectSummary,
  projects,
  selectedProject,
}: Pick<
  ProjectsWorkbenchProps,
  "projectSummary" | "projects" | "selectedProject"
>) {
  const evidence = evidenceState(projectSummary)

  return (
    <VpwSection>
      <VpwSectionHeader
        eyebrow="Projects"
        title="Projects"
        description="Manage workbench projects, imported findings, runs, and evidence readiness."
      />
      <VpwToolbar label="Project actions">
        <VpwToolbarGroup>
          <Button asChild>
            <a href="#create-project">
              <Plus aria-hidden="true" />
              Create project
            </a>
          </Button>
          <Button asChild variant="outline">
            <Link to="/imports">
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
    </VpwSection>
  )
}

function ProjectMetrics({
  projectSummary,
  projectSummaryById,
  projects,
  selectedProject,
}: Pick<
  ProjectsWorkbenchProps,
  "projectSummary" | "projectSummaryById" | "projects" | "selectedProject"
>) {
  const evidence = evidenceState(projectSummary)
  const totalOpen = totalOpenFindings(projects, projectSummaryById)

  return (
    <VpwSection>
      <VpwGrid columns={4} className="xl:grid-cols-5">
        <VpwMetricCard
          description="Workbench projects"
          icon={<FolderKanban aria-hidden="true" className="h-5 w-5" />}
          label="Total projects"
          tone="info"
          value={projects.length}
        />
        <VpwMetricCard
          description={selectedProject?.name ?? "Create or select a project"}
          icon={<CheckCircle2 aria-hidden="true" className="h-5 w-5" />}
          label="Active project"
          tone={selectedProject ? "success" : "warning"}
          value={selectedProject ? "Selected" : "Required"}
        />
        <VpwMetricCard
          description={latestRunLabel(projectSummary)}
          icon={<Clock3 aria-hidden="true" className="h-5 w-5" />}
          label="Latest import run"
          tone={runTone(projectSummary?.latest_run_status)}
          value={latestRunStatus(projectSummary)}
        />
        <VpwMetricCard
          description="Open or total findings"
          icon={<Gauge aria-hidden="true" className="h-5 w-5" />}
          label="Open findings"
          tone={typeof totalOpen === "number" && totalOpen > 0 ? "warning" : "neutral"}
          value={totalOpen ?? "No data"}
        />
        <VpwMetricCard
          description={evidence.detail}
          icon={<ShieldCheck aria-hidden="true" className="h-5 w-5" />}
          label="Evidence readiness"
          tone={evidence.tone === "neutral" ? "info" : evidence.tone}
          value={evidence.label}
        />
      </VpwGrid>
    </VpwSection>
  )
}

function CreateProjectPanel({
  createProjectError,
  createProjectForm,
  onCreateProject,
  onCreateProjectDescriptionChange,
  onCreateProjectNameChange,
  projectActionLoading,
}: Pick<
  ProjectsWorkbenchProps,
  | "createProjectError"
  | "createProjectForm"
  | "onCreateProject"
  | "onCreateProjectDescriptionChange"
  | "onCreateProjectNameChange"
  | "projectActionLoading"
>) {
  return (
    <div id="create-project">
      <VpwPanel className="space-y-5">
        <VpwSectionHeader
          eyebrow="Workspace setup"
          title="Create Project"
          description="Create a bounded workspace before importing scanner, SBOM, or CVE-list data."
        />
        <form className="space-y-4" onSubmit={onCreateProject}>
          <VpwField
            description="Use a team, application, service, or assessment name."
            error={createProjectError}
            htmlFor="create-project-name"
            label="Project name"
            required
          >
            <Input
              id="create-project-name"
              maxLength={255}
              onChange={(event) =>
                onCreateProjectNameChange(event.target.value)
              }
              value={createProjectForm.name}
            />
          </VpwField>
          <VpwField
            description="Optional context shown in project lists and evidence workflows."
            htmlFor="create-project-desc"
            label="Description"
          >
            <Textarea
              id="create-project-desc"
              maxLength={4096}
              onChange={(event) =>
                onCreateProjectDescriptionChange(event.target.value)
              }
              rows={4}
              value={createProjectForm.description}
            />
          </VpwField>
          <Button disabled={projectActionLoading} type="submit">
            <Plus aria-hidden="true" />
            {projectActionLoading ? "Creating project" : "Create project"}
          </Button>
        </form>
      </VpwPanel>
    </div>
  )
}

function ProjectWorkflowGuide() {
  const steps = [
    {
      body: "Name the workspace that owns the vulnerability intake.",
      icon: <FolderKanban aria-hidden="true" className="h-5 w-5" />,
      meta: "Step 1",
      title: "Create project",
    },
    {
      body: "Upload scanner, SBOM, or CVE-list data into that project.",
      icon: <Upload aria-hidden="true" className="h-5 w-5" />,
      meta: "Step 2",
      title: "Import data",
    },
    {
      body: "Review prioritized findings and generate decision evidence.",
      icon: <ShieldCheck aria-hidden="true" className="h-5 w-5" />,
      meta: "Step 3",
      title: "Generate evidence",
    },
  ]

  return (
    <VpwPanel className="space-y-5">
      <VpwSectionHeader
        eyebrow="Workflow"
        title="Next best path"
        description="Projects keep imports, findings, and evidence grouped for review."
      />
      <div className="grid gap-3">
        {steps.map((step) => (
          <div
            className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-4"
            key={step.title}
          >
            <div className="flex items-start gap-3">
              <div className="rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-info)] p-2 text-[var(--vpw-blue)]">
                {step.icon}
              </div>
              <div>
                <VpwBadge tone="info">{step.meta}</VpwBadge>
                <h3 className="mt-2 font-semibold text-[var(--vpw-text-primary)]">
                  {step.title}
                </h3>
                <p className="mt-1 text-sm leading-5 text-[var(--vpw-text-secondary)]">
                  {step.body}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </VpwPanel>
  )
}

function ProjectSetupSection(
  props: Pick<
    ProjectsWorkbenchProps,
    | "createProjectError"
    | "createProjectForm"
    | "onCreateProject"
    | "onCreateProjectDescriptionChange"
    | "onCreateProjectNameChange"
    | "projectActionLoading"
  >,
) {
  return (
    <VpwSection>
      <VpwGrid columns={2}>
        <CreateProjectPanel {...props} />
        <ProjectWorkflowGuide />
      </VpwGrid>
    </VpwSection>
  )
}

function ProjectDirectory({
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

function ActiveProjectPanel({
  deleteConfirmed,
  editProjectForm,
  editProjectId,
  onCancelEditProject,
  onDeleteConfirmedChange,
  onDeleteProject,
  onEditProjectDescriptionChange,
  onEditProjectNameChange,
  onSaveProject,
  onStartEditProject,
  projectActionLoading,
  projectSummary,
  selectedProject,
}: Pick<
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
  | "onStartEditProject"
  | "projectActionLoading"
  | "projectSummary"
  | "selectedProject"
>) {
  if (!selectedProject) {
    return (
      <VpwPanel>
        <VpwEmptyState
          icon={<FolderKanban aria-hidden="true" className="h-5 w-5" />}
          title="No active project selected"
          description="Select a project from the directory or create a new one before importing findings."
        />
      </VpwPanel>
    )
  }

  const evidence = evidenceState(projectSummary)
  const readiness = readinessProgress(selectedProject, projectSummary)

  return (
    <VpwPanel className="space-y-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <VpwSectionHeader
          eyebrow="Active workspace"
          title={selectedProject.name}
          description={selectedProject.description || "No description recorded."}
        />
        <VpwToolbarGroup>
          <Button
            onClick={() => onStartEditProject(selectedProject)}
            type="button"
            variant="outline"
          >
            Edit
          </Button>
          <Button asChild variant="outline">
            <Link to="/imports">
              <Upload aria-hidden="true" />
              Import findings
            </Link>
          </Button>
          <Button asChild>
            <Link to="/reports">
              <PlayCircle aria-hidden="true" />
              Generate evidence
            </Link>
          </Button>
        </VpwToolbarGroup>
      </div>

      <VpwKeyValueList
        columns={2}
        items={[
          {
            label: "Project id",
            value: shortId(selectedProject.id),
          },
          {
            label: "Created",
            value: formatDateTime(selectedProject.created_at),
          },
          {
            label: "Updated",
            value: formatDateTime(selectedProject.updated_at),
          },
          {
            label: "Evidence",
            tone: evidence.tone,
            value: evidence.label,
          },
        ]}
      />

      <VpwProgress
        label="Project readiness"
        tone={evidence.tone === "critical" ? "critical" : "info"}
        value={readiness}
      />

      {editProjectId === selectedProject.id ? (
        <form className="space-y-4" onSubmit={onSaveProject}>
          <VpwField htmlFor="edit-project-name" label="Edit project name" required>
            <Input
              id="edit-project-name"
              maxLength={255}
              onChange={(event) => onEditProjectNameChange(event.target.value)}
              value={editProjectForm.name}
            />
          </VpwField>
          <VpwField htmlFor="edit-project-desc" label="Edit description">
            <Textarea
              id="edit-project-desc"
              maxLength={4096}
              onChange={(event) =>
                onEditProjectDescriptionChange(event.target.value)
              }
              rows={3}
              value={editProjectForm.description}
            />
          </VpwField>
          <VpwToolbarGroup>
            <Button disabled={projectActionLoading} type="submit">
              Save project
            </Button>
            <Button
              onClick={onCancelEditProject}
              type="button"
              variant="outline"
            >
              Cancel
            </Button>
          </VpwToolbarGroup>
        </form>
      ) : null}

      <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <label className="flex items-start gap-3 text-sm text-[var(--vpw-text-secondary)]">
            <input
              checked={deleteConfirmed}
              className="mt-1"
              onChange={(event) =>
                onDeleteConfirmedChange(event.target.checked)
              }
              type="checkbox"
            />
            <span>
              Confirm deletion for this project. Delete is available because the
              existing route already supports it.
            </span>
          </label>
          <Button
            disabled={projectActionLoading || !deleteConfirmed}
            onClick={() => onDeleteProject(selectedProject)}
            type="button"
            variant="destructive"
          >
            <Archive aria-hidden="true" />
            Delete project
          </Button>
        </div>
      </div>
    </VpwPanel>
  )
}

function ProjectSelectionStrip({
  onSelectProject,
  projectSummaryById,
  projects,
  selectedProjectId,
}: Pick<
  ProjectsWorkbenchProps,
  "onSelectProject" | "projectSummaryById" | "projects" | "selectedProjectId"
>) {
  if (projects.length === 0) return null

  return (
    <VpwSection>
      <VpwSectionHeader
        eyebrow="Active project"
        title="Select Workspace"
        description="Choose which project owns imports, finding review, and evidence generation."
      />
      <VpwGrid columns={4}>
        {projects.slice(0, 4).map((project) => {
          const summary = projectSummaryById[project.id] ?? null
          const evidence = evidenceState(summary)
          return (
            <VpwSelectionCard
              checked={project.id === selectedProjectId}
              key={project.id}
              meta={
                <span className="flex flex-wrap items-center gap-2">
                  <VpwBadge tone={evidence.tone}>{evidence.label}</VpwBadge>
                  <span>{openFindings(summary) ?? "No"} findings</span>
                </span>
              }
              onClick={() => onSelectProject(project.id)}
              title={project.name}
            >
              {project.description || latestRunLabel(summary)}
            </VpwSelectionCard>
          )
        })}
      </VpwGrid>
    </VpwSection>
  )
}

export function ProjectsWorkbench(props: ProjectsWorkbenchProps) {
  return (
    <VpwPageContainer className="space-y-8 px-0 py-0">
      <ProjectHero
        projectSummary={props.projectSummary}
        projects={props.projects}
        selectedProject={props.selectedProject}
      />

      {props.projectActionError ? (
        <VpwStatusBanner title="Project action failed" tone="critical">
          {props.projectActionError}
        </VpwStatusBanner>
      ) : null}
      {props.projectActionMessage ? (
        <VpwStatusBanner title="Project action complete" tone="success">
          {props.projectActionMessage}
        </VpwStatusBanner>
      ) : null}

      <ProjectMetrics
        projectSummary={props.projectSummary}
        projectSummaryById={props.projectSummaryById}
        projects={props.projects}
        selectedProject={props.selectedProject}
      />
      <ProjectSetupSection
        createProjectError={props.createProjectError}
        createProjectForm={props.createProjectForm}
        onCreateProject={props.onCreateProject}
        onCreateProjectDescriptionChange={
          props.onCreateProjectDescriptionChange
        }
        onCreateProjectNameChange={props.onCreateProjectNameChange}
        projectActionLoading={props.projectActionLoading}
      />
      <ProjectSelectionStrip
        onSelectProject={props.onSelectProject}
        projectSummaryById={props.projectSummaryById}
        projects={props.projects}
        selectedProjectId={props.selectedProjectId}
      />
      <ProjectDirectory
        onRefreshProjects={props.onRefreshProjects}
        onSelectProject={props.onSelectProject}
        projectListLoading={props.projectListLoading}
        projectSummaryById={props.projectSummaryById}
        projects={props.projects}
        selectedProjectId={props.selectedProjectId}
      />
      <VpwSection>
        <VpwSectionHeader
          eyebrow="Project detail"
          title="Active Project"
          description="Inspect and manage the currently selected project."
        />
        <ActiveProjectPanel
          deleteConfirmed={props.deleteConfirmed}
          editProjectForm={props.editProjectForm}
          editProjectId={props.editProjectId}
          onCancelEditProject={props.onCancelEditProject}
          onDeleteConfirmedChange={props.onDeleteConfirmedChange}
          onDeleteProject={props.onDeleteProject}
          onEditProjectDescriptionChange={props.onEditProjectDescriptionChange}
          onEditProjectNameChange={props.onEditProjectNameChange}
          onSaveProject={props.onSaveProject}
          onStartEditProject={props.onStartEditProject}
          projectActionLoading={props.projectActionLoading}
          projectSummary={props.projectSummary}
          selectedProject={props.selectedProject}
        />
      </VpwSection>
    </VpwPageContainer>
  )
}
