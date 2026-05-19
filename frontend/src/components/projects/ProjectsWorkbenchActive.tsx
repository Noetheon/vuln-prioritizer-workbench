import { FolderKanban } from "lucide-react"
import {
  VpwBadge,
  VpwEmptyState,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import {
  evidenceState,
  formatDateTime,
  type ProjectsWorkbenchProps,
  readinessProgress,
  shortId,
} from "./projects-workbench-model"
import {
  ActiveProjectActions,
  ActiveProjectDeletePanel,
  ActiveProjectEditForm,
} from "./ProjectsWorkbenchActiveControls"

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
    <VpwPanel className="flex flex-col gap-5 border-[color-mix(in_srgb,var(--vpw-blue)_24%,var(--vpw-border-subtle))] bg-[var(--vpw-bg-card)]">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <VpwSectionHeader
          actions={<VpwBadge tone={evidence.tone}>{evidence.label}</VpwBadge>}
          eyebrow="Active workspace"
          title={selectedProject.name}
          description={
            selectedProject.description || "No description recorded."
          }
        />
        <ActiveProjectActions
          onStartEditProject={onStartEditProject}
          selectedProject={selectedProject}
        />
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
        <ActiveProjectEditForm
          editProjectForm={editProjectForm}
          onCancelEditProject={onCancelEditProject}
          onEditProjectDescriptionChange={onEditProjectDescriptionChange}
          onEditProjectNameChange={onEditProjectNameChange}
          onSaveProject={onSaveProject}
          projectActionLoading={projectActionLoading}
        />
      ) : null}

      <ActiveProjectDeletePanel
        deleteConfirmed={deleteConfirmed}
        onDeleteConfirmedChange={onDeleteConfirmedChange}
        onDeleteProject={onDeleteProject}
        projectActionLoading={projectActionLoading}
        selectedProject={selectedProject}
      />
    </VpwPanel>
  )
}

export function ActiveProjectSection(
  props: Pick<
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
  >,
) {
  return (
    <VpwSection>
      <VpwSectionHeader
        eyebrow="Project detail"
        title="Active Project"
        description="Inspect and manage the currently selected project."
      />
      <ActiveProjectPanel {...props} />
    </VpwSection>
  )
}
