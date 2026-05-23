import { FolderKanban } from "lucide-react"
import {
  VpwBadge,
  VpwEmptyState,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSectionHeader,
} from "@/components/vpw"
import type { ProjectUrlSearch } from "@/workbench/selected-project-search"
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
import { ActiveProjectWorkflowLinks } from "./ProjectsWorkbenchActiveWorkflow"

type ActiveProjectWorkflowProps = {
  projectSearch: ProjectUrlSearch
}

type ActiveProjectPanelProps = Pick<
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
> &
  ActiveProjectWorkflowProps

export function ActiveProjectPanel({
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
  projectSearch,
  projectSummary,
  selectedProject,
}: ActiveProjectPanelProps) {
  if (!selectedProject) {
    return (
      <VpwPanel className="projects-active-panel">
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
  const openFindingCount =
    projectSummary?.open_finding_count ?? projectSummary?.finding_count ?? null

  return (
    <VpwPanel className="projects-active-panel">
      <div className="projects-active-panel__header">
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

      <div className="projects-active-panel__readiness">
        <div className="projects-active-panel__readiness-copy">
          <p className="vpw-label">Project readiness</p>
          <p>
            {openFindingCount === null
              ? "Summary data is still loading for this project."
              : `${openFindingCount} finding${
                  openFindingCount === 1 ? "" : "s"
                } currently drive project follow-up.`}
          </p>
        </div>
        <VpwProgress
          label="Project readiness"
          tone={evidence.tone === "critical" ? "critical" : "info"}
          value={readiness}
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

      <ActiveProjectWorkflowLinks projectSearch={projectSearch} />

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
