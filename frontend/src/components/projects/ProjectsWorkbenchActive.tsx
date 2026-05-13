import { Link } from "@/lib/router"
import { Archive, FolderKanban, PlayCircle, Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwBadge,
  VpwEmptyState,
  VpwField,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwToolbarGroup,
} from "@/components/vpw"
import {
  evidenceState,
  formatDateTime,
  type ProjectsWorkbenchProps,
  readinessProgress,
  shortId,
} from "./projects-workbench-model"

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
  const projectSearch = selectedProjectRouteSearch(selectedProject.id)

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
        <VpwToolbarGroup>
          <Button
            onClick={() => onStartEditProject(selectedProject)}
            type="button"
            variant="outline"
          >
            Edit
          </Button>
          <Button asChild variant="outline">
            <Link search={projectSearch} to="/imports">
              <Upload aria-hidden="true" />
              Import findings
            </Link>
          </Button>
          <Button asChild>
            <Link search={projectSearch} to="/reports">
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
        <form className="flex flex-col gap-4" onSubmit={onSaveProject}>
          <VpwField
            htmlFor="edit-project-name"
            label="Edit project name"
            required
          >
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
            <Button
              aria-busy={projectActionLoading}
              disabled={projectActionLoading}
              type="submit"
            >
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
          <label
            className="flex items-start gap-3 text-sm text-[var(--vpw-text-secondary)]"
            htmlFor="project-delete-confirmed"
          >
            <Input
              checked={deleteConfirmed}
              className="mt-1 size-4 min-w-4 shrink-0 p-0 accent-[var(--vpw-blue)] shadow-none"
              id="project-delete-confirmed"
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
            aria-busy={projectActionLoading}
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
