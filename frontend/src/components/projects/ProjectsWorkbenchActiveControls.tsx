import { Link } from "@/lib/router"
import { Archive, PlayCircle, Upload } from "lucide-react"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { VpwField, VpwToolbarGroup } from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { ProjectsWorkbenchProps } from "./projects-workbench-model"

export function ActiveProjectActions({
  onStartEditProject,
  selectedProject,
}: Pick<ProjectsWorkbenchProps, "onStartEditProject" | "selectedProject">) {
  if (!selectedProject) return null
  const projectSearch = selectedProjectRouteSearch(selectedProject.id)

  return (
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
  )
}

export function ActiveProjectEditForm({
  editProjectForm,
  onCancelEditProject,
  onEditProjectDescriptionChange,
  onEditProjectNameChange,
  onSaveProject,
  projectActionLoading,
}: Pick<
  ProjectsWorkbenchProps,
  | "editProjectForm"
  | "onCancelEditProject"
  | "onEditProjectDescriptionChange"
  | "onEditProjectNameChange"
  | "onSaveProject"
  | "projectActionLoading"
>) {
  return (
    <form className="flex flex-col gap-4" onSubmit={onSaveProject}>
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
        <Button
          aria-busy={projectActionLoading}
          disabled={projectActionLoading}
          type="submit"
        >
          Save project
        </Button>
        <Button onClick={onCancelEditProject} type="button" variant="outline">
          Cancel
        </Button>
      </VpwToolbarGroup>
    </form>
  )
}

export function ActiveProjectDeletePanel({
  deleteConfirmed,
  onDeleteConfirmedChange,
  onDeleteProject,
  projectActionLoading,
  selectedProject,
}: Pick<
  ProjectsWorkbenchProps,
  | "deleteConfirmed"
  | "onDeleteConfirmedChange"
  | "onDeleteProject"
  | "projectActionLoading"
> & {
  selectedProject: ProjectPublic
}) {
  return (
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
  )
}
