import { Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { DetailDrawer, VpwField } from "@/components/vpw"
import type { ProjectsWorkbenchProps } from "./projects-workbench-model"

export function CreateProjectDrawer({
  createProjectDrawerOpen,
  createProjectError,
  createProjectForm,
  onCreateProjectDrawerOpenChange,
  onCreateProject,
  onCreateProjectDescriptionChange,
  onCreateProjectNameChange,
  projectActionLoading,
}: Pick<
  ProjectsWorkbenchProps,
  | "createProjectDrawerOpen"
  | "createProjectError"
  | "createProjectForm"
  | "onCreateProjectDrawerOpenChange"
  | "onCreateProject"
  | "onCreateProjectDescriptionChange"
  | "onCreateProjectNameChange"
  | "projectActionLoading"
>) {
  return (
    <DetailDrawer
      className="project-drawer w-[min(100vw,40rem)] sm:max-w-none"
      description="Create a bounded workspace before importing scanner, SBOM, or CVE-list data."
      onOpenChange={onCreateProjectDrawerOpenChange}
      open={createProjectDrawerOpen}
      title="Create project"
    >
      <CreateProjectForm
        createProjectError={createProjectError}
        createProjectForm={createProjectForm}
        onCreateProject={onCreateProject}
        onCreateProjectDescriptionChange={onCreateProjectDescriptionChange}
        onCreateProjectNameChange={onCreateProjectNameChange}
        projectActionLoading={projectActionLoading}
      />
    </DetailDrawer>
  )
}

function CreateProjectForm({
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
    <form className="projects-create-panel__form" onSubmit={onCreateProject}>
      <VpwField
        description="Use an application, service, environment, or assessment name."
        error={createProjectError}
        htmlFor="create-project-name"
        label="Project name"
        required
      >
        <Input
          id="create-project-name"
          maxLength={255}
          onChange={(event) => onCreateProjectNameChange(event.target.value)}
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
      <div className="projects-create-panel__footer">
        <p>
          New projects become the active scope after creation, so imports,
          triage, and evidence actions stay aligned.
        </p>
        <Button
          aria-busy={projectActionLoading}
          className="w-full"
          disabled={projectActionLoading}
          type="submit"
        >
          <Plus aria-hidden="true" />
          {projectActionLoading ? "Creating project" : "Create project"}
        </Button>
      </div>
    </form>
  )
}
