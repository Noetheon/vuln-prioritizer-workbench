import { Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import {
  VpwField,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import type { ProjectsWorkbenchProps } from "./projects-workbench-model"

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
      <VpwPanel className="flex flex-col gap-5">
        <VpwSectionHeader
          eyebrow="Workspace setup"
          title="Create Project"
          description="Create a bounded workspace before importing scanner, SBOM, or CVE-list data."
        />
        <form className="flex flex-col gap-4" onSubmit={onCreateProject}>
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
          <Button
            aria-busy={projectActionLoading}
            disabled={projectActionLoading}
            type="submit"
          >
            <Plus aria-hidden="true" />
            {projectActionLoading ? "Creating project" : "Create project"}
          </Button>
        </form>
      </VpwPanel>
    </div>
  )
}

export function ProjectSetupSection(
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
      <CreateProjectPanel {...props} />
    </VpwSection>
  )
}
