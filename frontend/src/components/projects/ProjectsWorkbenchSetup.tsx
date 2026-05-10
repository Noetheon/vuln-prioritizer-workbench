import { FolderKanban, Plus, ShieldCheck, Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import {
  VpwBadge,
  VpwField,
  VpwGrid,
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
    <VpwPanel className="flex flex-col gap-5">
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
      <VpwGrid columns={2}>
        <CreateProjectPanel {...props} />
        <ProjectWorkflowGuide />
      </VpwGrid>
    </VpwSection>
  )
}
