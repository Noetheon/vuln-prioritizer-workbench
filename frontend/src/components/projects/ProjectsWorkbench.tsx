import { VpwStatusBanner } from "@/components/vpw"
import {
  ActiveProjectSection,
  ProjectDirectory,
  ProjectHero,
  ProjectMetrics,
  ProjectSelectionStrip,
  ProjectSetupSection,
} from "./ProjectsWorkbenchSections"
import type { ProjectsWorkbenchProps } from "./projects-workbench-model"

export type {
  ProjectFormStateLike,
  ProjectsWorkbenchProps,
} from "./projects-workbench-model"

export function ProjectsWorkbench(props: ProjectsWorkbenchProps) {
  return (
    <div className="flex flex-col gap-6">
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
      {props.projectSummaryWarning ? (
        <VpwStatusBanner title="Project summary data incomplete" tone="warning">
          {props.projectSummaryWarning}
        </VpwStatusBanner>
      ) : null}

      <ProjectMetrics
        projectSummary={props.projectSummary}
        projectSummaryById={props.projectSummaryById}
        projects={props.projects}
        selectedProject={props.selectedProject}
      />
      <ActiveProjectSection
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
    </div>
  )
}
