import "@/styles/projects.css"

import { VpwPageContainer, VpwStatusBanner } from "@/components/vpw"
import {
  CreateProjectDrawer,
  ProjectDetailDrawer,
  ProjectDirectory,
  ProjectContext,
} from "./ProjectsWorkbenchSections"
import type { ProjectsWorkbenchProps } from "./projects-workbench-model"

export type {
  ProjectFormStateLike,
  ProjectsWorkbenchProps,
} from "./projects-workbench-model"

export function ProjectsWorkbench(props: ProjectsWorkbenchProps) {
  return (
    <VpwPageContainer className="projects-workbench vpw-page-stack px-0 py-0">
      <ProjectContext
        onCreateProjectDrawerOpenChange={
          props.onCreateProjectDrawerOpenChange
        }
        onRefreshProjects={props.onRefreshProjects}
        projectListLoading={props.projectListLoading}
        projectSummary={props.projectSummary}
        projectSummaryById={props.projectSummaryById}
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

      <ProjectDirectory
        onCreateProjectDrawerOpenChange={
          props.onCreateProjectDrawerOpenChange
        }
        onSelectProject={props.onSelectProject}
        projectListLoading={props.projectListLoading}
        projectSummaryById={props.projectSummaryById}
        projects={props.projects}
        selectedProjectId={props.selectedProjectId}
        onStartEditProject={props.onStartEditProject}
      />

      <CreateProjectDrawer
        createProjectDrawerOpen={props.createProjectDrawerOpen}
        createProjectError={props.createProjectError}
        createProjectForm={props.createProjectForm}
        onCreateProject={props.onCreateProject}
        onCreateProjectDescriptionChange={
          props.onCreateProjectDescriptionChange
        }
        onCreateProjectDrawerOpenChange={
          props.onCreateProjectDrawerOpenChange
        }
        onCreateProjectNameChange={props.onCreateProjectNameChange}
        projectActionLoading={props.projectActionLoading}
      />
      <ProjectDetailDrawer
        deleteConfirmed={props.deleteConfirmed}
        editProjectForm={props.editProjectForm}
        editProjectId={props.editProjectId}
        onCancelEditProject={props.onCancelEditProject}
        onDeleteConfirmedChange={props.onDeleteConfirmedChange}
        onDeleteProject={props.onDeleteProject}
        onEditProjectDescriptionChange={props.onEditProjectDescriptionChange}
        onEditProjectNameChange={props.onEditProjectNameChange}
        onSaveProject={props.onSaveProject}
        onSelectProject={props.onSelectProject}
        projectActionLoading={props.projectActionLoading}
        projectListLoading={props.projectListLoading}
        projectSummaryById={props.projectSummaryById}
        projects={props.projects}
        selectedProjectId={props.selectedProjectId}
      />
    </VpwPageContainer>
  )
}
