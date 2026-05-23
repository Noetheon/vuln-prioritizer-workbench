import { useMutation } from "@tanstack/react-query"
import { type FormEvent, useState } from "react"
import {
  ProjectsService,
  type ProjectPublic,
  type ProjectUpdate,
} from "../../api-client"
import { ProjectsWorkbench } from "../../components/projects/ProjectsWorkbench"
import { apiErrorMessage } from "../../lib/app-errors"
import { emptyProjectForm, type ProjectFormState } from "../../lib/app-defaults"
import { useWorkbenchContext } from "../WorkbenchContext"
import {
  projectRequestBody,
  validateProjectForm,
} from "../route-utils"
import {
  useProjectSummariesQuery,
  useProjectSummaryQuery,
} from "../useWorkbenchQueries"

function ProjectsRouteContainer() {
  const {
    projectListLoading,
    projects,
    refreshProjects,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const projectSummariesQuery = useProjectSummariesQuery(projects)
  const projectSummaryQuery = useProjectSummaryQuery(selectedProjectId)
  const projectSummaryById = projectSummariesQuery.data?.summaries ?? {}
  const failedProjectSummaryCount =
    projectSummariesQuery.data?.failedProjectIds.length ?? 0
  const [createProjectForm, setCreateProjectForm] =
    useState<ProjectFormState>(emptyProjectForm)
  const [createProjectDrawerOpen, setCreateProjectDrawerOpen] = useState(false)
  const [createProjectError, setCreateProjectError] = useState("")
  const [projectActionError, setProjectActionError] = useState("")
  const [projectActionMessage, setProjectActionMessage] = useState("")
  const [editProjectId, setEditProjectId] = useState("")
  const [editProjectForm, setEditProjectForm] =
    useState<ProjectFormState>(emptyProjectForm)
  const [deleteConfirmed, setDeleteConfirmed] = useState(false)

  const createProjectMutation = useMutation({
    mutationFn: (projectCreate: ReturnType<typeof projectRequestBody>) =>
      ProjectsService.createProject({ projectCreate }),
  })
  const updateProjectMutation = useMutation({
    mutationFn: ({
      projectId,
      projectUpdate,
    }: {
      projectId: string
      projectUpdate: ProjectUpdate
    }) =>
      ProjectsService.updateProject({
        project_id: projectId,
        projectUpdate,
      }),
  })
  const deleteProjectMutation = useMutation({
    mutationFn: (projectId: string) =>
      ProjectsService.deleteProject({ project_id: projectId }),
  })

  async function createProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setCreateProjectError("")
    setProjectActionError("")
    setProjectActionMessage("")
    const validationError = validateProjectForm(createProjectForm)
    if (validationError) {
      setCreateProjectError(validationError)
      return
    }

    try {
      const project = await createProjectMutation.mutateAsync(
        projectRequestBody(createProjectForm),
      )
      setCreateProjectForm(emptyProjectForm)
      setCreateProjectDrawerOpen(false)
      setProjectActionMessage(`Project ${project.name} created.`)
      await refreshProjects(project.id)
    } catch (caught) {
      setProjectActionError(apiErrorMessage("Project create failed", caught))
    }
  }

  function startEditProject(project: ProjectPublic) {
    setEditProjectId(project.id)
    setEditProjectForm({
      description: project.description ?? "",
      name: project.name,
    })
    setDeleteConfirmed(false)
    setProjectActionError("")
    setProjectActionMessage("")
  }

  async function saveProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!editProjectId) {
      return
    }
    setProjectActionError("")
    setProjectActionMessage("")
    const validationError = validateProjectForm(editProjectForm)
    if (validationError) {
      setProjectActionError(validationError)
      return
    }

    try {
      const project = await updateProjectMutation.mutateAsync({
        projectId: editProjectId,
        projectUpdate: projectRequestBody(editProjectForm),
      })
      setEditProjectId("")
      setProjectActionMessage(`Project ${project.name} updated.`)
      await refreshProjects(project.id)
    } catch (caught) {
      setProjectActionError(apiErrorMessage("Project update failed", caught))
    }
  }

  async function deleteProject(project: ProjectPublic) {
    if (!deleteConfirmed) {
      setProjectActionError("Confirm deletion before deleting this project.")
      return
    }

    setProjectActionError("")
    setProjectActionMessage("")
    try {
      await deleteProjectMutation.mutateAsync(project.id)
      setDeleteConfirmed(false)
      setEditProjectId("")
      setProjectActionMessage(`Project ${project.name} deleted.`)
      await refreshProjects()
    } catch (caught) {
      setProjectActionError(apiErrorMessage("Project delete failed", caught))
    }
  }

  const projectActionLoading =
    createProjectMutation.isPending ||
    updateProjectMutation.isPending ||
    deleteProjectMutation.isPending
  const projectSummaryWarning = [
    failedProjectSummaryCount > 0
      ? `${failedProjectSummaryCount} project summary ${
          failedProjectSummaryCount === 1 ? "could" : "summaries could"
        } not be loaded. Project counts may be incomplete.`
      : "",
    projectSummaryQuery.isError
      ? apiErrorMessage("Selected project summary unavailable", projectSummaryQuery.error)
      : "",
  ]
    .filter(Boolean)
    .join(" ")

  function setCreateProjectDrawer(open: boolean) {
    setCreateProjectDrawerOpen(open)
    setCreateProjectError("")
    if (open) {
      setProjectActionError("")
    }
  }

  return (
    <ProjectsWorkbench
      createProjectDrawerOpen={createProjectDrawerOpen}
      createProjectError={createProjectError}
      createProjectForm={createProjectForm}
      deleteConfirmed={deleteConfirmed}
      editProjectForm={editProjectForm}
      editProjectId={editProjectId}
      onCancelEditProject={() => setEditProjectId("")}
      onCreateProjectDrawerOpenChange={setCreateProjectDrawer}
      onCreateProject={createProject}
      onCreateProjectDescriptionChange={(description) =>
        setCreateProjectForm((form) => ({
          ...form,
          description,
        }))
      }
      onCreateProjectNameChange={(name) =>
        setCreateProjectForm((form) => ({
          ...form,
          name,
        }))
      }
      onDeleteConfirmedChange={setDeleteConfirmed}
      onDeleteProject={(project) => void deleteProject(project)}
      onEditProjectDescriptionChange={(description) =>
        setEditProjectForm((form) => ({
          ...form,
          description,
        }))
      }
      onEditProjectNameChange={(name) =>
        setEditProjectForm((form) => ({
          ...form,
          name,
        }))
      }
      onRefreshProjects={() => void refreshProjects(selectedProjectId)}
      onSaveProject={saveProject}
      onSelectProject={(projectId) => {
        setSelectedProjectId(projectId)
        setDeleteConfirmed(false)
        setEditProjectId("")
      }}
      onStartEditProject={startEditProject}
      projectActionError={projectActionError}
      projectActionLoading={projectActionLoading}
      projectActionMessage={projectActionMessage}
      projectListLoading={
        projectListLoading ||
        projectSummaryQuery.isLoading ||
        projectSummariesQuery.isLoading
      }
      projectSummary={projectSummaryQuery.data ?? null}
      projectSummaryById={projectSummaryById}
      projectSummaryWarning={projectSummaryWarning}
      projects={projects}
      selectedProject={selectedProject}
      selectedProjectId={selectedProjectId}
    />
  )
}

export function ProjectsRoute() {
  return <ProjectsRouteContainer />
}
