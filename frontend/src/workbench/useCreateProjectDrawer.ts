import { useMutation } from "@tanstack/react-query"
import { type FormEvent, useState } from "react"
import { type ProjectPublic, ProjectsService } from "../api-client"
import { apiErrorMessage } from "../lib/app-errors"
import { emptyProjectForm, type ProjectFormState } from "../lib/app-defaults"
import { projectRequestBody, validateProjectForm } from "./route-utils"

type UseCreateProjectDrawerOptions = {
  onCreated: (project: ProjectPublic) => Promise<void> | void
  // Where API failures go; without it they show inside the drawer.
  onError?: (message: string) => void
}

/** Form state, submit, and open state for the shared "Create project" drawer. */
export function useCreateProjectDrawer({
  onCreated,
  onError,
}: UseCreateProjectDrawerOptions) {
  const [form, setForm] = useState<ProjectFormState>(emptyProjectForm)
  const [open, setOpen] = useState(false)
  const [error, setError] = useState("")
  const mutation = useMutation({
    mutationFn: (projectCreate: ReturnType<typeof projectRequestBody>) =>
      ProjectsService.createProject({ projectCreate }),
  })

  function onOpenChange(next: boolean) {
    setOpen(next)
    setError("")
  }

  async function onCreateProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError("")
    const validationError = validateProjectForm(form)
    if (validationError) {
      setError(validationError)
      return
    }
    try {
      const project = await mutation.mutateAsync(projectRequestBody(form))
      setForm(emptyProjectForm)
      setOpen(false)
      await onCreated(project)
    } catch (caught) {
      const message = apiErrorMessage("Project create failed", caught)
      if (onError) {
        onError(message)
      } else {
        setError(message)
      }
    }
  }

  return {
    drawerProps: {
      createProjectDrawerOpen: open,
      createProjectError: error,
      createProjectForm: form,
      onCreateProject,
      onCreateProjectDescriptionChange: (description: string) =>
        setForm((current) => ({ ...current, description })),
      onCreateProjectDrawerOpenChange: onOpenChange,
      onCreateProjectNameChange: (name: string) =>
        setForm((current) => ({ ...current, name })),
      projectActionLoading: mutation.isPending,
    },
    openDrawer: () => onOpenChange(true),
    pending: mutation.isPending,
  }
}
