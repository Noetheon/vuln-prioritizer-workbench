import { useNavigate } from "@tanstack/react-router"
import { useQueryClient } from "@tanstack/react-query"
import {
  type Dispatch,
  type ReactNode,
  type SetStateAction,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react"
import {
  ApiError,
  type ProjectPublic,
  type ProviderStatusPublic,
  type UserPublic,
  type WorkbenchStatus,
} from "../api-client"
import { clearAccessToken } from "../auth"
import { apiErrorMessage } from "../lib/app-errors"
import {
  useWorkbenchBootstrapQuery,
  workbenchBootstrapQueryKey,
} from "./useWorkbenchBootstrapQuery"
import { useProjectsQuery } from "./useWorkbenchQueries"
import { workbenchQueryKeys } from "./workbench-query-keys"

const SELECTED_PROJECT_STORAGE_KEY = "vpw.selectedProjectId"

type SelectedProjectIdUpdate = string | ((previousProjectId: string) => string)

function readStoredSelectedProjectId() {
  if (typeof window === "undefined") {
    return ""
  }
  try {
    return window.localStorage.getItem(SELECTED_PROJECT_STORAGE_KEY) ?? ""
  } catch {
    return ""
  }
}

function persistSelectedProjectId(projectId: string) {
  if (typeof window === "undefined") {
    return
  }
  try {
    if (projectId) {
      window.localStorage.setItem(SELECTED_PROJECT_STORAGE_KEY, projectId)
    } else {
      window.localStorage.removeItem(SELECTED_PROJECT_STORAGE_KEY)
    }
  } catch {
    // Storage can be blocked in private or embedded browser contexts.
  }
}

export type WorkbenchContextValue = {
  currentUser: UserPublic | null
  handleAuthExpired: () => Promise<void>
  projectListLoading: boolean
  projects: ProjectPublic[]
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  providerStatusLoading: boolean
  refreshProjects: (preferredProjectId?: string) => Promise<void>
  refreshProviderStatus: () => Promise<void>
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  setSelectedProjectId: Dispatch<SetStateAction<string>>
  status: WorkbenchStatus | null
  statusError: string
}

const WorkbenchContext = createContext<WorkbenchContextValue | null>(null)

export function WorkbenchProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const handleAuthExpired = useCallback(async () => {
    clearAccessToken()
    await navigate({ to: "/login" })
  }, [navigate])
  const bootstrapQuery = useWorkbenchBootstrapQuery()
  const bootstrapError = bootstrapQuery.error
  const projectsQuery = useProjectsQuery()
  const projects = projectsQuery.data?.data ?? []
  const [selectedProjectId, setSelectedProjectIdState] = useState(
    readStoredSelectedProjectId,
  )

  const setSelectedProjectId = useCallback(
    (update: SetStateAction<string>) => {
      if (typeof update === "function") {
        setSelectedProjectIdState((previousProjectId) => {
          const nextProjectId = update(previousProjectId)
          persistSelectedProjectId(nextProjectId)
          return nextProjectId
        })
        return
      }
      persistSelectedProjectId(update)
      setSelectedProjectIdState(update)
    },
    [],
  )

  useEffect(() => {
    if (
      bootstrapError instanceof ApiError &&
      [401, 403].includes(bootstrapError.status)
    ) {
      void handleAuthExpired()
    }
  }, [bootstrapError, handleAuthExpired])

  useEffect(() => {
    setSelectedProjectId((previousProjectId) =>
      projects.some((project) => project.id === previousProjectId)
        ? previousProjectId
        : (projects[0]?.id ?? ""),
    )
  }, [projects, setSelectedProjectId])

  const refreshProjects = useCallback(
    async (preferredProjectId?: string) => {
      if (preferredProjectId) {
        setSelectedProjectId(preferredProjectId)
      }
      await queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.projects(),
      })
      await queryClient.invalidateQueries({
        queryKey: ["workbench", "project-summaries"],
      })
      await queryClient.invalidateQueries({
        queryKey: ["workbench", "project-summary"],
      })
    },
    [queryClient, setSelectedProjectId],
  )

  const refreshProviderStatus = useCallback(async () => {
    await queryClient.invalidateQueries({
      queryKey: workbenchBootstrapQueryKey,
    })
  }, [queryClient])

  const value = useMemo<WorkbenchContextValue>(
    () => ({
      currentUser: bootstrapQuery.data?.currentUser ?? null,
      handleAuthExpired,
      projectListLoading: projectsQuery.isLoading || projectsQuery.isFetching,
      projects,
      providerStatus: bootstrapQuery.data?.providerStatus ?? null,
      providerStatusError: bootstrapQuery.isError
        ? apiErrorMessage("Provider status unavailable", bootstrapError)
        : "",
      providerStatusLoading:
        bootstrapQuery.isLoading || bootstrapQuery.isFetching,
      refreshProjects,
      refreshProviderStatus,
      selectedProject:
        projects.find((project) => project.id === selectedProjectId) ?? null,
      selectedProjectId,
      setSelectedProjectId,
      status: bootstrapQuery.data?.status ?? null,
      statusError: bootstrapQuery.isError ? "Data services unavailable" : "",
    }),
    [
      bootstrapError,
      bootstrapQuery.data?.currentUser,
      bootstrapQuery.data?.providerStatus,
      bootstrapQuery.data?.status,
      bootstrapQuery.isError,
      bootstrapQuery.isFetching,
      bootstrapQuery.isLoading,
      handleAuthExpired,
      projects,
      projectsQuery.isFetching,
      projectsQuery.isLoading,
      refreshProjects,
      refreshProviderStatus,
      selectedProjectId,
      setSelectedProjectId,
    ],
  )

  return (
    <WorkbenchContext.Provider value={value}>
      {children}
    </WorkbenchContext.Provider>
  )
}

export function useWorkbenchContext() {
  const value = useContext(WorkbenchContext)
  if (value === null) {
    throw new Error("useWorkbenchContext must be used within WorkbenchProvider")
  }
  return value
}

export type { SelectedProjectIdUpdate }
