import { useLocation, useNavigate } from "@tanstack/react-router"
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
import {
  normalizeSelectedProjectId,
  searchStringFromUrlSearch,
  selectedProjectIdFromSearch,
  selectedProjectUrlSearch,
} from "./selected-project-search"
import { invalidateWorkbenchProjectQueries } from "./workbench-query-keys"

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

function activeSearchString(fallbackSearch: string) {
  return typeof window === "undefined" ? fallbackSearch : window.location.search
}

export function WorkbenchProvider({ children }: { children: ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const handleAuthExpired = useCallback(async () => {
    clearAccessToken()
    await navigate({ replace: true, search: {} as never, to: "/login" })
  }, [navigate])
  const bootstrapQuery = useWorkbenchBootstrapQuery()
  const bootstrapError = bootstrapQuery.error
  const projectsQuery = useProjectsQuery()
  const projects = projectsQuery.data?.data ?? []
  const urlSelectedProjectId = selectedProjectIdFromSearch(location.searchStr)
  const [selectedProjectIdState, setSelectedProjectIdState] = useState(
    () => urlSelectedProjectId || readStoredSelectedProjectId(),
  )
  const projectIds = useMemo(
    () => projects.map((project) => project.id),
    [projects],
  )
  const selectedProjectId = useMemo(
    () =>
      projectsQuery.isSuccess
        ? normalizeSelectedProjectId(
            [urlSelectedProjectId, selectedProjectIdState],
            projectIds,
          )
        : "",
    [
      projectIds,
      projectsQuery.isSuccess,
      selectedProjectIdState,
      urlSelectedProjectId,
    ],
  )

  const selectProjectId = useCallback(
    (nextProjectId: string, { replace }: { replace: boolean }) => {
      persistSelectedProjectId(nextProjectId)
      setSelectedProjectIdState(nextProjectId)
      const currentLocationSearch = activeSearchString(location.searchStr)
      const nextSearch = selectedProjectUrlSearch(
        currentLocationSearch,
        nextProjectId,
      )
      const currentSearch = currentLocationSearch.startsWith("?")
        ? currentLocationSearch.slice(1)
        : currentLocationSearch
      if (searchStringFromUrlSearch(nextSearch) === currentSearch) {
        return
      }
      void navigate({
        replace,
        search: (() => nextSearch) as never,
      })
    },
    [location.searchStr, navigate],
  )

  const setSelectedProjectId = useCallback(
    (update: SetStateAction<string>) => {
      const nextProjectId =
        typeof update === "function" ? update(selectedProjectId) : update
      selectProjectId(nextProjectId, { replace: false })
    },
    [selectProjectId, selectedProjectId],
  )

  useEffect(() => {
    if (bootstrapError instanceof ApiError && bootstrapError.status === 401) {
      void handleAuthExpired()
    }
  }, [bootstrapError, handleAuthExpired])

  useEffect(() => {
    if (!projectsQuery.isSuccess) {
      return
    }
    if (
      selectedProjectId === selectedProjectIdState &&
      selectedProjectId === urlSelectedProjectId
    ) {
      return
    }
    selectProjectId(selectedProjectId, { replace: true })
  }, [
    projectsQuery.isSuccess,
    selectProjectId,
    selectedProjectId,
    selectedProjectIdState,
    urlSelectedProjectId,
  ])

  const refreshProjects = useCallback(
    async (preferredProjectId?: string) => {
      await invalidateWorkbenchProjectQueries(queryClient)
      if (preferredProjectId) {
        setSelectedProjectId(preferredProjectId)
      }
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
