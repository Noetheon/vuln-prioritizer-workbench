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
  useWorkbenchCurrentUserQuery,
  useWorkbenchProviderStatusQuery,
  useWorkbenchStatusQuery,
  workbenchProviderStatusQueryKey,
} from "./useWorkbenchRuntimeQueries"
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
  projectListError: string
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
  const currentUserQuery = useWorkbenchCurrentUserQuery()
  const providerStatusQuery = useWorkbenchProviderStatusQuery()
  const statusQuery = useWorkbenchStatusQuery()
  const currentUserError = currentUserQuery.error
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
    if (currentUserError instanceof ApiError && currentUserError.status === 401) {
      void handleAuthExpired()
    }
  }, [currentUserError, handleAuthExpired])

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
      queryKey: workbenchProviderStatusQueryKey,
    })
  }, [queryClient])

  const value = useMemo<WorkbenchContextValue>(
    () => ({
      currentUser: currentUserQuery.data ?? null,
      handleAuthExpired,
      projectListError: projectsQuery.isError
        ? apiErrorMessage("Projects unavailable", projectsQuery.error)
        : "",
      projectListLoading: projectsQuery.isLoading || projectsQuery.isFetching,
      projects,
      providerStatus: providerStatusQuery.data ?? null,
      providerStatusError: providerStatusQuery.isError
        ? apiErrorMessage("Provider status unavailable", providerStatusQuery.error)
        : "",
      providerStatusLoading:
        providerStatusQuery.isLoading || providerStatusQuery.isFetching,
      refreshProjects,
      refreshProviderStatus,
      selectedProject:
        projects.find((project) => project.id === selectedProjectId) ?? null,
      selectedProjectId,
      setSelectedProjectId,
      status: statusQuery.data ?? null,
      statusError: statusQuery.isError ? "Data services unavailable" : "",
    }),
    [
      currentUserQuery.data,
      handleAuthExpired,
      projects,
      providerStatusQuery.data,
      providerStatusQuery.error,
      providerStatusQuery.isError,
      providerStatusQuery.isFetching,
      providerStatusQuery.isLoading,
      projectsQuery.error,
      projectsQuery.isFetching,
      projectsQuery.isError,
      projectsQuery.isLoading,
      refreshProjects,
      refreshProviderStatus,
      selectedProjectId,
      setSelectedProjectId,
      statusQuery.data,
      statusQuery.isError,
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
