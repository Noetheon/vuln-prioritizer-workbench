import { useLocation, useNavigate } from "@tanstack/react-router"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { type FormEvent, useEffect, useState } from "react"
import {
  ApiTokensService,
  type ApiTokenCreatePublic,
  type ApiTokenPublic,
} from "../../api-client"
import { SettingsRouteContainer } from "../../components/settings/SettingsRouteContainer"
import {
  normalizeSettingsTab,
  type SettingsTab,
} from "../../components/settings/settings-workbench-model"
import { apiErrorMessage } from "../../lib/app-errors"
import {
  type ApiTokenScope,
  apiTokenScopeOptions,
  canonicalApiTokenScopes,
  defaultApiTokenScopes,
} from "../../lib/app-defaults"
import { useWorkbenchContext } from "../WorkbenchContext"
import { useApiTokensQuery } from "../useWorkbenchQueries"
import { workbenchQueryKeys } from "../workbench-query-keys"

function SettingsRouteContent() {
  const location = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const {
    currentUser,
    projects,
    providerStatus,
    providerStatusError,
    providerStatusLoading,
    selectedProjectId,
    status,
    statusError,
  } = useWorkbenchContext()
  const [apiTokenActionError, setApiTokenActionError] = useState("")
  const [apiTokenMessage, setApiTokenMessage] = useState("")
  const [apiTokenName, setApiTokenName] = useState("automation")
  const [apiTokenScopes, setApiTokenScopes] = useState<ApiTokenScope[]>(
    defaultApiTokenScopes,
  )
  const [apiTokenProjectId, setApiTokenProjectId] = useState("")
  const [createdApiToken, setCreatedApiToken] =
    useState<ApiTokenCreatePublic | null>(null)
  const routeSearch = activeSearchString(location.searchStr)
  const activeSettingsTab = normalizeSettingsTab(
    new URLSearchParams(
      routeSearch.startsWith("?") ? routeSearch.slice(1) : routeSearch,
    ).get("tab"),
  )
  const apiTokensQuery = useApiTokensQuery(true)
  const createApiTokenMutation = useMutation({
    mutationFn: (apiTokenCreate: {
      name: string
      project_id: string | null
      scopes: ApiTokenScope[]
    }) => ApiTokensService.createApiToken({ apiTokenCreate }),
  })
  const revokeApiTokenMutation = useMutation({
    mutationFn: (tokenId: string) =>
      ApiTokensService.revokeApiToken({ token_id: tokenId }),
  })

  useEffect(() => {
    if (apiTokenScopes.includes("admin")) {
      setApiTokenProjectId("")
      return
    }
    setApiTokenProjectId((previousProjectId) => {
      if (projects.some((project) => project.id === previousProjectId)) {
        return previousProjectId
      }
      if (projects.some((project) => project.id === selectedProjectId)) {
        return selectedProjectId
      }
      return projects[0]?.id ?? ""
    })
  }, [apiTokenScopes, projects, selectedProjectId])

  useEffect(() => {
    if (activeSettingsTab !== "tokens") {
      setCreatedApiToken(null)
    }
  }, [activeSettingsTab])

  function updateSettingsTab(tab: SettingsTab) {
    if (tab !== "tokens") {
      setCreatedApiToken(null)
    }
    void navigate({
      search: settingsRouteSearch(activeSearchString(location.searchStr), tab),
      to: "/settings",
    })
  }

  function toggleApiTokenScope(scope: ApiTokenScope) {
    setApiTokenScopes((previousScopes) => {
      const nextScopes = previousScopes.includes(scope)
        ? previousScopes.filter((item) => item !== scope)
        : [...previousScopes, scope]
      return canonicalApiTokenScopes(nextScopes)
    })
  }

  async function createApiToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const name = apiTokenName.trim()
    if (!name) {
      setApiTokenActionError("Token name is required.")
      return
    }
    if (apiTokenScopes.length === 0) {
      setApiTokenActionError("Select at least one scope.")
      return
    }
    const adminToken = apiTokenScopes.includes("admin")
    const scopedProjectId = adminToken ? null : apiTokenProjectId
    if (!adminToken && !scopedProjectId) {
      setApiTokenActionError("Select a project scope for this token.")
      return
    }

    setApiTokenActionError("")
    setApiTokenMessage("")
    setCreatedApiToken(null)
    try {
      const created = await createApiTokenMutation.mutateAsync({
        name,
        project_id: scopedProjectId,
        scopes: apiTokenScopes,
      })
      setCreatedApiToken(created)
      setApiTokenName("automation")
      setApiTokenScopes(defaultApiTokenScopes)
      setApiTokenMessage(`Token ${created.name} created.`)
      await queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.apiTokens(),
      })
    } catch (caught) {
      setApiTokenActionError(apiErrorMessage("API token create failed", caught))
    }
  }

  async function revokeApiToken(token: ApiTokenPublic) {
    setApiTokenActionError("")
    setApiTokenMessage("")
    try {
      const revoked = await revokeApiTokenMutation.mutateAsync(token.id)
      setCreatedApiToken((created) =>
        created?.id === revoked.id ? null : created,
      )
      setApiTokenMessage(`Token ${revoked.name} revoked.`)
      await queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.apiTokens(),
      })
    } catch (caught) {
      setApiTokenActionError(apiErrorMessage("API token revoke failed", caught))
    }
  }

  return (
    <section className="w-full">
      <SettingsRouteContainer
        activeSettingsTab={activeSettingsTab}
        apiTokenActionLoading={
          createApiTokenMutation.isPending || revokeApiTokenMutation.isPending
        }
        apiTokenError={
          apiTokenActionError ||
          (apiTokensQuery.isError
            ? apiErrorMessage("API tokens unavailable", apiTokensQuery.error)
            : "")
        }
        apiTokenMessage={apiTokenMessage}
        apiTokenName={apiTokenName}
        apiTokenProjectId={apiTokenProjectId}
        apiTokenProjectOptions={projects}
        apiTokenScopeOptions={apiTokenScopeOptions}
        apiTokenScopes={apiTokenScopes}
        apiTokens={apiTokensQuery.data?.data ?? []}
        apiTokensLoading={apiTokensQuery.isLoading || apiTokensQuery.isFetching}
        createdApiToken={createdApiToken}
        currentUser={currentUser}
        onClearCreatedApiToken={() => setCreatedApiToken(null)}
        onApiTokenNameChange={setApiTokenName}
        onApiTokenProjectChange={setApiTokenProjectId}
        onCreateApiToken={createApiToken}
        onRevokeApiToken={(token) => void revokeApiToken(token)}
        onSettingsTabChange={updateSettingsTab}
        onToggleApiTokenScope={toggleApiTokenScope}
        providerStatus={providerStatus}
        providerStatusError={providerStatusError}
        providerStatusLoading={providerStatusLoading}
        status={status}
        statusError={statusError}
      />
    </section>
  )
}

export function SettingsRoute() {
  return <SettingsRouteContent />
}

function settingsRouteSearch(searchStr: string, tab: SettingsTab) {
  const rawSearch = searchStr.startsWith("?") ? searchStr.slice(1) : searchStr
  const params = new URLSearchParams(rawSearch)
  if (tab === "overview") {
    params.delete("tab")
  } else {
    params.set("tab", tab)
  }
  return Object.fromEntries(params.entries())
}

function activeSearchString(fallbackSearch: string) {
  return typeof window === "undefined" ? fallbackSearch : window.location.search
}
