import { useEffect } from "react"
import { useLocation, useNavigate } from "@/lib/router"
import { SettingsRouteContainer } from "../../components/settings/SettingsRouteContainer"
import {
  normalizeSettingsTab,
  type SettingsTab,
} from "../../components/settings/settings-workbench-model"
import { useWorkbenchContext } from "../WorkbenchContext"

function SettingsRouteContent() {
  const location = useLocation()
  const navigate = useNavigate()
  const {
    capabilities,
    capabilitiesError,
    providerStatus,
    providerStatusError,
    providerStatusLoading,
    selectedProjectId,
    status,
    statusError,
  } = useWorkbenchContext()
  const routeSearch = activeSearchString(location.searchStr)
  const rawSettingsTab = new URLSearchParams(
    routeSearch.startsWith("?") ? routeSearch.slice(1) : routeSearch,
  ).get("tab")
  const activeSettingsTab = normalizeSettingsTab(rawSettingsTab)

  useEffect(() => {
    if (!rawSettingsTab || rawSettingsTab === activeSettingsTab) {
      return
    }
    void navigate({
      replace: true,
      search: settingsRouteSearch(routeSearch, activeSettingsTab),
      to: "/settings",
    })
  }, [activeSettingsTab, navigate, rawSettingsTab, routeSearch])

  function updateSettingsTab(tab: SettingsTab) {
    void navigate({
      search: settingsRouteSearch(activeSearchString(location.searchStr), tab),
      to: "/settings",
    })
  }

  return (
    <section className="w-full">
      <SettingsRouteContainer
        activeSettingsTab={activeSettingsTab}
        capabilitiesError={capabilitiesError}
        onSettingsTabChange={updateSettingsTab}
        providerStatus={providerStatus}
        providerStatusError={providerStatusError}
        providerStatusLoading={providerStatusLoading}
        selectedProjectId={selectedProjectId}
        status={status}
        statusError={statusError}
        uploadPolicy={capabilities?.upload_policy ?? null}
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
