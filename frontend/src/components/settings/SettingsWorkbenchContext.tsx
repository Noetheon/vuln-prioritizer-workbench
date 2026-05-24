import { Link } from "@/lib/router"
import { useState } from "react"
import { useQueryClient } from "@tanstack/react-query"
import { ExternalLink, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  VpwCommandPanel,
  VpwSection,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { SettingsStatusGrid } from "./SettingsStatusGrid"
import type { SettingsWorkbenchProps } from "./settings-workbench-model"

type SettingsContextProps = Pick<
  SettingsWorkbenchProps,
  | "providerStatus"
  | "providerStatusError"
  | "selectedProjectId"
  | "status"
  | "statusError"
>

export function SettingsContext({
  providerStatus,
  providerStatusError,
  selectedProjectId,
  status,
  statusError,
}: SettingsContextProps) {
  const queryClient = useQueryClient()
  const [isRefreshing, setIsRefreshing] = useState(false)

  async function handleRefresh() {
    setIsRefreshing(true)
    await queryClient.invalidateQueries({ queryKey: ["workbench"] })
    await new Promise((resolve) => setTimeout(resolve, 600))
    setIsRefreshing(false)
  }

  return (
    <VpwSection aria-label="Workspace settings">
      <VpwCommandPanel
        className="settings-context-panel"
        actions={
          <VpwToolbar label="Settings actions" variant="plain">
            <VpwToolbarGroup>
              <Button
                className="cursor-pointer"
                disabled={isRefreshing}
                onClick={handleRefresh}
                type="button"
                variant="outline"
              >
                <RefreshCw
                  className={`mr-1.5 size-4 ${isRefreshing ? "animate-spin" : ""}`}
                />
                {isRefreshing ? "Scanning..." : "Run Diagnostics"}
              </Button>

              <Button asChild variant="outline">
                <a
                  className="inline-flex cursor-pointer items-center"
                  href="http://localhost:8000/docs"
                  rel="noreferrer"
                  target="_blank"
                >
                  API Explorer
                  <ExternalLink className="ml-1.5 size-3.5 opacity-60" />
                </a>
              </Button>

              <Button asChild variant="outline">
                <Link
                  search={selectedProjectRouteSearch(selectedProjectId)}
                  to="/providers"
                >
                  View providers
                </Link>
              </Button>
            </VpwToolbarGroup>
          </VpwToolbar>
        }
        description="Review local Workbench runtime, provider freshness, diagnostics, and safe operational defaults."
        eyebrow="Settings console"
        title="Workspace settings console"
      >
        <SettingsStatusGrid
          providerStatus={providerStatus}
          providerStatusError={providerStatusError}
          status={status}
          statusError={statusError}
        />
      </VpwCommandPanel>
    </VpwSection>
  )
}
