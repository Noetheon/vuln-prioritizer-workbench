import { Link } from "@/lib/router"

import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwCommandPanel,
  VpwSection,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  evidenceReadiness,
  providerHealth,
  type SettingsWorkbenchProps,
} from "./settings-workbench-model"

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
  const provider = providerHealth(providerStatus)
  const evidence = evidenceReadiness(
    providerStatus,
    providerStatusError,
    statusError,
  )
  const backend = backendState(status?.status, statusError)

  return (
    <VpwSection aria-label="Workspace settings">
      <VpwCommandPanel
        actions={
          <VpwToolbar label="Settings actions" variant="plain">
            <VpwToolbarGroup>
              <Button asChild variant="outline">
                <Link
                  search={selectedProjectRouteSearch(selectedProjectId)}
                  to="/providers"
                >
                  View providers
                </Link>
              </Button>
            </VpwToolbarGroup>
            <VpwToolbarGroup>
              <VpwBadge tone="success">Local workspace</VpwBadge>
              <VpwBadge tone={backend.tone}>{backend.label}</VpwBadge>
              <VpwBadge tone={provider.tone}>Providers {provider.label}</VpwBadge>
              <VpwBadge tone={evidence.tone}>Evidence {evidence.label}</VpwBadge>
            </VpwToolbarGroup>
          </VpwToolbar>
        }
        description="Review local Workbench runtime, provider freshness, diagnostics, and safe operational defaults."
        eyebrow="Settings console"
        title="Workspace settings console"
      />
    </VpwSection>
  )
}

function backendState(
  status: string | null | undefined,
  statusError: string,
): { label: string; tone: VpwBadgeTone } {
  if (statusError) {
    return { label: "Backend review", tone: "critical" }
  }
  if (!status) {
    return { label: "Backend checking", tone: "info" }
  }
  if (status === "ready") {
    return { label: "Backend ready", tone: "success" }
  }
  return { label: `Backend ${status}`, tone: "warning" }
}
