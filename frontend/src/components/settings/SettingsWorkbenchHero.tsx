import { Link } from "@tanstack/react-router"

import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import {
  evidenceReadiness,
  providerHealth,
  type SettingsWorkbenchProps,
  userLabel,
} from "./settings-workbench-model"

type SettingsHeroProps = Pick<
  SettingsWorkbenchProps,
  | "apiTokens"
  | "currentUser"
  | "providerStatus"
  | "providerStatusError"
  | "statusError"
>

type SettingsAlertsProps = Pick<
  SettingsWorkbenchProps,
  "apiTokenError" | "apiTokenMessage" | "providerStatusError" | "statusError"
>

export function SettingsHero({
  apiTokens,
  currentUser,
  providerStatus,
  providerStatusError,
  statusError,
}: SettingsHeroProps) {
  const provider = providerHealth(providerStatus)
  const evidence = evidenceReadiness(
    providerStatus,
    providerStatusError,
    statusError,
  )

  return (
    <VpwSection aria-label="User Settings">
      <VpwPanel className="flex flex-col gap-5 p-5">
        <VpwSectionHeader
          actions={
            <Button asChild variant="outline">
              <Link to="/providers">View providers</Link>
            </Button>
          }
          description="Manage workspace access, API tokens, runtime configuration and diagnostics."
          eyebrow="Workspace configuration"
          title="Settings"
        />
        <VpwToolbar label="Settings context" variant="plain">
          <VpwToolbarGroup>
            <VpwBadge tone={currentUser ? "success" : "warning"}>
              {userLabel(currentUser)}
            </VpwBadge>
            <VpwBadge tone={apiTokens.length > 0 ? "info" : "neutral"}>
              API tokens: {apiTokens.length}
            </VpwBadge>
            <VpwBadge tone={provider.tone}>
              Snapshot: {providerStatus?.snapshot_mode ?? "loading"}
            </VpwBadge>
            <VpwBadge tone={evidence.tone}>Evidence: {evidence.label}</VpwBadge>
          </VpwToolbarGroup>
        </VpwToolbar>
      </VpwPanel>
    </VpwSection>
  )
}

export function SettingsAlerts({
  apiTokenError,
  apiTokenMessage,
  providerStatusError,
  statusError,
}: SettingsAlertsProps) {
  return (
    <>
      {statusError ? (
        <VpwStatusBanner title="Workbench status unavailable" tone="critical">
          {statusError}
        </VpwStatusBanner>
      ) : null}

      {providerStatusError ? (
        <VpwStatusBanner title="Provider status unavailable" tone="warning">
          {providerStatusError}
        </VpwStatusBanner>
      ) : null}

      {apiTokenError ? (
        <VpwStatusBanner title="API token action failed" tone="critical">
          {apiTokenError}
        </VpwStatusBanner>
      ) : null}

      {apiTokenMessage ? (
        <VpwStatusBanner title="API token action complete" tone="success">
          {apiTokenMessage}
        </VpwStatusBanner>
      ) : null}
    </>
  )
}
