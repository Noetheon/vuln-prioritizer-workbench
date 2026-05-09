import { VpwPageContainer } from "@/components/vpw"
import {
  SettingsAccountHealth,
  SettingsAlerts,
  SettingsApiTokensSection,
  SettingsHero,
  SettingsMetrics,
  SettingsRuntimeDiagnostics,
  SettingsSecurityNotes,
} from "./SettingsWorkbenchSections"
import type { SettingsWorkbenchProps } from "./settings-workbench-model"

export type { SettingsWorkbenchProps } from "./settings-workbench-model"

export function SettingsWorkbench(props: SettingsWorkbenchProps) {
  return (
    <VpwPageContainer className="space-y-8 px-0 py-0">
      <SettingsHero
        apiTokens={props.apiTokens}
        currentUser={props.currentUser}
        providerStatus={props.providerStatus}
        providerStatusError={props.providerStatusError}
        statusError={props.statusError}
      />
      <SettingsAlerts
        apiTokenError={props.apiTokenError}
        apiTokenMessage={props.apiTokenMessage}
        providerStatusError={props.providerStatusError}
        statusError={props.statusError}
      />
      <SettingsMetrics
        apiTokens={props.apiTokens}
        apiTokensLoading={props.apiTokensLoading}
        currentUser={props.currentUser}
        providerStatus={props.providerStatus}
        providerStatusError={props.providerStatusError}
        statusError={props.statusError}
      />
      <SettingsAccountHealth
        apiTokens={props.apiTokens}
        currentUser={props.currentUser}
        providerStatus={props.providerStatus}
        providerStatusError={props.providerStatusError}
        providerStatusLoading={props.providerStatusLoading}
        status={props.status}
        statusError={props.statusError}
      />
      <SettingsApiTokensSection
        apiTokenActionLoading={props.apiTokenActionLoading}
        apiTokenName={props.apiTokenName}
        apiTokenProjectId={props.apiTokenProjectId}
        apiTokenProjectOptions={props.apiTokenProjectOptions}
        apiTokenScopeOptions={props.apiTokenScopeOptions}
        apiTokenScopes={props.apiTokenScopes}
        apiTokens={props.apiTokens}
        apiTokensLoading={props.apiTokensLoading}
        createdApiToken={props.createdApiToken}
        onApiTokenNameChange={props.onApiTokenNameChange}
        onApiTokenProjectChange={props.onApiTokenProjectChange}
        onCreateApiToken={props.onCreateApiToken}
        onRevokeApiToken={props.onRevokeApiToken}
        onToggleApiTokenScope={props.onToggleApiTokenScope}
      />
      <SettingsRuntimeDiagnostics
        providerStatus={props.providerStatus}
        providerStatusError={props.providerStatusError}
        status={props.status}
        statusError={props.statusError}
      />
      <SettingsSecurityNotes />
    </VpwPageContainer>
  )
}
