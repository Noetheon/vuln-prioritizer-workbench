import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VpwPageContainer } from "@/components/vpw"
import {
  SettingsAccountHealth,
  SettingsAlerts,
  SettingsApiTokensSection,
  SettingsHero,
  SettingsDiagnostics,
  SettingsRuntimeProviders,
} from "./SettingsWorkbenchSections"
import {
  normalizeSettingsTab,
  settingsTabOptions,
  type SettingsWorkbenchProps,
} from "./settings-workbench-model"

export type { SettingsWorkbenchProps } from "./settings-workbench-model"

export function SettingsWorkbench(props: SettingsWorkbenchProps) {
  return (
    <VpwPageContainer className="flex flex-col gap-5 px-0 py-0">
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
      <Tabs
        className="min-w-0"
        onValueChange={(value) =>
          props.onSettingsTabChange(normalizeSettingsTab(value))
        }
        value={props.activeSettingsTab}
      >
        <div className="flex min-w-0 border-b border-[var(--vpw-border-default)] pb-3">
          <TabsList
            aria-label="Settings sections"
            className="grid h-auto w-full min-w-0 grid-cols-2 gap-1 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] p-1 sm:inline-grid sm:w-auto sm:grid-cols-4"
          >
            {settingsTabOptions.map((option) => (
              <TabsTrigger
                className="min-h-9 min-w-0 rounded-[var(--vpw-radius-md)] border border-transparent px-2 py-2 text-center text-xs font-medium leading-tight text-[var(--vpw-text-secondary)] data-[state=active]:border-[var(--vpw-border-default)] data-[state=active]:bg-[var(--vpw-bg-card)] data-[state=active]:text-[var(--vpw-text-primary)] data-[state=active]:shadow-[var(--vpw-shadow-1)] sm:px-4 sm:text-sm"
                key={option.value}
                value={option.value}
              >
                {option.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        <TabsContent className="mt-5" value="overview">
          <SettingsAccountHealth
            apiTokens={props.apiTokens}
            currentUser={props.currentUser}
            providerStatus={props.providerStatus}
            providerStatusError={props.providerStatusError}
            providerStatusLoading={props.providerStatusLoading}
            status={props.status}
            statusError={props.statusError}
          />
        </TabsContent>

        <TabsContent className="mt-5" value="tokens">
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
            onClearCreatedApiToken={props.onClearCreatedApiToken}
            onApiTokenNameChange={props.onApiTokenNameChange}
            onApiTokenProjectChange={props.onApiTokenProjectChange}
            onCreateApiToken={props.onCreateApiToken}
            onRevokeApiToken={props.onRevokeApiToken}
            onToggleApiTokenScope={props.onToggleApiTokenScope}
          />
        </TabsContent>

        <TabsContent className="mt-5" value="runtime">
          <SettingsRuntimeProviders providerStatus={props.providerStatus} />
        </TabsContent>

        <TabsContent className="mt-5" value="diagnostics">
          <SettingsDiagnostics
            providerStatus={props.providerStatus}
            providerStatusError={props.providerStatusError}
            status={props.status}
            statusError={props.statusError}
          />
        </TabsContent>
      </Tabs>
    </VpwPageContainer>
  )
}
