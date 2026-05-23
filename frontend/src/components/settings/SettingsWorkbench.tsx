import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VpwPageContainer } from "@/components/vpw"
import "@/styles/projects.css"
import {
  SettingsAlerts,
  SettingsContext,
  SettingsDiagnostics,
  SettingsRuntimeProviders,
  SettingsWorkspaceHealth,
} from "./SettingsWorkbenchSections"
import {
  normalizeSettingsTab,
  settingsTabOptions,
  type SettingsWorkbenchProps,
} from "./settings-workbench-model"

export type { SettingsWorkbenchProps } from "./settings-workbench-model"

export function SettingsWorkbench(props: SettingsWorkbenchProps) {
  return (
    <VpwPageContainer className="settings-workbench vpw-page-stack px-0 py-0">
      <SettingsContext
        providerStatus={props.providerStatus}
        providerStatusError={props.providerStatusError}
        selectedProjectId={props.selectedProjectId}
        status={props.status}
        statusError={props.statusError}
      />
      <SettingsAlerts
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
        <div className="flex min-w-0">
          <TabsList
            aria-label="Settings sections"
            className="h-auto max-w-full flex-wrap justify-start gap-2 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] p-1"
          >
            {settingsTabOptions.map((option) => (
              <TabsTrigger
                className="min-w-0 px-3 py-1.5 text-sm"
                key={option.value}
                value={option.value}
              >
                {option.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        <TabsContent className="mt-5" value="overview">
          <SettingsWorkspaceHealth
            providerStatus={props.providerStatus}
            providerStatusError={props.providerStatusError}
            providerStatusLoading={props.providerStatusLoading}
            status={props.status}
            statusError={props.statusError}
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
