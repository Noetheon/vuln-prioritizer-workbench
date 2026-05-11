import { VpwStatusBanner } from "@/components/vpw"
import type { SettingsWorkbenchProps } from "./settings-workbench-model"

type SettingsAlertsProps = Pick<
  SettingsWorkbenchProps,
  "apiTokenError" | "apiTokenMessage" | "providerStatusError" | "statusError"
>

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
