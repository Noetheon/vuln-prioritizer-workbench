import { VpwStatusBanner } from "@/components/vpw"
import type { SettingsWorkbenchProps } from "./settings-workbench-model"

type SettingsAlertsProps = Pick<
  SettingsWorkbenchProps,
  "providerStatusError" | "statusError"
>

export function SettingsAlerts({
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

    </>
  )
}
