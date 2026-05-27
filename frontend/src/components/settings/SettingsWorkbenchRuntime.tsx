import type { ProviderStatusPublic, UploadPolicyPublic } from "@/api-client"
import { VpwSection } from "@/components/vpw"
import { SettingsDiagnosticsPanel } from "./SettingsDiagnosticsPanel"
import { SettingsRuntimeProviderPanel } from "./SettingsRuntimeProviderPanel"
import {
  evidenceReadiness,
  type SettingsWorkbenchProps,
} from "./settings-workbench-model"

type SettingsDiagnosticsProps = Pick<
  SettingsWorkbenchProps,
  "providerStatus" | "providerStatusError" | "status" | "statusError"
>

export function SettingsRuntimeProviders({
  capabilitiesError,
  providerStatus,
  uploadPolicy,
}: {
  capabilitiesError: string
  providerStatus: ProviderStatusPublic | null
  uploadPolicy: UploadPolicyPublic | null
}) {
  return (
    <VpwSection aria-label="Runtime and providers">
      <SettingsRuntimeProviderPanel
        capabilitiesError={capabilitiesError}
        providerStatus={providerStatus}
        uploadPolicy={uploadPolicy}
      />
    </VpwSection>
  )
}

export function SettingsDiagnostics({
  providerStatus,
  providerStatusError,
  status,
  statusError,
}: SettingsDiagnosticsProps) {
  const evidence = evidenceReadiness(
    providerStatus,
    providerStatusError,
    statusError,
  )

  return (
    <VpwSection aria-label="Diagnostics">
      <SettingsDiagnosticsPanel
        evidence={evidence}
        providerStatus={providerStatus}
        status={status}
        statusError={statusError}
      />
    </VpwSection>
  )
}
