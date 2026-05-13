import type { ProviderStatusPublic } from "@/api-client"

import { ProvidersWorkbench } from "./ProvidersWorkbench"

export type ProvidersRouteContainerProps = {
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  providerStatusLoading: boolean
  selectedProjectId: string
  onRefreshProviderStatus: () => Promise<void> | void
}

export function ProvidersRouteContainer({
  onRefreshProviderStatus,
  providerStatus,
  providerStatusError,
  providerStatusLoading,
  selectedProjectId,
}: ProvidersRouteContainerProps) {
  return (
    <ProvidersWorkbench
      onRefreshProviderStatus={() => void onRefreshProviderStatus()}
      providerStatus={providerStatus}
      providerStatusError={providerStatusError}
      providerStatusLoading={providerStatusLoading}
      selectedProjectId={selectedProjectId}
    />
  )
}
