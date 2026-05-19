import type { ProviderStatusPublic } from "@/api-client"
import { VpwGrid } from "@/components/vpw"
import { ProviderRuntimeFactsPanel } from "./ProviderRuntimeFactsPanel"
import { ProviderUpdateJobPanel } from "./ProviderUpdateJobPanel"

export function ProviderDiagnosticsSection({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  return (
    <VpwGrid columns={2}>
      <ProviderUpdateJobPanel providerStatus={providerStatus} />
      <ProviderRuntimeFactsPanel providerStatus={providerStatus} />
    </VpwGrid>
  )
}
