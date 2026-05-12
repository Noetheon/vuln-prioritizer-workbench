import { VpwPageContainer } from "@/components/vpw"
import {
  ProviderDataQualitySection,
  ProviderMetricsGrid,
  ProviderSnapshotDetails,
  ProviderSourcesTable,
  ProviderStatusAlerts,
  ProvidersHero,
} from "./ProvidersWorkbenchSections"
import {
  type ProvidersWorkbenchProps,
  providerSourceCounts,
  sourceRows,
} from "./providers-workbench-model"

export type { ProvidersWorkbenchProps } from "./providers-workbench-model"

export function ProvidersWorkbench({
  onRefreshProviderStatus,
  providerStatus,
  providerStatusError,
  providerStatusLoading,
}: ProvidersWorkbenchProps) {
  const showProviderDetails = !providerStatusError
  const rows = showProviderDetails ? sourceRows(providerStatus) : []
  const counts = providerSourceCounts(rows)

  return (
    <VpwPageContainer className="flex flex-col gap-6 px-0 py-0">
      <ProvidersHero
        onRefreshProviderStatus={onRefreshProviderStatus}
        providerStatus={providerStatus}
        providerStatusError={providerStatusError}
        providerStatusLoading={providerStatusLoading}
      />
      <ProviderStatusAlerts
        providerStatus={providerStatus}
        providerStatusError={providerStatusError}
        providerStatusLoading={providerStatusLoading}
      />
      {showProviderDetails ? (
        <>
          <ProviderMetricsGrid counts={counts} providerStatus={providerStatus} />
          <ProviderSourcesTable
            onRefreshProviderStatus={onRefreshProviderStatus}
            providerStatusLoading={providerStatusLoading}
            rows={rows}
          />
          <ProviderSnapshotDetails
            onRefreshProviderStatus={onRefreshProviderStatus}
            providerStatus={providerStatus}
            rows={rows}
          />
          <ProviderDataQualitySection
            counts={counts}
            providerStatus={providerStatus}
          />
        </>
      ) : null}
    </VpwPageContainer>
  )
}
