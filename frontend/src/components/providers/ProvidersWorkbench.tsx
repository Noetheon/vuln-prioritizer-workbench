import "@/styles/providers.css"

import { VpwPageContainer } from "@/components/vpw"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  ProviderDiagnosticsSection,
  ProviderDataQualitySection,
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
  selectedProjectId,
}: ProvidersWorkbenchProps) {
  const showProviderDetails = !providerStatusError
  const rows = showProviderDetails ? sourceRows(providerStatus) : []
  const counts = providerSourceCounts(rows)

  return (
    <VpwPageContainer className="providers-workbench flex flex-col gap-6 px-0 py-0">
      <ProvidersHero
        onRefreshProviderStatus={onRefreshProviderStatus}
        providerStatus={providerStatus}
        providerStatusError={providerStatusError}
        providerStatusLoading={providerStatusLoading}
        selectedProjectId={selectedProjectId}
      />
      <ProviderStatusAlerts
        providerStatus={providerStatus}
        providerStatusError={providerStatusError}
        providerStatusLoading={providerStatusLoading}
      />
      {showProviderDetails ? (
        <Tabs
          className="providers-tabs"
          defaultValue="sources"
          orientation="horizontal"
        >
          <TabsList
            aria-label="Data source detail tabs"
            className="providers-tabs-list h-auto max-w-full flex-wrap justify-start"
          >
            <TabsTrigger value="sources">Sources</TabsTrigger>
            <TabsTrigger value="snapshot">Snapshot</TabsTrigger>
            <TabsTrigger value="diagnostics">Diagnostics</TabsTrigger>
            <TabsTrigger value="quality">Quality</TabsTrigger>
          </TabsList>
          <TabsContent value="sources">
            <ProviderSourcesTable
              onRefreshProviderStatus={onRefreshProviderStatus}
              providerStatusLoading={providerStatusLoading}
              rows={rows}
            />
          </TabsContent>
          <TabsContent value="snapshot">
            <ProviderSnapshotDetails
              onRefreshProviderStatus={onRefreshProviderStatus}
              providerStatus={providerStatus}
              rows={rows}
            />
          </TabsContent>
          <TabsContent value="diagnostics">
            <ProviderDiagnosticsSection providerStatus={providerStatus} />
          </TabsContent>
          <TabsContent value="quality">
            <ProviderDataQualitySection
              counts={counts}
              providerStatus={providerStatus}
            />
          </TabsContent>
        </Tabs>
      ) : null}
    </VpwPageContainer>
  )
}
