import { ProvidersRouteContainer } from "../../components/providers/ProvidersRouteContainer"
import { useWorkbenchContext } from "../WorkbenchContext"

function ProvidersRouteContent() {
  const {
    providerStatus,
    providerStatusError,
    providerStatusLoading,
    refreshProviderStatus,
    selectedProjectId,
  } = useWorkbenchContext()

  return (
    <section className="w-full">
      <ProvidersRouteContainer
        onRefreshProviderStatus={() => void refreshProviderStatus()}
        providerStatus={providerStatus}
        providerStatusError={providerStatusError}
        providerStatusLoading={providerStatusLoading}
        selectedProjectId={selectedProjectId}
      />
    </section>
  )
}

export function ProvidersRoute() {
  return <ProvidersRouteContent />
}
