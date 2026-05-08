import { ProvidersRouteContainer } from "../../components/providers/ProvidersRouteContainer"
import { useWorkbenchContext } from "../WorkbenchContext"

function ProvidersRouteContent() {
  const {
    providerStatus,
    providerStatusError,
    providerStatusLoading,
    refreshProviderStatus,
  } = useWorkbenchContext()

  return (
    <section className="w-full">
      <ProvidersRouteContainer
        onRefreshProviderStatus={() => void refreshProviderStatus()}
        providerStatus={providerStatus}
        providerStatusError={providerStatusError}
        providerStatusLoading={providerStatusLoading}
      />
    </section>
  )
}

export function ProvidersRoute() {
  return <ProvidersRouteContent />
}
