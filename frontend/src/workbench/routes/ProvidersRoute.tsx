import { ProvidersRouteContainer } from "../../components/providers/ProvidersRouteContainer"
import { WorkbenchShell } from "../WorkbenchShell"
import { useWorkbenchContext } from "../WorkbenchContext"

function ProvidersRouteContent() {
  const {
    providerStatus,
    providerStatusError,
    providerStatusLoading,
    refreshProviderStatus,
  } = useWorkbenchContext()

  return (
    <section className="mx-auto w-full max-w-screen-2xl px-4 py-6 sm:px-6">
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
  return (
    <WorkbenchShell routePath="/providers">
      <ProvidersRouteContent />
    </WorkbenchShell>
  )
}
