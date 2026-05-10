import { Link } from "@tanstack/react-router"
import { RefreshCw } from "lucide-react"
import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
} from "@/components/vpw"
import { buildWaiverRegisterColumns } from "./WaiversWorkbenchRegisterColumns"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"

export function WaiverRegister({
  onExpireWaiver,
  onRefreshWaivers,
  waiverActionLoading,
  waivers,
  waiversLoading,
}: Pick<
  WaiversWorkbenchProps,
  | "onExpireWaiver"
  | "onRefreshWaivers"
  | "waiverActionLoading"
  | "waivers"
  | "waiversLoading"
>) {
  const [confirmExpireId, setConfirmExpireId] = useState<string | null>(null)

  useEffect(() => {
    if (
      confirmExpireId &&
      !waivers.some(
        (waiver) =>
          waiver.id === confirmExpireId && waiver.status !== "expired",
      )
    ) {
      setConfirmExpireId(null)
    }
  }, [confirmExpireId, waivers])

  const columns = buildWaiverRegisterColumns({
    confirmExpireId,
    onExpireWaiver,
    setConfirmExpireId,
    waiverActionLoading,
  })

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          <Button
            onClick={onRefreshWaivers}
            size="sm"
            type="button"
            variant="outline"
          >
            <RefreshCw aria-hidden="true" className="h-4 w-4" />
            Refresh
          </Button>
        }
        description="Accepted risk remains visible after creation and expiry."
        eyebrow="Register"
        title="Risk acceptance register"
      />
      {waiversLoading ? (
        <VpwPanel className="p-5">
          <VpwSkeletonStack rows={5} />
        </VpwPanel>
      ) : (
        <VpwDataTable
          caption="Waivers table"
          columns={columns}
          data={waivers}
          density="compact"
          emptyState={
            <VpwEmptyState
              action={
                <div className="flex flex-wrap justify-center gap-2">
                  <Button asChild>
                    <a href="#create-waiver">Create waiver</a>
                  </Button>
                  <Button asChild variant="outline">
                    <Link to="/findings">View findings</Link>
                  </Button>
                </div>
              }
              description="Create a waiver only when remediation cannot happen immediately and compensating controls are documented."
              title="No accepted risk decisions yet"
            />
          }
          getRowKey={(waiver) => waiver.id}
          tableClassName="table-fixed"
        />
      )}
    </VpwSection>
  )
}
