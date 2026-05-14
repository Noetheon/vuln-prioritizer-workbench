import { Link } from "@/lib/router"
import { RefreshCw } from "lucide-react"
import { useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwFilterBar,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSegmentedControl,
  VpwSkeletonStack,
} from "@/components/vpw"
import { buildWaiverRegisterColumns } from "./WaiversWorkbenchRegisterColumns"
import {
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"

const waiverViews = [
  { label: "Needs review", value: "needs-review" },
  { label: "Active", value: "active" },
  { label: "Expiring", value: "expiring" },
  { label: "Expired", value: "expired" },
  { label: "All", value: "all" },
] as const

export function WaiverRegister({
  openWaiverDrawer,
  onRefreshWaivers,
  selectedWaiverId,
  selectedProjectId,
  waiverActionLoading,
  waivers,
  waiversLoading,
}: Pick<
  WaiversWorkbenchProps,
  | "openWaiverDrawer"
  | "onRefreshWaivers"
  | "selectedWaiverId"
  | "selectedProjectId"
  | "waiverActionLoading"
  | "waivers"
  | "waiversLoading"
>) {
  const [registerView, setRegisterView] = useState("all")
  const [registerSearch, setRegisterSearch] = useState("")
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const filteredWaivers = useMemo(
    () =>
      waivers.filter(
        (waiver) =>
          matchesWaiverView(waiver, registerView) &&
          matchesWaiverSearch(waiver, registerSearch),
      ),
    [registerSearch, registerView, waivers],
  )

  const columns = buildWaiverRegisterColumns({
    openWaiverDrawer,
    selectedWaiverId,
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
      <VpwFilterBar
        actions={
          <Button
            disabled={!registerSearch && registerView === "all"}
            onClick={() => {
              setRegisterView("all")
              setRegisterSearch("")
            }}
            type="button"
            variant="outline"
          >
            Reset view
          </Button>
        }
        onSearchChange={setRegisterSearch}
        searchLabel="Risk acceptance search"
        searchPlaceholder="Search scope, owner, reason, evidence"
        searchValue={registerSearch}
      >
        <VpwSegmentedControl
          label="Risk acceptance views"
          onChange={setRegisterView}
          options={waiverViews}
          value={registerView}
        />
      </VpwFilterBar>
      {waiversLoading ? (
        <VpwPanel className="p-5">
          <VpwSkeletonStack rows={5} />
        </VpwPanel>
      ) : (
        <VpwDataTable
          caption="Risk acceptance register table"
          columns={columns}
          data={filteredWaivers}
          density="compact"
          emptyState={
            <VpwEmptyState
              action={
                <div className="flex flex-wrap justify-center gap-2">
                  <Button
                    onClick={() => openWaiverDrawer("create")}
                    type="button"
                  >
                    Create acceptance
                  </Button>
                  <Button asChild variant="outline">
                    <Link search={projectSearch} to="/findings">
                      View findings
                    </Link>
                  </Button>
                </div>
              }
              description="Create a risk acceptance only when remediation cannot happen immediately and compensating controls are documented."
              title={
                waivers.length === 0
                  ? "No accepted risk decisions yet"
                  : "No decisions match this view"
              }
            />
          }
          getRowKey={(waiver) => waiver.id}
          minWidth="1160px"
          tableClassName="table-fixed"
        />
      )}
    </VpwSection>
  )
}

function matchesWaiverView(
  waiver: WaiversWorkbenchProps["waivers"][number],
  view: string,
) {
  if (view === "all") return true
  if (view === "active") return waiver.status === "active"
  if (view === "expired") return waiver.status === "expired"
  if (view === "needs-review") return waiver.status === "review_due"
  if (view === "expiring") {
    return (
      waiver.status !== "expired" &&
      waiver.days_remaining !== null &&
      waiver.days_remaining !== undefined &&
      waiver.days_remaining >= 0 &&
      waiver.days_remaining <= 30
    )
  }
  return true
}

function matchesWaiverSearch(
  waiver: WaiversWorkbenchProps["waivers"][number],
  search: string,
) {
  const term = search.trim().toLowerCase()
  if (!term) return true
  return [
    waiverScopeLabel(waiver),
    waiver.owner,
    waiver.reason,
    waiver.status,
    waiver.approval_ref,
    waiver.ticket_url,
  ]
    .filter(Boolean)
    .some((value) => String(value).toLowerCase().includes(term))
}
