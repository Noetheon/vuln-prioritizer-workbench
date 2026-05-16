import { Link } from "@/lib/router"
import { RefreshCw, RotateCcw } from "lucide-react"
import { useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwFilterBar,
  VpwSection,
  VpwSegmentedControl,
  VpwSkeletonStack,
  VpwTableCard,
} from "@/components/vpw"
import { buildWaiverRegisterColumns } from "./WaiversWorkbenchRegisterColumns"
import {
  isMissingApproval,
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"

const waiverViews = [
  { label: "All", value: "all" },
  { label: "Active", value: "active" },
  { label: "Needs review", value: "needs-review" },
  { label: "Expiring", value: "expiring" },
  { label: "Expired", value: "expired" },
] as const

const waiverEvidenceViews = [
  { label: "All", value: "all" },
  { label: "Missing", value: "missing" },
  { label: "Recorded", value: "recorded" },
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
  const [evidenceView, setEvidenceView] = useState("all")
  const [registerSearch, setRegisterSearch] = useState("")
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const filteredWaivers = useMemo(
    () =>
      waivers.filter(
        (waiver) =>
          matchesWaiverView(waiver, registerView) &&
          matchesWaiverEvidenceView(waiver, evidenceView) &&
          matchesWaiverSearch(waiver, registerSearch),
      ),
    [evidenceView, registerSearch, registerView, waivers],
  )
  const hasRegisterFilters = registerView !== "all" || evidenceView !== "all" || registerSearch.trim().length > 0
  const resetRegisterFilters = () => {
    setRegisterView("all")
    setEvidenceView("all")
    setRegisterSearch("")
  }

  const columns = buildWaiverRegisterColumns({
    openWaiverDrawer,
    selectedWaiverId,
    waiverActionLoading,
  })

  return (
    <VpwSection>
      <VpwTableCard
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
      >
        <VpwFilterBar
          actions={
            <Button
              aria-label="Reset risk acceptance filters"
              disabled={!hasRegisterFilters}
              onClick={resetRegisterFilters}
              type="button"
              variant="outline"
            >
              <RotateCcw aria-hidden="true" />
              Reset
            </Button>
          }
          leading={
            <div className="vpw-filter-field flex-[0_0_auto]">
              <span className="vpw-label vpw-filter-label">View</span>
              <VpwSegmentedControl
                label="Risk acceptance views"
                onChange={setRegisterView}
                options={waiverViews}
                value={registerView}
              />
            </div>
          }
          onSearchChange={setRegisterSearch}
          searchClassName="vpw-filter-field--md"
          searchLabel="Risk acceptance search"
          searchPlaceholder="Scope, owner, reason"
          searchTitle="Search"
          searchValue={registerSearch}
        >
          <div className="vpw-filter-field flex-[0_0_auto]">
            <span className="vpw-label vpw-filter-label">Evidence</span>
            <VpwSegmentedControl
              label="Evidence coverage"
              onChange={setEvidenceView}
              options={waiverEvidenceViews}
              value={evidenceView}
            />
          </div>
        </VpwFilterBar>

        {waiversLoading ? (
          <VpwSkeletonStack rows={5} />
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
                className="!min-h-72 !rounded-none !border-0 !bg-transparent"
                description="Create a risk acceptance only when remediation cannot happen immediately and compensating controls are documented."
                title={
                  waivers.length === 0
                    ? "No accepted risk decisions yet"
                    : "No decisions match these filters"
                }
              />
            }
            getRowKey={(waiver) => waiver.id}
            minWidth="1080px"
            tableClassName="table-fixed"
          />
        )}
      </VpwTableCard>
    </VpwSection>
  )
}

function matchesWaiverEvidenceView(
  waiver: WaiversWorkbenchProps["waivers"][number],
  view: string,
) {
  if (view === "missing") return isMissingApproval(waiver)
  if (view === "recorded") return !isMissingApproval(waiver)
  return true
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
