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
  matchesWaiverEvidenceView,
  matchesWaiverSearch,
  matchesWaiverView,
  waiverEvidenceViews,
  waiverViews,
} from "./waivers-register-model"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"

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
  const hasRegisterFilters =
    registerView !== "all" ||
    evidenceView !== "all" ||
    registerSearch.trim().length > 0
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
        className="waivers-register-card"
        title="Decision register"
      >
        <VpwFilterBar
          className="waivers-filter-bar"
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
                    {waivers.length === 0 ? (
                      <Button
                        onClick={() => openWaiverDrawer("create")}
                        type="button"
                      >
                        Record accepted risk
                      </Button>
                    ) : (
                      <Button onClick={resetRegisterFilters} type="button">
                        Clear filters
                      </Button>
                    )}
                    <Button asChild variant="outline">
                      <Link
                        search={{ ...projectSearch, status: "accepted" }}
                        to="/findings"
                      >
                        Open accepted findings
                      </Link>
                    </Button>
                  </div>
                }
                className="!min-h-72 !rounded-none !border-0 !bg-transparent"
                description={
                  waivers.length === 0
                    ? "Record accepted risk only when a finding has an accountable owner, scope, expiry, and supporting evidence."
                    : "Clear filters or adjust the search."
                }
                title={
                  waivers.length === 0
                    ? "No accepted risk decisions yet"
                    : "No accepted-risk records match these filters"
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
