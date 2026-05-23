import { Link } from "@/lib/router"
import { RefreshCw, RotateCcw } from "lucide-react"
import { useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwField,
  VpwFilterBar,
  VpwSection,
  VpwSelectControl,
  VpwSkeletonStack,
  VpwTableCard,
} from "@/components/vpw"
import { buildWaiverRegisterColumns } from "./WaiversWorkbenchRegisterColumns"
import {
  matchesWaiverEvidenceView,
  matchesWaiverFindingView,
  matchesWaiverOwnerView,
  matchesWaiverSearch,
  matchesWaiverScopeTypeView,
  matchesWaiverView,
  waiverEvidenceViews,
  waiverFindingViews,
  waiverScopeTypeViews,
  waiverViews,
} from "./waivers-register-model"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"

export function WaiverRegister({
  openWaiverDrawer,
  onProjectChange,
  onRefreshWaivers,
  projectListLoading,
  projects,
  selectedWaiverId,
  selectedProjectId,
  waiverActionLoading,
  waivers,
  waiversLoading,
}: Pick<
  WaiversWorkbenchProps,
  | "openWaiverDrawer"
  | "onProjectChange"
  | "onRefreshWaivers"
  | "projectListLoading"
  | "projects"
  | "selectedWaiverId"
  | "selectedProjectId"
  | "waiverActionLoading"
  | "waivers"
  | "waiversLoading"
>) {
  const [registerView, setRegisterView] = useState("all")
  const [evidenceView, setEvidenceView] = useState("all")
  const [findingView, setFindingView] = useState("all")
  const [ownerView, setOwnerView] = useState("all")
  const [registerSearch, setRegisterSearch] = useState("")
  const [scopeTypeView, setScopeTypeView] = useState("all")
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const ownerOptions = useMemo(
    () => [
      { label: "All", value: "all" },
      ...Array.from(new Set(waivers.map((waiver) => waiver.owner)))
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b))
        .map((owner) => ({ label: owner, value: owner })),
    ],
    [waivers],
  )
  const filteredWaivers = useMemo(
    () =>
      waivers.filter(
        (waiver) =>
          matchesWaiverView(waiver, registerView) &&
          matchesWaiverEvidenceView(waiver, evidenceView) &&
          matchesWaiverFindingView(waiver, findingView) &&
          matchesWaiverOwnerView(waiver, ownerView) &&
          matchesWaiverScopeTypeView(waiver, scopeTypeView) &&
          matchesWaiverSearch(waiver, registerSearch),
      ),
    [
      evidenceView,
      findingView,
      ownerView,
      registerSearch,
      registerView,
      scopeTypeView,
      waivers,
    ],
  )
  const hasRegisterFilters =
    registerView !== "all" ||
    evidenceView !== "all" ||
    findingView !== "all" ||
    ownerView !== "all" ||
    scopeTypeView !== "all" ||
    registerSearch.trim().length > 0
  const resetRegisterFilters = () => {
    setRegisterView("all")
    setEvidenceView("all")
    setFindingView("all")
    setOwnerView("all")
    setRegisterSearch("")
    setScopeTypeView("all")
  }

  const columns = buildWaiverRegisterColumns({
    openWaiverDrawer,
    selectedWaiverId,
    waiverActionLoading,
  })

  return (
    <>
      <VpwSection className="waivers-register-filter-section">
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
            <VpwField className="vpw-filter-field--lg" label="Project">
              <VpwSelectControl
                ariaLabel="Risk Acceptance project"
                disabled={projectListLoading || projects.length === 0}
                onValueChange={onProjectChange}
                options={projects.map((project) => ({
                  label: project.name,
                  value: project.id,
                }))}
                placeholder="Select project"
                value={selectedProjectId}
              />
            </VpwField>
          }
          onSearchChange={setRegisterSearch}
          searchClassName="vpw-filter-field--md"
          searchLabel="Risk acceptance search"
          searchPlaceholder="Scope, owner, reason"
          searchTitle="Search"
          searchValue={registerSearch}
        >
          <VpwField className="vpw-filter-field--sm" label="View">
            <VpwSelectControl
              ariaLabel="Risk acceptance view"
              onValueChange={setRegisterView}
              options={waiverViews}
              value={registerView}
            />
          </VpwField>
          <VpwField className="vpw-filter-field--md" label="Owner">
            <VpwSelectControl
              ariaLabel="Risk acceptance owner"
              onValueChange={setOwnerView}
              options={ownerOptions}
              value={ownerView}
            />
          </VpwField>
          <VpwField className="vpw-filter-field--sm" label="Evidence">
            <VpwSelectControl
              ariaLabel="Risk acceptance evidence coverage"
              onValueChange={setEvidenceView}
              options={waiverEvidenceViews}
              value={evidenceView}
            />
          </VpwField>
          <VpwField className="vpw-filter-field--sm" label="Findings">
            <VpwSelectControl
              ariaLabel="Risk acceptance matched findings"
              onValueChange={setFindingView}
              options={waiverFindingViews}
              value={findingView}
            />
          </VpwField>
          <VpwField className="vpw-filter-field--sm" label="Scope">
            <VpwSelectControl
              ariaLabel="Risk acceptance scope type"
              onValueChange={setScopeTypeView}
              options={waiverScopeTypeViews}
              value={scopeTypeView}
            />
          </VpwField>
        </VpwFilterBar>
      </VpwSection>

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
    </>
  )
}
