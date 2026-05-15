import { Filter, ListFilter, X } from "lucide-react"
import type { Dispatch, SetStateAction } from "react"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { VpwBadge, VpwPanel, VpwSearchInput } from "@/components/vpw"
import {
  AdvancedFilterSelects,
  PrimaryFilterSelects,
} from "./RemediationQueueFilterControls"
import { RemediationQueueProjectSelect } from "./RemediationQueueProjectSelect"
import { RemediationQueueSavedViews } from "./RemediationQueueSavedViews"
import {
  savedViewFromFilters,
  type FindingFilters,
  type FindingsSavedView,
} from "./remediation-queue-model"

type RemediationQueueFiltersProps = {
  activeFindingFilters: boolean
  controlIdPrefix?: string
  filterCount: number
  findingAssetId: string | null
  findingAssetKey: string | null
  findingFilters: FindingFilters
  isDemo: boolean
  onClearAssetFilter: () => void
  onClearFilters: () => void
  onFilterChange: <K extends keyof FindingFilters>(
    key: K,
    value: FindingFilters[K],
  ) => void
  onProjectChange: (id: string) => void
  onSavedViewChange: (view: FindingsSavedView) => void
  ownerServiceDraft: string
  projectListLoading: boolean
  projects: ProjectPublic[]
  queryDraft: string
  selectedProjectId: string
  setAdvancedFiltersOpen: Dispatch<SetStateAction<boolean>>
  setOwnerServiceDraft: Dispatch<SetStateAction<string>>
  setQueryDraft: Dispatch<SetStateAction<string>>
  showAdvancedFilters: boolean
  signalFilterCount: number
}

export function RemediationQueueFilters({
  activeFindingFilters,
  controlIdPrefix = "queue",
  filterCount,
  findingAssetId,
  findingAssetKey,
  findingFilters,
  isDemo,
  onClearAssetFilter,
  onClearFilters,
  onFilterChange,
  onProjectChange,
  onSavedViewChange,
  ownerServiceDraft,
  projectListLoading,
  projects,
  queryDraft,
  selectedProjectId,
  setAdvancedFiltersOpen,
  setOwnerServiceDraft,
  setQueryDraft,
  showAdvancedFilters,
  signalFilterCount,
}: RemediationQueueFiltersProps) {
  const queueSearchId = `${controlIdPrefix}-search`
  const ownerServiceSearchId = `${controlIdPrefix}-owner-service`
  const activeSavedView = savedViewFromFilters(findingFilters)

  return (
    <VpwPanel
      aria-label="Findings filters"
      className="findings-filter-card py-0 shadow-sm"
      role="region"
    >
      <div className="px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          {!isDemo ? (
            <RemediationQueueProjectSelect
              onProjectChange={onProjectChange}
              projectListLoading={projectListLoading}
              projects={projects}
              selectedProjectId={selectedProjectId}
            />
          ) : null}

          {findingAssetId ? (
            <div className="inline-flex h-9 items-center gap-1.5 rounded-md border bg-muted px-2 text-xs font-medium">
              <span>Asset</span>
              <strong>{findingAssetKey ?? findingAssetId}</strong>
              <Button
                aria-label="Clear asset filter"
                className="ml-1 size-6"
                onClick={onClearAssetFilter}
                size="icon"
                type="button"
                variant="ghost"
              >
                <X aria-hidden="true" size={12} />
              </Button>
            </div>
          ) : null}

          <label
            className="flex min-w-64 flex-[1.35] flex-col gap-1"
            htmlFor={queueSearchId}
          >
            <span className="text-[11px] font-semibold uppercase text-muted-foreground">
              Search
            </span>
            <VpwSearchInput
              id={queueSearchId}
              onChange={(e) => setQueryDraft(e.target.value)}
              placeholder="CVE, component, asset"
              value={queryDraft}
            />
          </label>

          <label
            className="flex min-w-48 flex-1 flex-col gap-1"
            htmlFor={ownerServiceSearchId}
          >
            <span className="text-[11px] font-semibold uppercase text-muted-foreground">
              Owner / Service
            </span>
            <VpwSearchInput
              id={ownerServiceSearchId}
              onChange={(e) => setOwnerServiceDraft(e.target.value)}
              placeholder="payments, infra-team"
              value={ownerServiceDraft}
            />
          </label>

          <PrimaryFilterSelects
            findingFilters={findingFilters}
            onFilterChange={onFilterChange}
          />

          <RemediationQueueSavedViews
            activeSavedView={activeSavedView}
            onSavedViewChange={onSavedViewChange}
          />

          <div className="ml-auto flex items-end gap-2 self-end">
            <Button
              aria-expanded={showAdvancedFilters}
              className="h-10"
              onClick={() => setAdvancedFiltersOpen((open) => !open)}
              size="sm"
              type="button"
              variant={showAdvancedFilters ? "secondary" : "outline"}
            >
              <ListFilter aria-hidden="true" size={14} />
              Signals
              {signalFilterCount > 0 ? (
                <VpwBadge className="ml-1" density="compact">
                  {signalFilterCount}
                </VpwBadge>
              ) : null}
            </Button>

            <Button
              className="h-10"
              disabled={!activeFindingFilters && filterCount === 0}
              onClick={onClearFilters}
              size="sm"
              type="button"
              variant="ghost"
            >
              <Filter aria-hidden="true" size={14} />
              Reset
            </Button>
          </div>
        </div>

        {showAdvancedFilters ? (
          <AdvancedFilterSelects
            findingFilters={findingFilters}
            onFilterChange={onFilterChange}
          />
        ) : null}
      </div>
    </VpwPanel>
  )
}
