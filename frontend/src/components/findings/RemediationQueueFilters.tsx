import { ListFilter, RotateCcw } from "lucide-react"
import type { Dispatch, SetStateAction } from "react"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { FilterBar, VpwField, VpwSearchControl } from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"
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
  const activeSavedView = savedViewFromFilters(findingFilters)
  const activeFilterChips = [
    findingAssetId
      ? {
          label: `Asset: ${findingAssetKey ?? findingAssetId}`,
          onRemove: onClearAssetFilter,
        }
      : null,
    queryDraft.trim()
      ? {
          label: `Search: ${queryDraft.trim()}`,
          onRemove: () => setQueryDraft(""),
        }
      : null,
    ownerServiceDraft.trim()
      ? {
          label: `Owner / service: ${ownerServiceDraft.trim()}`,
          onRemove: () => setOwnerServiceDraft(""),
        }
      : null,
    findingFilters.priority
      ? {
          label: `Priority: ${labelize(findingFilters.priority)}`,
          onRemove: () => onFilterChange("priority", ""),
        }
      : null,
    findingFilters.status
      ? {
          label: `Status: ${labelize(findingFilters.status)}`,
          onRemove: () => onFilterChange("status", ""),
        }
      : null,
    findingFilters.kev
      ? {
          label: findingFilters.kev === "true" ? "KEV listed" : "Not KEV",
          onRemove: () => onFilterChange("kev", ""),
        }
      : null,
    findingFilters.exposure
      ? {
          label: `Exposure: ${labelize(findingFilters.exposure)}`,
          onRemove: () => onFilterChange("exposure", ""),
        }
      : null,
    findingFilters.epssMin
      ? {
          label: `EPSS min: ${findingFilters.epssMin}`,
          onRemove: () => onFilterChange("epssMin", ""),
        }
      : null,
    findingFilters.epssMax
      ? {
          label: `EPSS max: ${findingFilters.epssMax}`,
          onRemove: () => onFilterChange("epssMax", ""),
        }
      : null,
    findingFilters.cvssMin
      ? {
          label: `CVSS min: ${findingFilters.cvssMin}`,
          onRemove: () => onFilterChange("cvssMin", ""),
        }
      : null,
    findingFilters.cvssMax
      ? {
          label: `CVSS max: ${findingFilters.cvssMax}`,
          onRemove: () => onFilterChange("cvssMax", ""),
        }
      : null,
  ].filter((chip): chip is { label: string; onRemove: () => void } =>
    Boolean(chip),
  )

  return (
    <FilterBar
      activeFilters={activeFilterChips.map((chip) => ({
        ariaLabel: `Remove active filter ${chip.label}`,
        id: chip.label,
        label: chip.label,
        onRemove: chip.onRemove,
      }))}
      actions={
        <>
          <Button
            aria-expanded={showAdvancedFilters}
            onClick={() => setAdvancedFiltersOpen((open) => !open)}
            size="sm"
            type="button"
            variant={showAdvancedFilters ? "secondary" : "outline"}
          >
            <ListFilter aria-hidden="true" size={14} />
            {signalFilterCount > 0
              ? `Signals (${signalFilterCount})`
              : "Signals"}
          </Button>
          <Button
            disabled={!activeFindingFilters && filterCount === 0}
            onClick={onClearFilters}
            size="sm"
            type="button"
            variant="ghost"
          >
            <RotateCcw aria-hidden="true" size={14} />
            Reset
          </Button>
        </>
      }
      leading={
        !isDemo ? (
            <RemediationQueueProjectSelect
              onProjectChange={onProjectChange}
              projectListLoading={projectListLoading}
              projects={projects}
              selectedProjectId={selectedProjectId}
            />
          ) : undefined
      }
      onSearchChange={setQueryDraft}
      searchLabel="Finding search"
      searchPlaceholder="CVE, asset"
      searchTitle="Search"
      searchValue={queryDraft}
      secondaryControls={
        showAdvancedFilters ? (
          <AdvancedFilterSelects
            findingFilters={findingFilters}
            onFilterChange={onFilterChange}
          />
        ) : undefined
      }
    >
      <VpwField
        className="vpw-filter-field vpw-filter-field--md"
        label="Owner / Service"
      >
        <VpwSearchControl
          onChange={(event) => setOwnerServiceDraft(event.target.value)}
          placeholder="Owner or service"
          value={ownerServiceDraft}
        />
      </VpwField>
      <PrimaryFilterSelects
        findingFilters={findingFilters}
        onFilterChange={onFilterChange}
      />
      <RemediationQueueSavedViews
        activeSavedView={activeSavedView}
        onSavedViewChange={onSavedViewChange}
      />
    </FilterBar>
  )
}
