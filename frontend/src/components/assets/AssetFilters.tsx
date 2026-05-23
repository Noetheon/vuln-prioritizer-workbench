import { BriefcaseBusiness, FilterX, RotateCcw, Server } from "lucide-react"

import type { ProjectPublic } from "../../api-client"
import { Button } from "../ui/button"
import {
  VpwEmptyState,
  VpwField,
  VpwFilterBar,
  VpwSection,
  VpwSearchControl,
  VpwSelectControl,
  VpwSkeletonStack,
  VpwTableCard,
} from "../vpw"
import { Link } from "@/lib/router"
import type { ReactNode } from "react"
import {
  criticalityOptions,
  environmentOptions,
  exposureOptions,
  type AssetFindingFilter,
  type AssetRescoreFilter,
} from "./asset-model"

const allOption = { label: "All", value: "all" }
const environmentFilterOptions = [
  allOption,
  ...environmentOptions.map((value) => ({ label: labelizeFilter(value), value })),
]
const exposureFilterOptions = [
  allOption,
  ...exposureOptions.map((value) => ({ label: labelizeFilter(value), value })),
]
const criticalityFilterOptions = [
  allOption,
  ...criticalityOptions.map((value) => ({ label: labelizeFilter(value), value })),
]
const findingFilterOptions = [
  allOption,
  { label: "Linked", value: "linked" },
  { label: "None", value: "none" },
]
const rescoreFilterOptions = [
  allOption,
  { label: "Needed", value: "needed" },
  { label: "Current", value: "current" },
]

export function AssetInventoryShell({
  assetCriticalityFilter,
  assetEnvironmentFilter,
  assetExposureFilter,
  assetFindingFilter,
  assetHasActiveFilters,
  assetOwnerFilter,
  assetRecordsTotal,
  assetRescoreFilter,
  assetSearchFilter,
  assetServiceFilter,
  assetsLoading,
  children,
  clearAssetFilters,
  hasAssets,
  openImportAssets,
  projectLoading,
  projects,
  projectSelectDisabled,
  selectProject,
  selectedProject,
  selectedProjectId,
  setAssetCriticalityFilter,
  setAssetEnvironmentFilter,
  setAssetExposureFilter,
  setAssetFindingFilter,
  setAssetOwnerFilter,
  setAssetRescoreFilter,
  setAssetSearchFilter,
  setAssetServiceFilter,
}: {
  assetCriticalityFilter: string
  assetEnvironmentFilter: string
  assetExposureFilter: string
  assetFindingFilter: AssetFindingFilter
  assetHasActiveFilters: boolean
  assetOwnerFilter: string
  assetRecordsTotal: number
  assetRescoreFilter: AssetRescoreFilter
  assetSearchFilter: string
  assetServiceFilter: string
  assetsLoading: boolean
  children: ReactNode
  clearAssetFilters: () => void
  hasAssets: boolean
  openImportAssets: () => void
  projectLoading: boolean
  projects: ProjectPublic[]
  projectSelectDisabled: boolean
  selectProject: (projectId: string) => void
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  setAssetCriticalityFilter: (value: string) => void
  setAssetEnvironmentFilter: (value: string) => void
  setAssetExposureFilter: (value: string) => void
  setAssetFindingFilter: (value: AssetFindingFilter) => void
  setAssetOwnerFilter: (value: string) => void
  setAssetRescoreFilter: (value: AssetRescoreFilter) => void
  setAssetSearchFilter: (value: string) => void
  setAssetServiceFilter: (value: string) => void
}) {
  return (
    <VpwSection className="assets-inventory-shell">
      <VpwFilterBar
        className="assets-filter-bar"
        leading={
          <VpwField className="vpw-filter-field--lg" label="Project">
            <VpwSelectControl
              ariaLabel="Assets project"
              disabled={projectSelectDisabled}
              options={projects.map((project) => ({
                label: project.name,
                value: project.id,
              }))}
              onValueChange={selectProject}
              placeholder="Select project"
              value={selectedProjectId}
            />
          </VpwField>
        }
        actions={
          <Button
            aria-label="Reset asset filters"
            disabled={!assetHasActiveFilters}
            onClick={clearAssetFilters}
            type="button"
            variant="outline"
          >
            <RotateCcw aria-hidden="true" />
            Reset
          </Button>
        }
        onSearchChange={setAssetSearchFilter}
        searchClassName="vpw-filter-field--md"
        searchLabel="Asset search"
        searchPlaceholder="Name, key, target"
        searchTitle="Asset"
        searchValue={assetSearchFilter}
      >
        <VpwField className="vpw-filter-field--md" label="Service">
          <VpwSearchControl
            aria-label="Asset service filter"
            onChange={(event) => setAssetServiceFilter(event.target.value)}
            placeholder="Filter by service"
            value={assetServiceFilter}
          />
        </VpwField>
        <VpwField className="vpw-filter-field--md" label="Owner">
          <VpwSearchControl
            aria-label="Asset owner filter"
            onChange={(event) => setAssetOwnerFilter(event.target.value)}
            placeholder="Filter by owner"
            value={assetOwnerFilter}
          />
        </VpwField>
        <VpwField className="vpw-filter-field--sm" label="Environment">
          <VpwSelectControl
            ariaLabel="Asset environment filter"
            onValueChange={setAssetEnvironmentFilter}
            options={environmentFilterOptions}
            value={assetEnvironmentFilter}
          />
        </VpwField>
        <VpwField className="vpw-filter-field--sm" label="Exposure">
          <VpwSelectControl
            ariaLabel="Asset exposure filter"
            onValueChange={setAssetExposureFilter}
            options={exposureFilterOptions}
            value={assetExposureFilter}
          />
        </VpwField>
        <VpwField className="vpw-filter-field--sm" label="Criticality">
          <VpwSelectControl
            ariaLabel="Asset criticality filter"
            onValueChange={setAssetCriticalityFilter}
            options={criticalityFilterOptions}
            value={assetCriticalityFilter}
          />
        </VpwField>
        <VpwField className="vpw-filter-field--sm" label="Findings">
          <VpwSelectControl
            ariaLabel="Asset finding linkage filter"
            onValueChange={(value) =>
              setAssetFindingFilter(value as AssetFindingFilter)
            }
            options={findingFilterOptions}
            value={assetFindingFilter}
          />
        </VpwField>
        <VpwField className="vpw-filter-field--sm" label="Rescore">
          <VpwSelectControl
            ariaLabel="Asset rescore filter"
            onValueChange={(value) =>
              setAssetRescoreFilter(value as AssetRescoreFilter)
            }
            options={rescoreFilterOptions}
            value={assetRescoreFilter}
          />
        </VpwField>
      </VpwFilterBar>

      {projects.length === 0 && !projectLoading ? (
        <VpwEmptyState
          action={
            <Button asChild>
              <Link to="/projects">Create project</Link>
            </Button>
          }
          icon={<BriefcaseBusiness aria-hidden="true" />}
          title="No projects yet"
          description="Create a project before managing asset context."
        />
      ) : null}

      {!assetsLoading && selectedProject && assetRecordsTotal === 0 ? (
        <VpwEmptyState
          action={
            <Button onClick={openImportAssets} type="button" variant="outline">
              Import asset context
            </Button>
          }
          icon={<Server aria-hidden="true" />}
          title="No asset context yet"
          description="Import asset context to improve prioritization and ownership."
        />
      ) : null}

      {!assetsLoading && selectedProject && assetRecordsTotal > 0 && !hasAssets ? (
        <VpwEmptyState
          action={
            <Button
              disabled={!assetHasActiveFilters}
              onClick={clearAssetFilters}
              type="button"
              variant="outline"
            >
              <RotateCcw aria-hidden="true" />
              Reset filters
            </Button>
          }
          icon={<FilterX aria-hidden="true" />}
          title="No matching assets"
          description="Adjust the register filters to return to the project asset list."
        />
      ) : null}

      {assetsLoading ? (
        <VpwTableCard
          className="assets-table-card"
          description="Loading the asset rows for the selected project and filters."
          title="Asset register"
        >
          <VpwSkeletonStack rows={6} />
        </VpwTableCard>
      ) : null}

      {children}
    </VpwSection>
  )
}

function labelizeFilter(value: string) {
  return value
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ")
}
