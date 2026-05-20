import { BriefcaseBusiness, RotateCcw, Server } from "lucide-react"

import type { ProjectPublic } from "../../api-client"
import { Button } from "../ui/button"
import {
  VpwEmptyState,
  VpwField,
  VpwFilterBar,
  VpwSection,
  VpwSectionHeader,
  VpwSearchControl,
  VpwSelectControl,
  VpwSkeletonStack,
  VpwTableCard,
} from "../vpw"
import { Link } from "@/lib/router"
import type { ReactNode } from "react"

export function AssetInventoryShell({
  assetOwnerFilter,
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
  setAssetOwnerFilter,
  setAssetServiceFilter,
}: {
  assetOwnerFilter: string
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
  setAssetOwnerFilter: (value: string) => void
  setAssetServiceFilter: (value: string) => void
}) {
  return (
    <VpwSection className="assets-inventory-shell">
      <VpwSectionHeader
        description="Filter by project context, then inspect the asset records that change prioritization."
        eyebrow="In-scope assets"
        title="Asset inventory"
      />
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
        onSearchChange={setAssetServiceFilter}
        searchClassName="vpw-filter-field--md"
        searchLabel="Asset service filter"
        searchPlaceholder="Filter by service"
        searchTitle="Service"
        searchValue={assetServiceFilter}
      >
        <VpwField className="vpw-filter-field--md" label="Owner">
          <VpwSearchControl
            aria-label="Asset owner filter"
            onChange={(event) => setAssetOwnerFilter(event.target.value)}
            placeholder="Filter by owner"
            value={assetOwnerFilter}
          />
        </VpwField>
        <Button
          aria-label="Reset asset filters"
          disabled={!assetOwnerFilter && !assetServiceFilter}
          onClick={clearAssetFilters}
          type="button"
          variant="outline"
        >
          <RotateCcw aria-hidden="true" />
          Reset
        </Button>
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

      {!assetsLoading && selectedProject && !hasAssets ? (
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
