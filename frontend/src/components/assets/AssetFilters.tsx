import { BriefcaseBusiness, RefreshCw, Server } from "lucide-react"

import type { ProjectPublic } from "../../api-client"
import { Button } from "../ui/button"
import { Input } from "../ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select"
import {
  VpwEmptyState,
  VpwField,
  VpwFilterBar,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
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
  projectLoading,
  projects,
  projectSelectDisabled,
  refreshAssets,
  selectProject,
  selectedAssetId,
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
  projectLoading: boolean
  projects: ProjectPublic[]
  projectSelectDisabled: boolean
  refreshAssets: (preferredAssetId?: string) => Promise<void>
  selectProject: (projectId: string) => void
  selectedAssetId: string
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  setAssetOwnerFilter: (value: string) => void
  setAssetServiceFilter: (value: string) => void
}) {
  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          <Button
            disabled={projectSelectDisabled}
            onClick={() => void refreshAssets(selectedAssetId)}
            type="button"
            variant="outline"
          >
            <RefreshCw aria-hidden="true" />
            Refresh
          </Button>
        }
        description="Filter project assets by service and owner, then inspect the context that changes prioritization."
        eyebrow="In-scope assets"
        title="Asset inventory"
      />
      <VpwFilterBar
        actions={
          <Button
            disabled={!assetOwnerFilter && !assetServiceFilter}
            onClick={clearAssetFilters}
            type="button"
            variant="outline"
          >
            Clear filters
          </Button>
        }
        onSearchChange={setAssetServiceFilter}
        searchLabel="Asset service filter"
        searchPlaceholder="Filter by service"
        searchValue={assetServiceFilter}
      >
        <VpwField className="min-w-52" label="Owner">
          <Input
            aria-label="Asset owner filter"
            onChange={(event) => setAssetOwnerFilter(event.target.value)}
            placeholder="Filter owner"
            value={assetOwnerFilter}
          />
        </VpwField>
        <VpwField className="min-w-64" label="Project">
          <Select
            disabled={projectSelectDisabled}
            onValueChange={selectProject}
            value={selectedProjectId}
          >
            <SelectTrigger aria-label="Assets project">
              <SelectValue placeholder="Select project" />
            </SelectTrigger>
            <SelectContent>
              {projects.map((project) => (
                <SelectItem key={project.id} value={project.id}>
                  {project.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
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

      {!assetsLoading && selectedProject && !hasAssets ? (
        <VpwEmptyState
          action={
            <Button asChild variant="outline">
              <a href="#asset-context-import">Import asset context</a>
            </Button>
          }
          icon={<Server aria-hidden="true" />}
          title="No asset context yet"
          description="Import asset context to improve prioritization and ownership."
        />
      ) : null}

      {assetsLoading ? (
        <VpwPanel className="p-5">
          <VpwSkeletonStack rows={6} />
        </VpwPanel>
      ) : null}

      {children}
    </VpwSection>
  )
}
