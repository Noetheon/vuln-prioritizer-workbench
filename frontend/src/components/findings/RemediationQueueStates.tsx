import { Link } from "@/lib/router"
import type { FindingPublic, ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwEmptyState,
  VpwPanel,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"

type RemediationQueueStatesProps = {
  activeFindingFilters: boolean
  displayFindings: FindingPublic[]
  findingsError: string
  hasError: boolean
  isDemo: boolean
  isLoading: boolean
  onClearFilters: () => void
  projects: ProjectPublic[]
  selectedProject: ProjectPublic | null
}

export function RemediationQueueStates({
  activeFindingFilters,
  displayFindings,
  findingsError,
  hasError,
  isDemo,
  isLoading,
  onClearFilters,
  projects,
  selectedProject,
}: RemediationQueueStatesProps) {
  return (
    <>
      {hasError ? (
        <VpwStatusBanner title="Findings unavailable" tone="critical">
          {findingsError}
        </VpwStatusBanner>
      ) : null}
      {isLoading ? (
        <VpwPanel aria-busy="true" aria-label="Loading findings" role="status">
          <VpwSkeletonStack rows={6} />
        </VpwPanel>
      ) : null}

      {!isLoading && !hasError && !isDemo && projects.length === 0 ? (
        <VpwEmptyState
          action={
            <Button asChild>
              <Link to="/projects">Create a project</Link>
            </Button>
          }
          ariaLabel="No projects empty state"
          description="Create a project before reviewing findings."
          title="No projects yet"
        />
      ) : null}

      {!isLoading &&
      !hasError &&
      !isDemo &&
      selectedProject &&
      displayFindings.length === 0 &&
      !activeFindingFilters ? (
        <VpwEmptyState
          action={
            <Button asChild>
              <Link to="/imports">Import data</Link>
            </Button>
          }
          ariaLabel="No findings empty state"
          description="Import scanner, SBOM, or CVE-list data to create findings."
          title={`No findings in ${selectedProject.name}`}
        />
      ) : null}

      {!isLoading &&
      !hasError &&
      displayFindings.length === 0 &&
      activeFindingFilters ? (
        <VpwEmptyState
          action={
            <Button onClick={onClearFilters} type="button" variant="outline">
              Clear filters
            </Button>
          }
          ariaLabel="No filter matches"
          description="Try broadening the server-side query."
          title="No findings match these filters"
        />
      ) : null}
    </>
  )
}
