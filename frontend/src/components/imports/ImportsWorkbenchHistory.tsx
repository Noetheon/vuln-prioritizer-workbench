import { History } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwSection,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwTableCard,
} from "@/components/vpw"
import { buildImportHistoryColumns } from "./ImportsWorkbenchHistoryColumns"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"

export function RecentImports({
  onOpenDiagnostics,
  onRefreshRuns,
  onSelectRun,
  projectRuns,
  runsError,
  runsLoading,
  selectedProject,
  selectedRunId,
  selectedRunSummary,
}: Pick<
  ImportsWorkbenchProps,
  | "onRefreshRuns"
  | "onSelectRun"
  | "projectRuns"
  | "runsError"
  | "runsLoading"
  | "selectedProject"
  | "selectedRunId"
  | "selectedRunSummary"
> & {
  onOpenDiagnostics: (runId: string) => void
}) {
  const columns = buildImportHistoryColumns({
    onOpenDiagnostics,
    onSelectRun,
    selectedRunId,
    selectedRunSummary,
  })
  const refreshDescription = runsLoading
    ? "Import runs are refreshing."
    : selectedProject
      ? selectedProject.name
      : "Select a project before refreshing imports."

  return (
    <VpwSection>
      <VpwTableCard
        actions={
          <Button
            disabled={runsLoading || !selectedProject}
            onClick={onRefreshRuns}
            size="sm"
            type="button"
            variant="outline"
          >
            Refresh
          </Button>
        }
        description={refreshDescription}
        title="Recent Imports"
      >
        {runsError ? (
          <VpwStatusBanner title="Import runs unavailable" tone="critical">
            {runsError}
          </VpwStatusBanner>
        ) : null}
        {runsLoading ? (
          <VpwSkeletonStack rows={4} />
        ) : (
          <VpwDataTable
            caption="Recent import runs"
            columns={columns}
            data={projectRuns}
            density="compact"
            emptyState={
              <VpwEmptyState
                description="Upload a supported file to create import run history."
                icon={<History aria-hidden="true" className="h-5 w-5" />}
                title="No import runs yet"
              />
            }
            getRowKey={(run) => run.id}
            minWidth="980px"
          />
        )}
      </VpwTableCard>
    </VpwSection>
  )
}
