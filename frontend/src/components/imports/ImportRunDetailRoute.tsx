import { Link } from "@/lib/router"
import { FileSearch, ListChecks } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  VpwEmptyState,
  VpwGrid,
  VpwMetricCard,
  VpwPanel,
  VpwSection,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { runStatusLabel } from "@/lib/risk-format"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  DiagnosticsTab,
  EvidenceTab,
  FindingsTab,
  MetadataTab,
  OverviewTab,
} from "./ImportRunDetailTabs"
import {
  formatDateTime,
  formatDisplayType,
  runFileLabel,
  runTone,
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"

type ImportRunDetailRouteProps = ImportsWorkbenchProps & {
  onOpenDiagnostics: (runId: string) => void
}

export function ImportRunDetailRoute({
  onOpenDiagnostics,
  runDetailError,
  runDetailLoading,
  selectedRun,
  selectedRunId,
  selectedRunSummary,
  selectedProject,
}: ImportRunDetailRouteProps) {
  if (runDetailLoading) {
    return (
      <div className="imports-page-shell w-full min-w-0">
        <VpwPanel>
          <VpwSkeletonStack rows={6} />
        </VpwPanel>
      </div>
    )
  }

  if (runDetailError) {
    return (
      <div className="imports-page-shell w-full min-w-0">
        <VpwStatusBanner title="Run detail unavailable" tone="critical">
          {runDetailError}
        </VpwStatusBanner>
      </div>
    )
  }

  if (!selectedRun || !selectedRunSummary) {
    return (
      <div className="imports-page-shell w-full min-w-0">
        <VpwEmptyState
          description="The selected import run could not be loaded."
          title="Import run not found"
        />
      </div>
    )
  }

  const projectSearch = selectedProjectRouteSearch(selectedRunSummary.project_id)
  const reviewFindingsPrimary =
    (selectedRunSummary.finding_count ?? 0) > 0 ||
    (selectedRunSummary.created_findings ?? 0) > 0 ||
    (selectedRunSummary.updated_findings ?? 0) > 0

  return (
    <div className="imports-page-shell flex w-full min-w-0 flex-col gap-6">
      <VpwSection>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-[var(--vpw-text-secondary)]">
            {formatDisplayType(selectedRunSummary.input_type)} ·{" "}
            {runFileLabel(selectedRunSummary)} ·{" "}
            {formatDateTime(selectedRunSummary.started_at)}
          </p>
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              onClick={() => onOpenDiagnostics(selectedRunId)}
              type="button"
              variant={reviewFindingsPrimary ? "outline" : "default"}
            >
              <FileSearch aria-hidden="true" data-icon="inline-start" />
              Diagnostics
            </Button>
            <Button asChild variant={reviewFindingsPrimary ? "default" : "outline"}>
              <Link search={projectSearch} to="/findings">
                <ListChecks aria-hidden="true" data-icon="inline-start" />
                Review findings
              </Link>
            </Button>
          </div>
        </div>
        <VpwGrid columns={4}>
          <VpwMetricCard
            label="Status"
            tone={runTone(selectedRunSummary.status)}
            value={runStatusLabel(selectedRunSummary.status)}
          />
          <VpwMetricCard
            label="Created findings"
            value={selectedRunSummary.created_findings ?? 0}
          />
          <VpwMetricCard
            label="Updated findings"
            value={selectedRunSummary.updated_findings ?? 0}
          />
          <VpwMetricCard
            label="Ignored lines"
            tone={(selectedRunSummary.ignored_lines ?? 0) > 0 ? "warning" : "neutral"}
            value={selectedRunSummary.ignored_lines ?? 0}
          />
        </VpwGrid>
      </VpwSection>

      <Tabs defaultValue="overview">
        <TabsList
          aria-label="Import run detail tabs"
          className="flex flex-wrap justify-start"
        >
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="findings">Review findings</TabsTrigger>
          <TabsTrigger value="diagnostics">Diagnostics</TabsTrigger>
          <TabsTrigger value="evidence">Evidence</TabsTrigger>
          <TabsTrigger value="metadata">Metadata</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <OverviewTab
            projectName={selectedProject?.name}
            run={selectedRun}
            summary={selectedRunSummary}
          />
        </TabsContent>
        <TabsContent value="findings">
          <FindingsTab summary={selectedRunSummary} />
        </TabsContent>
        <TabsContent value="diagnostics">
          <DiagnosticsTab run={selectedRun} summary={selectedRunSummary} />
        </TabsContent>
        <TabsContent value="evidence">
          <EvidenceTab run={selectedRun} summary={selectedRunSummary} />
        </TabsContent>
        <TabsContent value="metadata">
          <MetadataTab run={selectedRun} summary={selectedRunSummary} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
