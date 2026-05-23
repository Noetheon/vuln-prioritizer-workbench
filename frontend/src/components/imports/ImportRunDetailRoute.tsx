import { Link } from "@/lib/router"
import { FileSearch, ListChecks } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  VpwCommandPanel,
  VpwEmptyState,
  VpwCompactMetric,
  VpwMetricStrip,
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

  const projectSearch = selectedProjectRouteSearch(
    selectedRunSummary.project_id,
  )
  const reviewFindingsPrimary =
    (selectedRunSummary.finding_count ?? 0) > 0 ||
    (selectedRunSummary.created_findings ?? 0) > 0 ||
    (selectedRunSummary.updated_findings ?? 0) > 0

  return (
    <div className="imports-page-shell vpw-page-stack w-full min-w-0">
      <VpwSection>
        <VpwCommandPanel
          actions={
            <div className="flex flex-wrap justify-end gap-2">
              <Button
                onClick={() => onOpenDiagnostics(selectedRunId)}
                type="button"
                variant={reviewFindingsPrimary ? "outline" : "default"}
              >
                <FileSearch aria-hidden="true" data-icon="inline-start" />
                Diagnostics
              </Button>
              <Button
                asChild
                variant={reviewFindingsPrimary ? "default" : "outline"}
              >
                <Link search={projectSearch} to="/findings">
                  <ListChecks aria-hidden="true" data-icon="inline-start" />
                  Review findings
                </Link>
              </Button>
            </div>
          }
          description={`${formatDisplayType(selectedRunSummary.input_type)} - ${runFileLabel(selectedRunSummary)} - ${formatDateTime(selectedRunSummary.started_at)}`}
          eyebrow="Import run"
          title="Run evidence context"
        >
          <VpwMetricStrip minCardWidth="10rem">
            <VpwCompactMetric
              label="Status"
              tone={runTone(selectedRunSummary.status)}
              value={runStatusLabel(selectedRunSummary.status)}
            />
            <VpwCompactMetric
              label="Created findings"
              tone={
                (selectedRunSummary.created_findings ?? 0) > 0
                  ? "success"
                  : "info"
              }
              value={selectedRunSummary.created_findings ?? 0}
            />
            <VpwCompactMetric
              label="Updated findings"
              tone={
                (selectedRunSummary.updated_findings ?? 0) > 0
                  ? "info"
                  : "support"
              }
              value={selectedRunSummary.updated_findings ?? 0}
            />
            <VpwCompactMetric
              label="Ignored lines"
              tone={
                (selectedRunSummary.ignored_lines ?? 0) > 0
                  ? "warning"
                  : "success"
              }
              value={selectedRunSummary.ignored_lines ?? 0}
            />
          </VpwMetricStrip>
        </VpwCommandPanel>
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
