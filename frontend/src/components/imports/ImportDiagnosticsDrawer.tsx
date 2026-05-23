import { Link } from "@/lib/router"
import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  DetailDrawer,
  VpwEmptyState,
  VpwPanel,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { ImportDiagnosticsDrawerTabs } from "./ImportDiagnosticsDrawerTabs"

type ImportDiagnosticsDrawerProps = {
  diagnosticsOpen: boolean
  diagnosticsRunId: string
  onDiagnosticsOpenChange: (open: boolean) => void
  runDetailError: string
  runDetailLoading: boolean
  selectedRun: AnalysisRunPublic | null
  selectedRunId: string
  selectedRunSummary: AnalysisRunSummaryPublic | null
}

export function ImportDiagnosticsDrawer({
  diagnosticsOpen,
  diagnosticsRunId,
  onDiagnosticsOpenChange,
  runDetailError,
  runDetailLoading,
  selectedRun,
  selectedRunId,
  selectedRunSummary,
}: ImportDiagnosticsDrawerProps) {
  const waitingForSelectedRun = Boolean(
    diagnosticsRunId && selectedRunId !== diagnosticsRunId,
  )

  return (
    <DetailDrawer
      className="w-screen max-w-none max-sm:left-0 max-sm:right-0 max-sm:w-auto max-sm:max-w-none sm:w-[600px] sm:max-w-[640px]"
      description={`Run ID ${diagnosticsRunId ? diagnosticsRunId.slice(0, 8) : "not selected"}`}
      footer={
        selectedRunSummary ? (
          <>
            <Button asChild size="sm" variant="outline">
              <Link
                search={{ projectId: selectedRunSummary.project_id }}
                to="/findings"
              >
                Review findings
              </Link>
            </Button>
            <Button asChild size="sm">
              <Link
                params={{ runId: selectedRunSummary.id }}
                search={{ projectId: selectedRunSummary.project_id }}
                to="/imports/runs/$runId"
              >
                Open run detail
              </Link>
            </Button>
          </>
        ) : null
      }
      onOpenChange={onDiagnosticsOpenChange}
      open={diagnosticsOpen}
      title="Run diagnostics"
    >
      {waitingForSelectedRun || runDetailLoading ? (
        <VpwPanel>
          <VpwSkeletonStack rows={5} />
        </VpwPanel>
      ) : runDetailError ? (
        <VpwStatusBanner title="Run detail unavailable" tone="critical">
          {runDetailError}
        </VpwStatusBanner>
      ) : selectedRun && selectedRunSummary ? (
        <ImportDiagnosticsDrawerTabs
          run={selectedRun}
          summary={selectedRunSummary}
        />
      ) : (
        <VpwEmptyState
          description="Select an import run to inspect parser, upload, provider, and raw metadata."
          title="No run selected"
        />
      )}
    </DetailDrawer>
  )
}
