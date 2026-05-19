import { Link } from "@/lib/router"
import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import {
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
    <Sheet open={diagnosticsOpen} onOpenChange={onDiagnosticsOpenChange}>
      <SheetContent className="vpw-sheet-content h-[100dvh] w-screen max-w-none gap-0 overflow-hidden p-0 max-sm:left-0 max-sm:right-0 max-sm:w-auto max-sm:max-w-none sm:w-[600px] sm:max-w-[640px]">
        <SheetHeader className="shrink-0 border-b border-[var(--vpw-border-subtle)] px-5 py-4 pr-12 text-left">
          <SheetTitle>Run diagnostics</SheetTitle>
          <SheetDescription>
            Run ID {diagnosticsRunId ? diagnosticsRunId.slice(0, 8) : "not selected"}
          </SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
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
        </div>
        {selectedRunSummary ? (
          <SheetFooter className="sticky bottom-0 flex-col shrink-0 border-t border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] px-5 py-3 sm:flex-row sm:justify-between">
            <Button asChild size="sm" variant="outline">
              <Link search={{ projectId: selectedRunSummary.project_id }} to="/findings">
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
          </SheetFooter>
        ) : null}
      </SheetContent>
    </Sheet>
  )
}
