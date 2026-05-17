import { Link } from "@/lib/router"
import { CheckCircle2, Database, History, ListChecks, Plus, TableProperties } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import { formatProviderFreshness } from "@/lib/provider-format"
import { runStatusLabel } from "@/lib/risk-format"
import { SUPPORTED_IMPORT_FORMATS } from "@/lib/import-format-metadata"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { RecentImports } from "./ImportsWorkbenchHistory"
import {
  formatDateTime,
  type ImportsWorkbenchProps,
  runFileLabel,
  runTone,
} from "./imports-workbench-model"

type ImportsHomeRouteProps = ImportsWorkbenchProps & {
  diagnosticsOpen: boolean
  diagnosticsRunId: string
  onDiagnosticsOpenChange: (open: boolean) => void
  onOpenDiagnostics: (runId: string) => void
}

export function ImportsHomeRoute(props: ImportsHomeRouteProps) {
  const providerSummary = formatProviderFreshness(props.providerStatus)
  const lastRun = props.projectRuns[0] ?? null
  const projectSearch = selectedProjectRouteSearch(props.selectedProjectId)

  return (
    <div className="imports-page-shell mx-auto flex w-full max-w-[1480px] flex-col gap-6">
      <VpwSection>
        <VpwSectionHeader
          actions={
            <>
              <Button asChild variant="outline">
                <Link search={projectSearch} to="/imports/formats">
                  <TableProperties aria-hidden="true" data-icon="inline-start" />
                  Supported formats
                </Link>
              </Button>
              <Button asChild>
                <Link search={projectSearch} to="/imports/new">
                  <Plus aria-hidden="true" data-icon="inline-start" />
                  New import
                </Link>
              </Button>
            </>
          }
          description="Bring supplied vulnerability evidence into the Workbench with a guided import flow."
          eyebrow="Prepare"
          title="Imports"
        />
        <VpwGrid columns={3}>
          <VpwMetricCard
            description={props.selectedProject?.name ?? "No project selected"}
            icon={<ListChecks aria-hidden="true" className="h-4 w-4" />}
            label="Current project"
            tone={props.selectedProject ? "neutral" : "warning"}
            value={props.selectedProject ? "Active project" : "Required"}
          />
          <VpwMetricCard
            description={providerSummary.detail}
            icon={<Database aria-hidden="true" className="h-4 w-4" />}
            label="Provider data"
            tone={props.providerStatus?.status === "ok" ? "success" : "warning"}
            value={providerSummary.value}
          />
          <VpwMetricCard
            description={
              lastRun
                ? `${runFileLabel(lastRun)} - ${formatDateTime(lastRun.started_at)}`
                : "No import run recorded yet"
            }
            icon={<History aria-hidden="true" className="h-4 w-4" />}
            label="Last import"
            tone={lastRun?.status ? runTone(lastRun.status) : "neutral"}
            value={lastRun ? runStatusLabel(lastRun.status) : "None yet"}
          />
        </VpwGrid>
      </VpwSection>

      <RecentImports
        {...props}
        onOpenDiagnostics={props.onOpenDiagnostics}
      />

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader
            description="A short path through the import flow."
            title="Quick start"
          />
          <VpwKeyValueList
            items={[
              {
                label: "1. Choose source",
                value: "Select project and input type.",
              },
              {
                label: "2. Upload file",
                value: "Attach the main evidence file.",
              },
              {
                label: "3. Add context",
                value: "Optionally add asset context, VEX, or reviewed ATT&CK context.",
              },
              {
                label: "4. Review import",
                value: "Check readiness and start the run.",
              },
            ]}
          />
        </VpwPanel>
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader
            description={`${SUPPORTED_IMPORT_FORMATS.length} supported input types.`}
            title="Supported formats"
          />
          <div className="grid gap-2 text-sm text-[var(--vpw-text-secondary)]">
            {["Simple inputs", "Scanner exports", "SBOM / dependency data", "Network scanner exports"].map(
              (category) => (
                <div
                  className="flex items-center justify-between gap-3 border-b border-[var(--vpw-border-subtle)] py-2 last:border-b-0"
                  key={category}
                >
                  <span>{category}</span>
                  <CheckCircle2
                    aria-hidden="true"
                    className="size-4 text-[var(--vpw-text-muted)]"
                  />
                </div>
              ),
            )}
          </div>
          <Button asChild size="sm" variant="outline">
            <Link search={projectSearch} to="/imports/formats">
              View format requirements
            </Link>
          </Button>
        </VpwPanel>
      </div>
    </div>
  )
}
