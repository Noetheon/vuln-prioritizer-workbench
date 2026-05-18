import { Link } from "@/lib/router"
import {
  ChevronRight,
  Database,
  FileJson,
  FileText,
  History,
  ListChecks,
  Network,
  Plus,
  ScanLine,
  TableProperties,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  VpwGrid,
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
    <div className="imports-page-shell flex w-full min-w-0 flex-col gap-6">
      <VpwSection>
        <div className="flex flex-wrap justify-end gap-2">
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
        </div>
        <VpwGrid columns={3}>
          <VpwMetricCard
            description={props.selectedProject ? "Active project" : "No project selected"}
            icon={<ListChecks aria-hidden="true" className="h-4 w-4" />}
            label="Current project"
            tone={props.selectedProject ? "neutral" : "warning"}
            value={props.selectedProject?.name ?? "Required"}
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
          <div className="grid gap-3">
            {[
              ["1", "Choose source", "Select project and input type."],
              ["2", "Upload file", "Attach the main evidence file."],
              [
                "3",
                "Add context (optional)",
                "Add asset context, VEX, or reviewed ATT&CK context.",
              ],
              ["4", "Review import", "Check readiness and start the run."],
            ].map(([number, title, description]) => (
              <Link
                className="group flex items-center gap-4 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-4 py-3 text-sm transition-colors hover:border-[var(--vpw-border-strong)] hover:bg-[var(--vpw-bg-panel)]"
                key={number}
                search={projectSearch}
                to="/imports/new"
              >
                <span className="grid size-6 shrink-0 place-items-center rounded-full bg-[var(--vpw-green)] font-mono text-xs font-semibold text-[var(--vpw-bg-card)]">
                  {number}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block font-semibold text-[var(--vpw-text-primary)]">
                    {title}
                  </span>
                  <span className="block text-sm text-[var(--vpw-text-secondary)]">
                    {description}
                  </span>
                </span>
                <ChevronRight
                  aria-hidden="true"
                  className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-hover:translate-x-0.5"
                />
              </Link>
            ))}
          </div>
        </VpwPanel>
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader
            description={`${SUPPORTED_IMPORT_FORMATS.length} supported input types grouped by evidence source.`}
            title="Supported formats"
          />
          <div className="grid gap-2 text-sm text-[var(--vpw-text-secondary)]">
            {[
              {
                description: "CVE lists, CSV files",
                icon: FileText,
                label: "Simple inputs",
              },
              {
                description: "Trivy, Grype, Dependency-Check, GitHub alerts",
                icon: ScanLine,
                label: "Scanner exports",
              },
              {
                description: "CycloneDX, SPDX",
                icon: FileJson,
                label: "SBOM / dependency data",
              },
              {
                description: "Nessus XML, OpenVAS XML",
                icon: Network,
                label: "Network scanner exports",
              },
            ].map(({ description, icon: Icon, label }) => (
                <div
                  className="flex items-start gap-3 border-b border-[var(--vpw-border-subtle)] py-2 last:border-b-0"
                  key={label}
                >
                  <Icon
                    aria-hidden="true"
                    className="mt-0.5 size-4 shrink-0 text-[var(--vpw-green)]"
                  />
                  <span className="min-w-0">
                    <span className="block font-semibold text-[var(--vpw-text-primary)]">
                      {label}
                    </span>
                    <span className="block text-xs leading-5">{description}</span>
                  </span>
                </div>
              ))}
          </div>
          <Button asChild size="sm" variant="outline">
            <Link search={projectSearch} to="/imports/formats">
              View all formats and requirements
              <ChevronRight aria-hidden="true" data-icon="inline-end" />
            </Link>
          </Button>
        </VpwPanel>
      </div>
    </div>
  )
}
