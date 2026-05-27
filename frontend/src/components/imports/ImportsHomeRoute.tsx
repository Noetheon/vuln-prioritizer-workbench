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
  VpwCommandPanel,
  MetricStrip,
  type MetricStripMetric,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import { formatProviderFreshness } from "@/lib/provider-format"
import { runStatusLabel } from "@/lib/risk-format"
import { supportedImportCategories } from "@/lib/import-format-metadata"
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
  const formatCategories = supportedImportCategories(props.supportedFormats)
  const capabilitiesUnavailable =
    Boolean(props.capabilitiesError) ||
    (!props.capabilitiesLoading && props.supportedFormats.length === 0)
  const categoryIcons = {
    network: Network,
    sbom: FileJson,
    scanner: ScanLine,
    simple: FileText,
  } as const
  const metrics: MetricStripMetric[] = [
    {
      description: props.selectedProject
        ? "Active project"
        : "No project selected",
      icon: <ListChecks aria-hidden="true" className="h-4 w-4" />,
      label: "Current project",
      tone: props.selectedProject ? "info" : "warning",
      value: props.selectedProject?.name ?? "Required",
    },
    {
      description: providerSummary.detail,
      icon: <Database aria-hidden="true" className="h-4 w-4" />,
      label: "Provider data",
      tone: props.providerStatus?.status === "ok" ? "success" : "warning",
      value: providerSummary.value,
    },
    {
      description: lastRun
        ? `${runFileLabel(lastRun)} - ${formatDateTime(lastRun.started_at)}`
        : "No import run recorded yet",
      icon: <History aria-hidden="true" className="h-4 w-4" />,
      label: "Last import",
      tone: lastRun?.status ? runTone(lastRun.status) : "info",
      value: lastRun ? runStatusLabel(lastRun.status) : "None yet",
    },
  ]

  return (
    <div className="imports-page-shell vpw-page-stack w-full min-w-0">
      <VpwSection>
        <VpwCommandPanel
          actions={
            <div className="flex flex-wrap justify-end gap-2">
              <Button asChild variant="outline">
                <Link search={projectSearch} to="/imports/formats">
                  <TableProperties
                    aria-hidden="true"
                    data-icon="inline-start"
                  />
                  Supported formats
                </Link>
              </Button>
              {capabilitiesUnavailable ? (
                <Button disabled>
                  <Plus aria-hidden="true" data-icon="inline-start" />
                  New import
                </Button>
              ) : (
                <Button asChild>
                  <Link search={projectSearch} to="/imports/new">
                    <Plus aria-hidden="true" data-icon="inline-start" />
                    New import
                  </Link>
                </Button>
              )}
            </div>
          }
          description="Load scanner, SBOM, CVE, and network evidence into the selected workbench project."
          eyebrow="Evidence intake"
          title="Import workspace"
        >
          <MetricStrip metrics={metrics} minCardWidth="13rem" />
        </VpwCommandPanel>
      </VpwSection>

      <RecentImports {...props} onOpenDiagnostics={props.onOpenDiagnostics} />

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
                className="group grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 border-b border-[var(--vpw-border-subtle)] px-2 py-3 text-sm transition-colors last:border-b-0 hover:bg-[var(--vpw-bg-panel)]"
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
            description={`${props.supportedFormats.length} supported input types grouped by evidence source.`}
            title="Supported formats"
          />
          <div className="grid gap-2 text-sm text-[var(--vpw-text-secondary)]">
            {formatCategories.map(({ category, label }) => {
              const Icon =
                categoryIcons[category as keyof typeof categoryIcons] ?? FileText
              const formatCount = props.supportedFormats.filter(
                (format) => format.category === category,
              ).length
              return (
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
                  <span className="block text-xs leading-5">
                    {formatCount} supported format{formatCount === 1 ? "" : "s"}
                  </span>
                </span>
              </div>
              )
            })}
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
