import { Link } from "@tanstack/react-router"
import { CheckCircle2, History, PackageCheck, Upload } from "lucide-react"
import type { AnalysisRunPublic, ImportParseErrorPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwDemoBanner,
  VpwEmptyState,
  VpwField,
  VpwGrid,
  VpwImportStepCard,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPageContainer,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { formatProviderFreshness } from "@/lib/provider-format"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import { runStatusLabel } from "@/lib/risk-format"
import {
  failedRunCause,
  formatDateTime,
  formatDisplayType,
  formatExpectedFields,
  jsonPreview,
  metadataRows,
  runFileLabel,
  runTone,
  selectedFormat,
  type ImportsWorkbenchProps,
  uploadProgress,
} from "./imports-workbench-model"

function ImportHero({
  importWizard,
  projectRuns,
  providerStatus,
  selectedProject,
}: Pick<
  ImportsWorkbenchProps,
  "importWizard" | "projectRuns" | "providerStatus" | "selectedProject"
>) {
  const providerSummary = providerStatus
    ? formatProviderFreshness(providerStatus)
    : null
  const isDemo = DEMO_MODE_ENABLED && !selectedProject

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          isDemo ? <VpwBadge tone="warning">Demo preview</VpwBadge> : null
        }
        description="Normalize scanner, SBOM, and CVE-list inputs into prioritized findings."
        eyebrow="Imports"
        title="Imports"
      />
      {isDemo ? (
        <VpwDemoBanner>
          <strong>Demo preview.</strong> Select or create a project before
          uploading production import files.
        </VpwDemoBanner>
      ) : null}
      <VpwGrid columns={4}>
        <VpwMetricCard
          description={selectedProject?.name ?? "No project selected"}
          icon={<PackageCheck aria-hidden="true" className="h-4 w-4" />}
          label="Current project"
          tone={selectedProject ? "success" : "warning"}
          value={selectedProject ? "Ready" : "Required"}
        />
        <VpwMetricCard
          description={providerSummary?.detail ?? "Provider status loading"}
          icon={<CheckCircle2 aria-hidden="true" className="h-4 w-4" />}
          label="Provider snapshot"
          tone={providerStatus?.status === "ok" ? "success" : "info"}
          value={providerSummary?.value ?? "Checking"}
        />
        <VpwMetricCard
          description="Historical import runs"
          icon={<History aria-hidden="true" className="h-4 w-4" />}
          label="Run history"
          tone="info"
          value={projectRuns.length}
        />
        <VpwMetricCard
          description={formatDisplayType(importWizard.inputType)}
          icon={<Upload aria-hidden="true" className="h-4 w-4" />}
          label="Selected format"
          tone={importWizard.file ? "success" : "neutral"}
          value={importWizard.file ? "File ready" : "Waiting"}
        />
      </VpwGrid>
    </VpwSection>
  )
}

function ImportWizard({
  importError,
  importLoading,
  importWizard,
  onAssetContextFileChange,
  onFileChange,
  onInputTypeChange,
  onProjectChange,
  onSubmit,
  onVexFileChange,
  projectListLoading,
  projects,
  selectedProjectId,
  supportedFormats,
}: Pick<
  ImportsWorkbenchProps,
  | "importError"
  | "importLoading"
  | "importWizard"
  | "onAssetContextFileChange"
  | "onFileChange"
  | "onInputTypeChange"
  | "onProjectChange"
  | "onSubmit"
  | "onVexFileChange"
  | "projectListLoading"
  | "projects"
  | "selectedProjectId"
  | "supportedFormats"
>) {
  const format = selectedFormat(supportedFormats, importWizard.inputType)
  const stepCards = [
    {
      title: "Select project",
      description: "Choose the workspace that owns the imported findings.",
      status: selectedProjectId ? "Ready" : "Required",
      statusTone: selectedProjectId ? "success" : "warning",
    },
    {
      title: "Select input type",
      description: "Match parser behavior to the file format.",
      status: format?.label ?? "Required",
      statusTone: "info",
    },
    {
      title: "Upload file",
      description: "Attach the source file that should become findings.",
      status: importWizard.file ? "Ready" : "Required",
      statusTone: importWizard.file ? "success" : "warning",
    },
    {
      title: "Validate and import",
      description:
        "The backend validates format, parses input, and records run evidence.",
      status: importLoading ? "Running" : "Ready",
      statusTone: importLoading ? "info" : "neutral",
    },
  ] as const

  return (
    <VpwSection>
      <VpwSectionHeader
        description="Step through project, format, files, and validation before import."
        title="Import Wizard"
      />
      <VpwGrid columns={4}>
        {stepCards.map((step) => (
          <VpwImportStepCard
            description={step.description}
            key={step.title}
            status={step.status}
            statusTone={step.statusTone}
            title={step.title}
          />
        ))}
      </VpwGrid>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(20rem,0.75fr)]">
        <VpwPanel>
          <form className="space-y-5" onSubmit={onSubmit}>
            <VpwToolbar label="Import controls">
              <VpwToolbarGroup>
                <VpwBadge tone={importWizard.file ? "success" : "neutral"}>
                  {importWizard.file ? "Source attached" : "Source required"}
                </VpwBadge>
                {importWizard.assetContextFile ? (
                  <VpwBadge tone="info">Asset context</VpwBadge>
                ) : null}
                {importWizard.vexFile ? (
                  <VpwBadge tone="support">VEX sidecar</VpwBadge>
                ) : null}
              </VpwToolbarGroup>
            </VpwToolbar>
            <div className="grid gap-4 lg:grid-cols-2">
              <VpwField label="Project" required>
                <Select
                  disabled={projectListLoading || projects.length === 0}
                  name="importProject"
                  onValueChange={onProjectChange}
                  value={selectedProjectId}
                >
                  <SelectTrigger aria-label="Import project">
                    <SelectValue placeholder="Select project" />
                  </SelectTrigger>
                  <SelectContent>
                    {projects.length === 0 ? (
                      <SelectItem disabled value="none">
                        No projects
                      </SelectItem>
                    ) : null}
                    {projects.map((project) => (
                      <SelectItem key={project.id} value={project.id}>
                        {project.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </VpwField>
              <VpwField
                description={format?.detail}
                label="Input type"
                required
              >
                <Select
                  name="inputType"
                  onValueChange={onInputTypeChange}
                  value={importWizard.inputType}
                >
                  <SelectTrigger aria-label="Input type">
                    <SelectValue placeholder="Select format" />
                  </SelectTrigger>
                  <SelectContent>
                    {supportedFormats.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </VpwField>
            </div>
            <VpwField
              description={`Accepted: ${format?.accept ?? "supported files"}`}
              label="Import file"
              required
            >
              <input
                accept={format?.accept}
                aria-label="Import file"
                className="w-full rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-3 py-2 text-sm"
                name="importFile"
                onChange={(event) =>
                  onFileChange(event.target.files?.[0] ?? null)
                }
                type="file"
              />
            </VpwField>
            <div className="grid gap-4 lg:grid-cols-2">
              <VpwField
                description="Optional CSV with target_kind, target_ref, asset_id, owner, service, exposure."
                label="Asset context CSV"
              >
                <input
                  accept=".csv,text/csv"
                  aria-label="Asset context CSV"
                  className="w-full rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-3 py-2 text-sm"
                  name="assetContextFile"
                  onChange={(event) =>
                    onAssetContextFileChange(event.target.files?.[0] ?? null)
                  }
                  type="file"
                />
              </VpwField>
              <VpwField
                description="Optional OpenVEX or CycloneDX VEX JSON sidecar."
                label="OpenVEX / VEX JSON"
              >
                <input
                  accept=".json,application/json"
                  aria-label="OpenVEX/VEX JSON"
                  className="w-full rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-3 py-2 text-sm"
                  name="vexFile"
                  onChange={(event) =>
                    onVexFileChange(event.target.files?.[0] ?? null)
                  }
                  type="file"
                />
              </VpwField>
            </div>
            <VpwProgress
              label="Import readiness"
              tone={importWizard.file && selectedProjectId ? "success" : "info"}
              value={uploadProgress(importWizard)}
            />
            {importError ? (
              <VpwStatusBanner title="Import upload failed" tone="critical">
                {importError}
              </VpwStatusBanner>
            ) : null}
            {importLoading ? (
              <VpwStatusBanner title="Uploading and parsing import file">
                Backend validation and normalization are running.
              </VpwStatusBanner>
            ) : null}
            <Button
              aria-busy={importLoading}
              disabled={importLoading || projects.length === 0}
              type="submit"
            >
              <Upload aria-hidden="true" className="h-4 w-4" />
              {importLoading ? "Uploading" : "Upload Import"}
            </Button>
          </form>
        </VpwPanel>
        <VpwPanel>
          <VpwSectionHeader
            description="Files are accepted only when they match the selected parser."
            title="Upload Security Notes"
          />
          <VpwKeyValueList
            items={[
              {
                label: "Parsing",
                value: "Workbench backend",
                description: "Files are parsed locally by Workbench services.",
                tone: "info",
              },
              {
                label: "Unsupported formats",
                value: "Rejected",
                description:
                  "Uploads must match the selected format and extension.",
                tone: "warning",
              },
              {
                label: "Evidence handling",
                value: "Configured",
                description:
                  "Original inputs may be included in evidence only when configured.",
                tone: "neutral",
              },
              {
                label: "Network activity",
                value: "No scanning",
                description:
                  "The import wizard does not run probes or scanners.",
                tone: "success",
              },
            ]}
          />
        </VpwPanel>
      </div>
    </VpwSection>
  )
}

function SupportedFormats({
  importWizard,
  onInputTypeChange,
  supportedFormats,
}: Pick<
  ImportsWorkbenchProps,
  "importWizard" | "onInputTypeChange" | "supportedFormats"
>) {
  return (
    <VpwSection>
      <VpwSectionHeader
        description="Supported source formats and parser expectations."
        title="Supported Input Formats"
      />
      <VpwGrid columns={4}>
        {supportedFormats.map((format) => (
          <VpwSelectionCard
            checked={format.value === importWizard.inputType}
            key={format.value}
            meta={format.accept}
            onClick={() => onInputTypeChange(format.value)}
            title={format.label}
          >
            <div className="space-y-2">
              <p>{format.detail}</p>
              <p className="text-xs">
                Expected: {formatExpectedFields(format.value)}
              </p>
            </div>
          </VpwSelectionCard>
        ))}
        <VpwSelectionCard
          checked={Boolean(importWizard.vexFile)}
          meta=".json, application/json"
          title="OpenVEX / VEX sidecar"
        >
          <div className="space-y-2">
            <p>
              Optional VEX JSON sidecar attached to occurrence or SBOM imports.
            </p>
            <p className="text-xs">
              Expected: OpenVEX statements or CycloneDX VEX vulnerability status
              data.
            </p>
          </div>
        </VpwSelectionCard>
      </VpwGrid>
    </VpwSection>
  )
}

function ImportResult({
  importRun,
  importRunSummary,
}: Pick<ImportsWorkbenchProps, "importRun" | "importRunSummary">) {
  if (!importRun && !importRunSummary) return null

  const summaryRun = importRunSummary ?? importRun
  const status = summaryRun?.status ?? "pending"
  const runId = summaryRun?.id ?? importRun?.id ?? ""

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          <VpwBadge tone={runTone(status)}>{runStatusLabel(status)}</VpwBadge>
        }
        description="Latest completed import result from the current session."
        title="Import Result"
      />
      <VpwPanel>
        <VpwGrid columns={4}>
          <VpwMetricCard
            description={runId ? `Run ${runId.slice(0, 8)}` : "Run pending"}
            icon={<CheckCircle2 aria-hidden="true" className="h-4 w-4" />}
            label="Run status"
            tone={runTone(status) === "critical" ? "critical" : "success"}
            value={runStatusLabel(status)}
          />
          <VpwMetricCard
            description="New findings"
            label="Created findings"
            tone="info"
            value={importRunSummary?.created_findings ?? 0}
          />
          <VpwMetricCard
            description="Existing findings"
            label="Updated findings"
            tone="support"
            value={importRunSummary?.updated_findings ?? 0}
          />
          <VpwMetricCard
            description={runId ? runId : "N.A."}
            label="Ignored lines"
            tone="warning"
            value={importRunSummary?.ignored_lines ?? 0}
          />
        </VpwGrid>
        <div className="mt-5 flex flex-wrap gap-2">
          <Button asChild variant="outline">
            <Link to="/findings">View Findings</Link>
          </Button>
          <Button asChild variant="outline">
            <Link to="/reports">Generate Evidence</Link>
          </Button>
        </div>
      </VpwPanel>
    </VpwSection>
  )
}

function ParserErrors({ errors }: { errors: ImportParseErrorPublic[] }) {
  if (errors.length === 0) return null

  const columns: VpwDataTableColumn<ImportParseErrorPublic>[] = [
    { id: "line", header: "Line", cell: (error) => error.line ?? "N.A." },
    { id: "field", header: "Field", cell: (error) => error.field ?? "N.A." },
    { id: "value", header: "Value", cell: (error) => error.value ?? "N.A." },
    { id: "message", header: "Message", cell: (error) => error.message },
  ]

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={<VpwBadge tone="critical">{errors.length} issue(s)</VpwBadge>}
        description="Rows rejected during parser validation."
        title="Parser Errors"
      />
      <VpwDataTable
        caption="Parser errors"
        columns={columns}
        data={errors}
        getRowKey={(error, index) =>
          [error.filename, error.line, error.field, error.value, index].join(
            ":",
          )
        }
      />
    </VpwSection>
  )
}

function RecentImports({
  onRefreshRuns,
  onSelectRun,
  projectRuns,
  runDetailError,
  runDetailLoading,
  runsError,
  runsLoading,
  selectedProject,
  selectedRun,
  selectedRunId,
  selectedRunSummary,
}: Pick<
  ImportsWorkbenchProps,
  | "onRefreshRuns"
  | "onSelectRun"
  | "projectRuns"
  | "runDetailError"
  | "runDetailLoading"
  | "runsError"
  | "runsLoading"
  | "selectedProject"
  | "selectedRun"
  | "selectedRunId"
  | "selectedRunSummary"
>) {
  const columns: VpwDataTableColumn<AnalysisRunPublic>[] = [
    {
      id: "run",
      header: "Run",
      cell: (run) => (
        <button
          className="text-left font-mono text-sm font-medium text-[var(--vpw-blue)]"
          onClick={() => onSelectRun(run.id)}
          type="button"
        >
          {run.id.slice(0, 8)}
        </button>
      ),
    },
    { id: "file", header: "Input file", cell: (run) => runFileLabel(run) },
    {
      id: "type",
      header: "Input type",
      cell: (run) => (
        <VpwBadge tone="info">{formatDisplayType(run.input_type)}</VpwBadge>
      ),
    },
    {
      id: "status",
      header: "Status",
      cell: (run) => (
        <VpwBadge tone={runTone(run.status)}>
          {runStatusLabel(run.status)}
        </VpwBadge>
      ),
    },
    {
      id: "findings",
      header: "Findings",
      cell: (run) =>
        selectedRunId === run.id && selectedRunSummary
          ? `${selectedRunSummary.created_findings ?? 0} created / ${
              selectedRunSummary.updated_findings ?? 0
            } updated`
          : "Select for counts",
    },
    {
      id: "started",
      header: "Timestamp",
      cell: (run) => formatDateTime(run.started_at),
    },
    {
      id: "actions",
      header: "Actions",
      className: "text-right",
      headerClassName: "text-right",
      cell: (run) => (
        <Button
          onClick={() => onSelectRun(run.id)}
          size="sm"
          type="button"
          variant={selectedRunId === run.id ? "default" : "outline"}
        >
          {selectedRunId === run.id ? "Selected" : "Inspect"}
        </Button>
      ),
    },
  ]

  return (
    <VpwSection>
      <VpwSectionHeader
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
        description={selectedProject?.name ?? "No project selected"}
        title="Recent Imports"
      />
      {runsError ? (
        <VpwStatusBanner title="Import runs unavailable" tone="critical">
          {runsError}
        </VpwStatusBanner>
      ) : null}
      {runsLoading ? (
        <VpwPanel>
          <VpwSkeletonStack rows={4} />
        </VpwPanel>
      ) : (
        <VpwDataTable
          caption="Recent import runs"
          columns={columns}
          data={projectRuns}
          emptyState={
            <VpwEmptyState
              description="Upload a supported file to create import run history."
              icon={<History aria-hidden="true" className="h-5 w-5" />}
              title="No import runs yet"
            />
          }
          getRowKey={(run) => run.id}
        />
      )}
      <RunDetail
        runDetailError={runDetailError}
        runDetailLoading={runDetailLoading}
        selectedRun={selectedRun}
        selectedRunId={selectedRunId}
        selectedRunSummary={selectedRunSummary}
      />
    </VpwSection>
  )
}

function RunDetail({
  runDetailError,
  runDetailLoading,
  selectedRun,
  selectedRunId,
  selectedRunSummary,
}: Pick<
  ImportsWorkbenchProps,
  | "runDetailError"
  | "runDetailLoading"
  | "selectedRun"
  | "selectedRunId"
  | "selectedRunSummary"
>) {
  if (runDetailLoading) {
    return (
      <VpwPanel>
        <VpwSkeletonStack rows={4} />
      </VpwPanel>
    )
  }

  if (runDetailError) {
    return (
      <VpwStatusBanner title="Run detail unavailable" tone="critical">
        {runDetailError}
      </VpwStatusBanner>
    )
  }

  if (!selectedRunId) {
    return (
      <VpwEmptyState
        description="Select a historical import run to inspect details."
        title="No run selected"
      />
    )
  }

  if (!selectedRun || !selectedRunSummary) return null

  const metadata = metadataRows(selectedRunSummary.input_upload).map(
    ([label, value]) => ({
      label,
      value: String(value),
    }),
  )
  const selectedParseErrors = selectedRunSummary.parse_errors ?? []

  return (
    <VpwPanel className="space-y-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="vpw-label">Run detail</p>
          <h3 className="mt-1 text-lg font-semibold text-[var(--vpw-text-primary)]">
            {selectedRunId.slice(0, 8)}
          </h3>
        </div>
        <Button asChild size="sm" variant="outline">
          <Link to="/findings">Findings</Link>
        </Button>
      </div>
      <VpwKeyValueList
        columns={2}
        items={[
          {
            label: "Status",
            value: runStatusLabel(selectedRunSummary.status),
            tone: runTone(selectedRunSummary.status),
          },
          {
            label: "Input type",
            value: formatDisplayType(selectedRunSummary.input_type),
          },
          { label: "Filename", value: runFileLabel(selectedRunSummary) },
          {
            label: "Started",
            value: formatDateTime(selectedRunSummary.started_at),
          },
          {
            label: "Finished",
            value: formatDateTime(selectedRunSummary.finished_at),
          },
          {
            label: "Provider snapshot",
            value: selectedRunSummary.provider_snapshot_id ?? "N.A.",
          },
        ]}
      />
      <VpwGrid columns={4}>
        <VpwMetricCard
          label="Created"
          value={selectedRunSummary.created_findings ?? 0}
        />
        <VpwMetricCard
          label="Updated"
          value={selectedRunSummary.updated_findings ?? 0}
        />
        <VpwMetricCard
          label="Findings"
          value={selectedRunSummary.finding_count ?? 0}
        />
        <VpwMetricCard
          label="Ignored"
          value={selectedRunSummary.ignored_lines ?? 0}
        />
      </VpwGrid>
      {selectedRunSummary.status === "failed" ? (
        <VpwStatusBanner title="Failure Cause" tone="critical">
          <p>{failedRunCause(selectedRun, selectedRunSummary)}</p>
          <pre className="mt-3 max-h-64 overflow-auto rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-card)] p-3 text-xs">
            {jsonPreview(selectedRunSummary.error_json)}
          </pre>
        </VpwStatusBanner>
      ) : null}
      <VpwSectionHeader title="Upload Metadata" />
      {metadata.length > 0 ? (
        <VpwKeyValueList columns={2} items={metadata} />
      ) : (
        <VpwEmptyState title="No upload metadata recorded" />
      )}
      <VpwSectionHeader
        actions={
          selectedParseErrors.length > 0 ? (
            <VpwBadge tone="critical">
              {selectedParseErrors.length} parser issue(s)
            </VpwBadge>
          ) : (
            <VpwBadge tone="success">No parser errors</VpwBadge>
          )
        }
        title="Run Parser Errors"
      />
      {selectedParseErrors.length > 0 ? (
        <ParserErrors errors={selectedParseErrors} />
      ) : (
        <VpwEmptyState title="No parser errors recorded" />
      )}
    </VpwPanel>
  )
}

export function ImportsWorkbench(props: ImportsWorkbenchProps) {
  const hasProject = Boolean(props.selectedProjectId)

  return (
    <VpwPageContainer className="space-y-8 px-0 py-0">
      <ImportHero
        importWizard={props.importWizard}
        projectRuns={props.projectRuns}
        providerStatus={props.providerStatus}
        selectedProject={props.selectedProject}
      />
      {!hasProject && !props.projectListLoading ? (
        <VpwStatusBanner title="Project required" tone="warning">
          Create or select a project before uploading import files.
        </VpwStatusBanner>
      ) : null}
      <ImportWizard {...props} />
      <SupportedFormats
        importWizard={props.importWizard}
        onInputTypeChange={props.onInputTypeChange}
        supportedFormats={props.supportedFormats}
      />
      <ImportResult
        importRun={props.importRun}
        importRunSummary={props.importRunSummary}
      />
      <ParserErrors errors={props.importParseErrors} />
      <RecentImports {...props} />
    </VpwPageContainer>
  )
}
