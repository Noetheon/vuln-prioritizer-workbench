import { Upload } from "lucide-react"
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
  VpwField,
  VpwGrid,
  VpwImportStepCard,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import {
  formatExpectedFields,
  type ImportsWorkbenchProps,
  selectedFormat,
  uploadProgress,
} from "./imports-workbench-model"

export function ImportWizard({
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

export function SupportedFormats({
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
