import { Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  VpwAdvancedOptionsDisclosure,
  VpwBadge,
  VpwField,
  VpwFileInput,
  VpwProgress,
  VpwSection,
  VpwStatusBanner,
} from "@/components/vpw"
import { formatProviderFreshness } from "@/lib/provider-format"
import { ProviderAttackOptions } from "./ImportsWorkbenchProviderOptions"
import {
  type ImportsWorkbenchProps,
  selectedFormat,
  uploadProgress,
} from "./imports-workbench-model"

type FileUploadFieldProps = {
  accept: string | undefined
  className?: string
  description: string
  file: File | null
  id: string
  label: string
  name: string
  onFileChange: (file: File | null) => void
  required?: boolean
}

function FileUploadField({
  accept,
  className,
  description,
  file,
  id,
  label,
  name,
  onFileChange,
  required = false,
}: FileUploadFieldProps) {
  return (
    <VpwField
      description={
        <span className="grid gap-1">
          <span>{description}</span>
          <span className="font-medium text-[var(--vpw-text-secondary)]">
            {file ? `Selected: ${file.name}` : "No file selected"}
          </span>
        </span>
      }
      htmlFor={id}
      label={label}
      required={required}
    >
      <VpwFileInput
        accept={accept}
        className={className}
        file={file}
        id={id}
        label={label}
        name={name}
        onFileChange={onFileChange}
      />
    </VpwField>
  )
}

export function ImportWizard({
  importError,
  importLoading,
  importWizard,
  onAssetContextFileChange,
  onFileChange,
  onInputTypeChange,
  onLockedProviderDataChange,
  onProviderSnapshotFileChange,
  onProjectChange,
  onSubmit,
  onAttackMappingFileChange,
  onAttackSourceChange,
  onAttackTechniqueMetadataFileChange,
  onVexFileChange,
  providerStatus,
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
  | "onLockedProviderDataChange"
  | "onProviderSnapshotFileChange"
  | "onProjectChange"
  | "onSubmit"
  | "onAttackMappingFileChange"
  | "onAttackSourceChange"
  | "onAttackTechniqueMetadataFileChange"
  | "onVexFileChange"
  | "providerStatus"
  | "projectListLoading"
  | "projects"
  | "selectedProjectId"
  | "supportedFormats"
>) {
  const format = selectedFormat(supportedFormats, importWizard.inputType)
  const progress = uploadProgress(importWizard)
  const providerSummary = formatProviderFreshness(providerStatus)
  const hasAdvancedEvidence = Boolean(
    importWizard.assetContextFile ||
      importWizard.vexFile ||
      importWizard.providerSnapshotFile ||
      importWizard.lockedProviderData ||
      importWizard.attackMappingFile ||
      importWizard.attackTechniqueMetadataFile ||
      (importWizard.attackSource && importWizard.attackSource !== "none"),
  )
  const canSubmit =
    !importLoading && Boolean(selectedProjectId) && Boolean(importWizard.file)
  const steps = [
    {
      label: "Project",
      description: selectedProjectId ? "Scope selected" : "Choose scope",
      state: selectedProjectId ? "complete" : "warning",
    },
    {
      label: "Format",
      description: format?.label ?? "Parser required",
      state: format ? "complete" : "warning",
    },
    {
      label: "Source file",
      description: importWizard.file ? "Attached" : "Attach source",
      state: importWizard.file ? "complete" : "active",
    },
    {
      label: "Validate",
      description: importLoading ? "Import running" : "Create findings",
      state: importLoading ? "active" : canSubmit ? "pending" : "warning",
    },
  ] as const

  return (
    <VpwSection>
      <form
        className="imports-workspace"
        id="import-workflow"
        onSubmit={onSubmit}
      >
        <div className="imports-flow-panel">
          <div className="imports-flow-header">
            <div>
              <p className="imports-kicker">Import workflow</p>
              <h2>Validate and ingest source evidence</h2>
              <p>
                Select scope, choose parser, attach the source file, then run
                validation.
              </p>
            </div>
            <Button
              aria-busy={importLoading}
              disabled={!canSubmit || projects.length === 0}
              type="submit"
            >
              <Upload aria-hidden="true" data-icon="inline-start" />
              {importLoading ? "Uploading" : "Upload import"}
            </Button>
          </div>

          <WorkflowStepList steps={steps} />

          <div className="imports-form-grid">
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
                  <SelectGroup>
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
                  </SelectGroup>
                </SelectContent>
              </Select>
            </VpwField>
            <VpwField description={format?.detail} label="Parser" required>
              <Select
                name="inputType"
                onValueChange={onInputTypeChange}
                value={importWizard.inputType}
              >
                <SelectTrigger aria-label="Parser">
                  <SelectValue placeholder="Select format" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {supportedFormats.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </VpwField>
          </div>

          <FileUploadField
            accept={format?.accept}
            className="imports-file-input imports-source-file"
            description={`Accepted: ${format?.accept ?? "supported files"}`}
            file={importWizard.file}
            id="import-file"
            label="Source file"
            name="importFile"
            onFileChange={onFileChange}
            required
          />

          <VpwAdvancedOptionsDisclosure
            badge={
              hasAdvancedEvidence ? (
                <VpwBadge tone="info">Active</VpwBadge>
              ) : (
                <VpwBadge tone="neutral">Optional</VpwBadge>
              )
            }
            className="imports-advanced"
            description="Asset context, VEX, provider snapshot and ATT&CK evidence stay secondary until needed."
            open={hasAdvancedEvidence ? true : undefined}
            title="Advanced evidence controls"
          >
            <div className="flex flex-col gap-5">
              <div className="grid gap-4 lg:grid-cols-2">
                <FileUploadField
                  accept=".csv,text/csv"
                  className="imports-file-input"
                  description="Ownership, service and exposure context."
                  file={importWizard.assetContextFile}
                  id="asset-context-file"
                  label="Asset context CSV"
                  name="assetContextFile"
                  onFileChange={onAssetContextFileChange}
                />
                <FileUploadField
                  accept=".json,application/json"
                  className="imports-file-input"
                  description="VEX status for occurrence or SBOM imports."
                  file={importWizard.vexFile}
                  id="vex-file"
                  label="OpenVEX / VEX JSON"
                  name="vexFile"
                  onFileChange={onVexFileChange}
                />
              </div>
              <ProviderAttackOptions
                importWizard={importWizard}
                onAttackMappingFileChange={onAttackMappingFileChange}
                onAttackSourceChange={onAttackSourceChange}
                onAttackTechniqueMetadataFileChange={
                  onAttackTechniqueMetadataFileChange
                }
                onLockedProviderDataChange={onLockedProviderDataChange}
                onProviderSnapshotFileChange={onProviderSnapshotFileChange}
              />
            </div>
          </VpwAdvancedOptionsDisclosure>

          <div className="imports-readiness-row">
            <VpwProgress
              label="Import readiness"
              tone={canSubmit ? "success" : "warning"}
              value={progress}
            />
          </div>
          {importError ? (
            <VpwStatusBanner title="Import upload failed" tone="critical">
              {importError}
            </VpwStatusBanner>
          ) : null}
          {importLoading ? (
            <VpwStatusBanner title="Uploading and parsing import file">
              Validation and normalization are running.
            </VpwStatusBanner>
          ) : null}
        </div>

        <aside aria-label="Import context" className="imports-context-rail">
          <ContextCard
            items={[
              {
                label: "Project",
                tone: selectedProjectId ? "success" : "warning",
                value: selectedProjectId ? "Selected" : "Required",
              },
              {
                label: "Source file",
                tone: importWizard.file ? "success" : "warning",
                value: importWizard.file ? "Attached" : "Required",
              },
              {
                label: "Readiness",
                tone: canSubmit ? "success" : "warning",
                value: `${progress}%`,
              },
            ]}
            title="Readiness"
          />
          <ContextCard
            description={providerSummary.detail}
            items={[
              {
                label: "Provider snapshot",
                tone: providerStatus?.status === "ok" ? "success" : "warning",
                value: providerSummary.value,
              },
              {
                label: "Snapshot file",
                tone: importWizard.providerSnapshotFile ? "info" : "neutral",
                value: importWizard.providerSnapshotFile ? "Set" : "Optional",
              },
              {
                label: "VEX sidecar",
                tone: importWizard.vexFile ? "support" : "neutral",
                value: importWizard.vexFile ? "Attached" : "Optional",
              },
            ]}
            title="Provider evidence"
          />
          <ContextCard
            description="Local parsing only. Imports do not probe assets or run scanners."
            items={[
              { label: "Network", value: "No scanning", tone: "success" },
              { label: "Unsupported files", value: "Rejected", tone: "warning" },
              { label: "Mode", value: "Local import", tone: "info" },
            ]}
            title="Safety"
          />
        </aside>
      </form>
    </VpwSection>
  )
}

function WorkflowStepList({
  steps,
}: {
  steps: readonly {
    description: string
    label: string
    state: "active" | "complete" | "pending" | "warning"
  }[]
}) {
  return (
    <ol className="imports-step-strip">
      {steps.map((step, index) => (
        <li className={`imports-step imports-step-${step.state}`} key={step.label}>
          <span aria-hidden="true">{index + 1}</span>
          <div>
            <strong>{step.label}</strong>
            <small>{step.description}</small>
          </div>
        </li>
      ))}
    </ol>
  )
}

function ContextCard({
  description,
  items,
  title,
}: {
  description?: string
  items: {
    label: string
    tone: "critical" | "info" | "neutral" | "success" | "support" | "warning"
    value: string
  }[]
  title: string
}) {
  return (
    <section className="imports-context-card">
      <h3>{title}</h3>
      {description ? <p>{description}</p> : null}
      <dl>
        {items.map((item) => (
          <div key={item.label}>
            <dt>{item.label}</dt>
            <dd>
              <VpwBadge tone={item.tone}>{item.value}</VpwBadge>
            </dd>
          </div>
        ))}
      </dl>
    </section>
  )
}
