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
  VpwBadge,
  VpwField,
  VpwFileInput,
  VpwGrid,
  VpwImportStepCard,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { ProviderAttackOptions } from "./ImportsWorkbenchProviderOptions"
import {
  type ImportsWorkbenchProps,
  selectedFormat,
  uploadProgress,
} from "./imports-workbench-model"

type FileUploadFieldProps = {
  accept: string | undefined
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
  onUseDemoProviderSnapshot,
  onAttackMappingFileChange,
  onAttackSourceChange,
  onAttackTechniqueMetadataFileChange,
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
  | "onLockedProviderDataChange"
  | "onProviderSnapshotFileChange"
  | "onProjectChange"
  | "onSubmit"
  | "onUseDemoProviderSnapshot"
  | "onAttackMappingFileChange"
  | "onAttackSourceChange"
  | "onAttackTechniqueMetadataFileChange"
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
          <form className="flex flex-col gap-5" onSubmit={onSubmit}>
            <VpwToolbar label="Import controls" variant="plain">
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
                {importWizard.providerSnapshotFile ? (
                  <VpwBadge tone="info">Provider snapshot</VpwBadge>
                ) : null}
                {importWizard.attackSource !== "none" ? (
                  <VpwBadge tone="support">ATT&CK mapping</VpwBadge>
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
              description={`Accepted: ${format?.accept ?? "supported files"}`}
              file={importWizard.file}
              id="import-file"
              label="Import file"
              name="importFile"
              onFileChange={onFileChange}
              required
            />
            <div className="grid gap-4 lg:grid-cols-2">
              <FileUploadField
                accept=".csv,text/csv"
                description="Optional CSV with target_kind, target_ref, asset_id, owner, service, exposure."
                file={importWizard.assetContextFile}
                id="asset-context-file"
                label="Asset context CSV"
                name="assetContextFile"
                onFileChange={onAssetContextFileChange}
              />
              <FileUploadField
                accept=".json,application/json"
                description="Optional OpenVEX or CycloneDX VEX JSON sidecar."
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
              onUseDemoProviderSnapshot={onUseDemoProviderSnapshot}
            />
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
              <Upload aria-hidden="true" data-icon="inline-start" />
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
