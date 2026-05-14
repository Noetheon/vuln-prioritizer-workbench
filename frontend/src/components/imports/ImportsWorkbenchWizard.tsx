import { ChevronDown, Upload } from "lucide-react"
import { useEffect, useState } from "react"
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
  MetaTag,
  VpwBadge,
  VpwField,
  VpwKeyValueList,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import { FileUploadField } from "./ImportsWorkbenchFileUploadField"
import { ImportWizardSteps } from "./ImportWizardSteps"
import { ProviderAttackOptions } from "./ImportsWorkbenchProviderOptions"
import {
  fileSizeLabel,
  formatDisplayType,
  formatExpectedFields,
  hasOptionalContext,
  importSubmitDisabled,
  type ImportsWorkbenchProps,
  optionalContextLabels,
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
  const submitDisabled = importSubmitDisabled({
    importLoading,
    projectListLoading,
    projectCount: projects.length,
    selectedProjectId,
    wizard: importWizard,
  })
  const optionalLabels = optionalContextLabels(importWizard)
  const optionalContextSelected = hasOptionalContext(importWizard)
  const [optionalOpen, setOptionalOpen] = useState(optionalContextSelected)
  useEffect(() => {
    if (optionalContextSelected) setOptionalOpen(true)
  }, [optionalContextSelected])
  const optionalSummary =
    optionalLabels.length > 0 ? optionalLabels.join(", ") : "None selected"
  const selectedProject = projects.find((project) => project.id === selectedProjectId)
  const sourceFileLabel = importWizard.file
    ? `${importWizard.file.name} (${fileSizeLabel(importWizard.file)})`
    : "Required"
  const providerSetting = importWizard.providerSnapshotFile
    ? importWizard.providerSnapshotFile
    : importWizard.lockedProviderData
      ? "Locked provider data"
      : "Current provider data"
  const attackSetting =
    importWizard.attackSource && importWizard.attackSource !== "none"
      ? formatDisplayType(importWizard.attackSource)
      : "None"

  return (
    <VpwSection id="import-wizard">
      <VpwSectionHeader
        description="Choose a source format, attach the evidence file, add optional overlays only when needed, then review before upload."
        title="Upload evidence"
      />
      <ImportWizardSteps
        format={format}
        importLoading={importLoading}
        importWizard={importWizard}
        selectedProjectId={selectedProjectId}
      />
      <form
        className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(20rem,0.7fr)]"
        onSubmit={onSubmit}
      >
        <div className="flex min-w-0 flex-col gap-4">
          <VpwPanel className="flex flex-col gap-5">
            <VpwSectionHeader
              description="Required fields for a valid import run."
              title="Source"
            />
            <VpwToolbar label="Import readiness" variant="plain">
              <VpwToolbarGroup>
                <VpwBadge tone={selectedProjectId ? "success" : "warning"}>
                  {selectedProjectId ? "Project ready" : "Project required"}
                </VpwBadge>
                <VpwBadge tone={importWizard.inputType ? "info" : "warning"}>
                  {format?.label ?? "Input type required"}
                </VpwBadge>
                <VpwBadge tone={importWizard.file ? "success" : "warning"}>
                  {importWizard.file ? "File ready" : "File required"}
                </VpwBadge>
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
          </VpwPanel>

          <details
            className="rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-0)]"
            onToggle={(event) => setOptionalOpen(event.currentTarget.open)}
            open={optionalOpen}
          >
            <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 [&::-webkit-details-marker]:hidden">
              <span className="min-w-0">
                <span className="block text-base font-semibold text-[var(--vpw-text-primary)]">
                  Optional context overlays
                </span>
                <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
                  Asset context, VEX, provider replay, and reviewed ATT&CK mappings stay collapsed unless needed.
                </span>
              </span>
              <span className="flex shrink-0 items-center gap-2">
                <VpwBadge tone={optionalLabels.length > 0 ? "info" : "neutral"}>
                  {optionalLabels.length > 0
                    ? `${optionalLabels.length} selected`
                    : "Optional"}
                </VpwBadge>
                <ChevronDown aria-hidden="true" className="size-4" />
              </span>
            </summary>
            <div className="flex flex-col gap-4 border-t border-[var(--vpw-border-default)] p-5">
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
            </div>
          </details>
        </div>

        <VpwPanel className="flex flex-col gap-5">
          <VpwSectionHeader
            description="Review the exact local import settings before creating a run."
            title="Review settings"
          />
          <VpwKeyValueList
            items={[
              {
                label: "Project",
                value: selectedProject?.name ?? "Required",
                tone: selectedProjectId ? "success" : "warning",
              },
              {
                label: "Input type",
                value: format?.label ?? formatDisplayType(importWizard.inputType),
                description: formatExpectedFields(importWizard.inputType),
                tone: "info",
              },
              {
                label: "Main file",
                value: sourceFileLabel,
                tone: importWizard.file ? "success" : "warning",
              },
              {
                label: "Optional overlays",
                value: optionalSummary,
                tone: optionalLabels.length > 0 ? "info" : "neutral",
              },
              {
                label: "Provider snapshot",
                value: providerSetting,
              },
              {
                label: "ATT&CK source",
                value: attackSetting,
              },
            ]}
          />
          {optionalLabels.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {optionalLabels.map((label) => (
                <MetaTag key={label} label={label} />
              ))}
            </div>
          ) : null}
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
              Workbench validation and normalization are running locally.
            </VpwStatusBanner>
          ) : null}
          <Button
            aria-busy={importLoading}
            disabled={submitDisabled}
            type="submit"
          >
            <Upload aria-hidden="true" data-icon="inline-start" />
            {importLoading ? "Uploading" : "Start import"}
          </Button>
        </VpwPanel>
      </form>
    </VpwSection>
  )
}
