import type { ImportUploadFormData, ImportWizardState } from "@/lib/app-defaults"

export type ImportUploadPayloadInput = {
  importWizard: ImportWizardState
  selectedAssetContextFile: File | null
  selectedFile: File
  selectedVexFile: File | null
}

export function buildImportUploadFormData({
  importWizard,
  selectedAssetContextFile,
  selectedFile,
  selectedVexFile,
}: ImportUploadPayloadInput): ImportUploadFormData {
  const attackSource = importWizard.attackSource ?? "none"
  const includeAttackFiles = attackSource !== "none"

  return {
    ...(includeAttackFiles && importWizard.attackMappingFile.trim()
      ? {
          attack_mapping_file: importWizard.attackMappingFile.trim(),
        }
      : {}),
    attack_source: attackSource,
    ...(includeAttackFiles && importWizard.attackTechniqueMetadataFile.trim()
      ? {
          attack_technique_metadata_file:
            importWizard.attackTechniqueMetadataFile.trim(),
        }
      : {}),
    ...(selectedAssetContextFile
      ? {
          asset_context_file: selectedAssetContextFile,
        }
      : {}),
    ...(selectedVexFile
      ? {
          vex_file: selectedVexFile,
        }
      : {}),
    file: selectedFile,
    input_type: importWizard.inputType,
    locked_provider_data: importWizard.lockedProviderData,
    ...(importWizard.providerSnapshotFile.trim()
      ? {
          provider_snapshot_file: importWizard.providerSnapshotFile.trim(),
        }
      : {}),
  }
}
