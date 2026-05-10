import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { VpwField, VpwPanel, VpwSectionHeader } from "@/components/vpw"
import { attackImportSourceOptions } from "@/lib/app-defaults"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"

export function ProviderAttackOptions({
  importWizard,
  onAttackMappingFileChange,
  onAttackSourceChange,
  onAttackTechniqueMetadataFileChange,
  onLockedProviderDataChange,
  onProviderSnapshotFileChange,
}: Pick<
  ImportsWorkbenchProps,
  | "importWizard"
  | "onAttackMappingFileChange"
  | "onAttackSourceChange"
  | "onAttackTechniqueMetadataFileChange"
  | "onLockedProviderDataChange"
  | "onProviderSnapshotFileChange"
>) {
  return (
    <VpwPanel className="flex flex-col gap-4 border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-4">
      <VpwSectionHeader
        description="Optional deterministic enrichment from managed Workbench artifact directories."
        title="Provider and ATT&CK options"
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <VpwField
          description="Filename under the configured provider snapshot directory, for example demo_provider_snapshot.json."
          htmlFor="provider-snapshot-file"
          label="Provider snapshot file"
        >
          <Input
            id="provider-snapshot-file"
            name="providerSnapshotFile"
            onChange={(event) =>
              onProviderSnapshotFileChange(event.target.value)
            }
            placeholder="demo_provider_snapshot.json"
            value={importWizard.providerSnapshotFile}
          />
        </VpwField>
        <label className="flex min-h-10 items-start gap-3 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] p-3 text-sm">
          <input
            checked={importWizard.lockedProviderData}
            className="mt-1"
            name="lockedProviderData"
            onChange={(event) =>
              onLockedProviderDataChange(event.target.checked)
            }
            type="checkbox"
          />
          <span className="grid gap-1">
            <span className="font-medium text-[var(--vpw-text-primary)]">
              Locked provider data
            </span>
            <span className="text-xs leading-5 text-[var(--vpw-text-muted)]">
              Treat selected provider snapshot data as deterministic evidence
              for this import.
            </span>
          </span>
        </label>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <VpwField
          description={
            attackImportSourceOptions.find(
              (option) => option.value === importWizard.attackSource,
            )?.detail
          }
          label="ATT&CK source"
        >
          <Select
            name="attackSource"
            onValueChange={onAttackSourceChange}
            value={importWizard.attackSource}
          >
            <SelectTrigger aria-label="ATT&CK source">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {attackImportSourceOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </VpwField>
        <VpwField
          description="Managed filename required for CTID JSON or local curated ATT&CK imports."
          htmlFor="attack-mapping-file"
          label="Mapping file"
        >
          <Input
            disabled={importWizard.attackSource === "none"}
            id="attack-mapping-file"
            name="attackMappingFile"
            onChange={(event) => onAttackMappingFileChange(event.target.value)}
            placeholder="mapping.json"
            value={importWizard.attackMappingFile}
          />
        </VpwField>
        <VpwField
          description="Optional managed technique metadata filename."
          htmlFor="attack-technique-metadata-file"
          label="Technique metadata"
        >
          <Input
            disabled={importWizard.attackSource === "none"}
            id="attack-technique-metadata-file"
            name="attackTechniqueMetadataFile"
            onChange={(event) =>
              onAttackTechniqueMetadataFileChange(event.target.value)
            }
            placeholder="techniques.json"
            value={importWizard.attackTechniqueMetadataFile}
          />
        </VpwField>
      </div>
    </VpwPanel>
  )
}
