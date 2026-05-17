import { FileJson } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { VpwField, VpwSectionHeader } from "@/components/vpw"
import {
  attackImportSourceOptions,
  demoProviderSnapshotFile,
} from "@/lib/app-defaults"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"

export function ProviderAttackOptions({
  importWizard,
  onAttackMappingFileChange,
  onAttackSourceChange,
  onAttackTechniqueMetadataFileChange,
  onLockedProviderDataChange,
  onProviderSnapshotFileChange,
  onUseDemoProviderSnapshot,
}: Pick<
  ImportsWorkbenchProps,
  | "importWizard"
  | "onAttackMappingFileChange"
  | "onAttackSourceChange"
  | "onAttackTechniqueMetadataFileChange"
  | "onLockedProviderDataChange"
  | "onProviderSnapshotFileChange"
  | "onUseDemoProviderSnapshot"
>) {
  const attackSourceDisabled = importWizard.attackSource === "none"
  const attackSourceDisabledReason = "Select an ATT&CK source to enable this field."

  return (
    <div className="flex flex-col gap-4">
      <VpwSectionHeader
        description="Current provider data is used by default. Static snapshots are advanced deterministic replay inputs."
        title="Provider and ATT&CK options"
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <VpwField
          description={`Filename under the configured provider snapshot directory, for example ${demoProviderSnapshotFile}.`}
          htmlFor="provider-snapshot-file"
          label="Provider snapshot file"
        >
          <div className="flex flex-col gap-2 sm:flex-row">
            <Input
              id="provider-snapshot-file"
              name="providerSnapshotFile"
              onChange={(event) =>
                onProviderSnapshotFileChange(event.target.value)
              }
              placeholder={demoProviderSnapshotFile}
              value={importWizard.providerSnapshotFile}
            />
            <Button
              className="sm:w-auto"
              onClick={onUseDemoProviderSnapshot}
              size="sm"
              type="button"
              variant="outline"
            >
              <FileJson aria-hidden="true" data-icon="inline-start" />
              Use demo snapshot
            </Button>
          </div>
        </VpwField>
        <label
          className="flex min-h-10 items-start gap-3 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] p-3 text-sm"
          htmlFor="locked-provider-data"
        >
          <Input
            checked={importWizard.lockedProviderData}
            className="mt-1 size-4 min-w-4 shrink-0 p-0 accent-[var(--vpw-blue)] shadow-none"
            id="locked-provider-data"
            name="lockedProviderData"
            onChange={(event) =>
              onLockedProviderDataChange(event.target.checked)
            }
            type="checkbox"
          />
          <span className="grid gap-1">
            <span className="font-medium text-[var(--vpw-text-primary)]">
              Lock provider data for deterministic replay
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
          description={
            attackSourceDisabled
              ? attackSourceDisabledReason
              : "Required when source is CTID JSON or Local curated."
          }
          htmlFor="attack-mapping-file"
          label="Mapping file"
        >
          <Input
            disabled={attackSourceDisabled}
            id="attack-mapping-file"
            name="attackMappingFile"
            onChange={(event) => onAttackMappingFileChange(event.target.value)}
            placeholder="mapping.json"
            value={importWizard.attackMappingFile}
          />
        </VpwField>
        <VpwField
          description={
            attackSourceDisabled
              ? attackSourceDisabledReason
              : "Optional technique metadata filename."
          }
          htmlFor="attack-technique-metadata-file"
          label="Technique metadata"
        >
          <Input
            disabled={attackSourceDisabled}
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
    </div>
  )
}
