import { Database, FileJson, LockKeyhole, ShieldCheck } from "lucide-react"

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
import { VpwField } from "@/components/vpw"
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
  const selectedAttackSourceDetail = attackImportSourceOptions.find(
    (option) => option.value === importWizard.attackSource,
  )?.detail

  return (
    <div className="grid gap-4">
      <div className="grid gap-1">
        <h3 className="text-lg font-semibold text-[var(--vpw-text-primary)]">
          Advanced options
        </h3>
        <p className="text-sm leading-6 text-[var(--vpw-text-secondary)]">
          Leave these defaults unchanged unless this import needs deterministic
          replay data or reviewed ATT&CK mapping artifacts.
        </p>
      </div>

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(220px,0.72fr)]">
        <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] p-3">
          <div className="flex items-start gap-3">
            <span className="grid size-9 shrink-0 place-items-center rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-card)] text-[var(--vpw-blue)]">
              <Database aria-hidden="true" className="size-4" />
            </span>
            <div className="min-w-0">
              <p className="font-semibold text-[var(--vpw-text-primary)]">
                Provider data
              </p>
              <p className="mt-1 text-xs leading-5 text-[var(--vpw-text-secondary)]">
                Current provider data is used unless a snapshot is selected.
              </p>
            </div>
          </div>
          <VpwField
            className="mt-3"
            description={`Optional filename under the provider snapshot directory, for example ${demoProviderSnapshotFile}.`}
            htmlFor="provider-snapshot-file"
            label="Snapshot filename"
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
        </div>

        <label
          className="flex min-h-10 items-start gap-3 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] p-3 text-sm"
          htmlFor="locked-provider-data"
        >
          <Input
            aria-label="Lock provider data for deterministic replay"
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
            <span className="inline-flex items-center gap-2 font-semibold text-[var(--vpw-text-primary)]">
              <LockKeyhole
                aria-hidden="true"
                className="size-4 text-[var(--vpw-text-muted)]"
              />
              Deterministic replay
            </span>
            <span className="text-xs leading-5 text-[var(--vpw-text-muted)]">
              Lock the selected provider snapshot only when the import must be
              reproducible.
            </span>
          </span>
        </label>
      </div>

      <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] p-3">
        <div className="mb-3 flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-card)] text-[var(--vpw-blue)]">
            <ShieldCheck aria-hidden="true" className="size-4" />
          </span>
          <div className="min-w-0">
            <p className="font-semibold text-[var(--vpw-text-primary)]">
              Reviewed ATT&CK mapping
            </p>
            <p className="mt-1 text-xs leading-5 text-[var(--vpw-text-secondary)]">
              Add reviewed defensive mappings only. This does not auto-map or
              change base priority.
            </p>
          </div>
        </div>
        <div className="grid gap-3 lg:grid-cols-3">
          <VpwField
            description={selectedAttackSourceDetail}
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
    </div>
  )
}
