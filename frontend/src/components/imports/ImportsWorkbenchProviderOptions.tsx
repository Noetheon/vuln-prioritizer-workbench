import { Database, FileJson, LockKeyhole, ShieldCheck } from "lucide-react"
import type { ReactNode } from "react"

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
      <p className="max-w-3xl text-sm leading-6 text-[var(--vpw-text-secondary)]">
        Keep defaults unless this import needs a repeatable provider snapshot or
        reviewed ATT&CK mapping artifacts.
      </p>

      <section className="grid gap-3 border-t border-[var(--vpw-border-subtle)] pt-3">
        <AdvancedOptionHeading
          description="Current provider data is used unless a snapshot is selected."
          icon={<Database aria-hidden="true" className="size-4" />}
          title="Provider data"
        />
        <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-start">
          <VpwField
            description="Optional filename under the provider snapshot directory."
            htmlFor="provider-snapshot-file"
            label="Snapshot filename"
          >
            <Input
              id="provider-snapshot-file"
              name="providerSnapshotFile"
              onChange={(event) =>
                onProviderSnapshotFileChange(event.target.value)
              }
              placeholder={demoProviderSnapshotFile}
              value={importWizard.providerSnapshotFile}
            />
          </VpwField>
          <Button
            className="h-10 md:mt-[1.625rem] md:whitespace-nowrap"
            onClick={onUseDemoProviderSnapshot}
            type="button"
            variant="outline"
          >
            <FileJson aria-hidden="true" data-icon="inline-start" />
            Use demo snapshot
          </Button>
        </div>
        <label className="flex items-start gap-3 text-sm" htmlFor="locked-provider-data">
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
          <span className="min-w-0 pt-px">
            <span className="inline-flex items-center gap-2 font-semibold text-[var(--vpw-text-primary)]">
              <LockKeyhole
                aria-hidden="true"
                className="size-4 text-[var(--vpw-text-muted)]"
              />
              Deterministic replay
            </span>
            <span className="mt-0.5 block text-xs leading-5 text-[var(--vpw-text-muted)]">
              Lock the selected provider snapshot only when the import must be
              reproducible.
            </span>
          </span>
        </label>
      </section>

      <section className="grid gap-3 border-t border-[var(--vpw-border-subtle)] pt-3">
        <AdvancedOptionHeading
          description="Add reviewed defensive mappings only. This does not auto-map or change base priority."
          icon={<ShieldCheck aria-hidden="true" className="size-4" />}
          title="Reviewed ATT&CK mapping"
        />
        <div className="grid gap-3">
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
          <div className="grid gap-3 sm:grid-cols-2">
            <VpwField
              description={
                attackSourceDisabled
                  ? attackSourceDisabledReason
                  : "Required for CTID JSON or Local curated."
              }
              htmlFor="attack-mapping-file"
              label="Mapping file"
            >
              <Input
                disabled={attackSourceDisabled}
                id="attack-mapping-file"
                name="attackMappingFile"
                onChange={(event) =>
                  onAttackMappingFileChange(event.target.value)
                }
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
      </section>
    </div>
  )
}

function AdvancedOptionHeading({
  description,
  icon,
  title,
}: {
  description: string
  icon: ReactNode
  title: string
}) {
  return (
    <div className="flex items-start gap-3">
      <span className="grid size-8 shrink-0 place-items-center rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] text-[var(--vpw-blue)]">
        {icon}
      </span>
      <div className="min-w-0">
        <p className="font-semibold text-[var(--vpw-text-primary)]">{title}</p>
        <p className="mt-1 text-xs leading-5 text-[var(--vpw-text-secondary)]">
          {description}
        </p>
      </div>
    </div>
  )
}
