import { ChevronRight, Info, ShieldCheck, Table2 } from "lucide-react"
import {
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import type { ImportReadinessCheck } from "@/lib/import-format-metadata"
import { FileUploadField } from "./ImportsWorkbenchFileUploadField"
import { ProviderAttackOptions } from "./ImportsWorkbenchProviderOptions"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"

export function AddContextStep(
  props: ImportsWorkbenchProps & {
    readiness: readonly ImportReadinessCheck[]
  },
) {
  const assetContextCheck = props.readiness.find(
    (check) => check.id === "asset-context",
  )
  const vexCheck = props.readiness.find((check) => check.id === "vex")
  const attackContextCheck = props.readiness.find(
    (check) => check.id === "attack-context",
  )
  const assetContextReady = assetContextCheck?.status === "passed"
  const vexReady = vexCheck?.status === "passed"
  return (
    <section className="flex flex-col gap-5">
      <VpwSectionHeader
        description="Optional context can improve prioritization and explanations. You can skip this step."
        title="Add context (optional)"
      />
      <div className="grid gap-4 md:grid-cols-2">
        <FileUploadField
          accept=".csv,text/csv"
          acceptedLabel=".csv"
          description="Owner, service, environment, exposure, and criticality context."
          emptyIcon={<Table2 aria-hidden="true" className="size-5" />}
          file={props.importWizard.assetContextFile}
          id="asset-context-file"
          label="Asset context CSV"
          layout="centered"
          name="assetContextFile"
          onFileChange={props.onAssetContextFileChange}
          selectedDescription={optionalFileDescription(
            assetContextCheck?.status,
            "CSV header detected.",
          )}
          selectedTone={assetContextReady ? "accepted" : "default"}
          showSelectedFileDescription={false}
        />
        <FileUploadField
          accept=".json,application/json"
          acceptedLabel=".json"
          description="OpenVEX or CycloneDX VEX sidecar."
          emptyIcon={<ShieldCheck aria-hidden="true" className="size-5" />}
          file={props.importWizard.vexFile}
          id="vex-file"
          label="VEX overlay"
          layout="centered"
          name="vexFile"
          onFileChange={props.onVexFileChange}
          selectedDescription={optionalFileDescription(
            vexCheck?.status,
            "JSON parsed.",
          )}
          selectedTone={vexReady ? "accepted" : "default"}
          showSelectedFileDescription={false}
        />
      </div>
      {assetContextCheck?.status === "error" ? (
        <VpwStatusBanner title="Asset context file needs attention" tone="critical">
          {assetContextCheck.message}
        </VpwStatusBanner>
      ) : null}
      {vexCheck?.status === "error" ? (
        <VpwStatusBanner title="VEX overlay needs attention" tone="critical">
          {vexCheck.message}
        </VpwStatusBanner>
      ) : null}
      {attackContextCheck?.status === "error" ? (
        <VpwStatusBanner title="ATT&CK context needs attention" tone="critical">
          {attackContextCheck.message}
        </VpwStatusBanner>
      ) : null}
      <div className="flex items-start gap-3 rounded-[var(--vpw-radius-lg)] border border-[color-mix(in_srgb,var(--vpw-blue)_32%,var(--vpw-border-default))] bg-[var(--vpw-bg-info)] p-4 text-sm text-[var(--vpw-text-secondary)]">
        <Info
          aria-hidden="true"
          className="mt-0.5 size-5 shrink-0 text-[var(--vpw-blue)]"
        />
        <div>
          <p className="font-semibold text-[var(--vpw-blue)]">
            ATT&CK/TTP context
          </p>
          <p className="mt-1 leading-6">
            Adds reviewed defensive ATT&CK mappings where available. Unmapped
            CVEs remain unmapped, and this context does not override base priority.
          </p>
        </div>
      </div>
      <details className="group rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-semibold text-[var(--vpw-text-primary)] [&::-webkit-details-marker]:hidden">
          <span className="inline-flex min-w-0 items-center gap-2">
            <ChevronRight
              aria-hidden="true"
              className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-open:rotate-90"
            />
            <span>Advanced provider data and reviewed ATT&CK context</span>
          </span>
          <span className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-info)] px-2 py-1 font-mono text-xs text-[var(--vpw-blue)]">
            Optional
          </span>
        </summary>
        <div className="border-t border-[var(--vpw-border-default)] p-3 sm:p-4">
          <ProviderAttackOptions
            importWizard={props.importWizard}
            onAttackMappingFileChange={props.onAttackMappingFileChange}
            onAttackSourceChange={props.onAttackSourceChange}
            onAttackTechniqueMetadataFileChange={
              props.onAttackTechniqueMetadataFileChange
            }
            onLockedProviderDataChange={props.onLockedProviderDataChange}
            onProviderSnapshotFileChange={props.onProviderSnapshotFileChange}
            onUseDemoProviderSnapshot={props.onUseDemoProviderSnapshot}
          />
        </div>
      </details>
    </section>
  )
}

function optionalFileDescription(
  status: ImportReadinessCheck["status"] | undefined,
  successMessage: string,
) {
  if (status === "passed") return successMessage
  if (status === "pending") return "Checking file."
  if (status === "error") return "Needs attention."
  return undefined
}
