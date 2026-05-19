import {
  MetaTag,
  VpwBadge,
  VpwPanel,
  VpwSectionHeader,
} from "@/components/vpw"
import type { ImportReadinessCheck } from "@/lib/import-format-metadata"
import { cn } from "@/lib/utils"
import {
  hasOptionalContext,
  optionalContextLabels,
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"
import {
  readinessCopyForStep,
  readinessToneForStep,
  type StepId,
} from "./new-import-route-state"

export function SummaryRail({
  importFailed = false,
  inputTypeLabel,
  props,
  readiness,
  step,
}: {
  importFailed?: boolean
  inputTypeLabel: string
  props: ImportsWorkbenchProps
  readiness: readonly ImportReadinessCheck[]
  step: StepId
}) {
  return (
    <VpwPanel
      className="import-summary-rail flex flex-col gap-4 lg:h-full min-[1600px]:sticky min-[1600px]:top-6"
      data-testid="import-summary-rail"
    >
      <VpwSectionHeader title="Import summary" />
      <dl className="grid border-t border-[var(--vpw-border-subtle)] text-sm">
        {[
          {
            label: "Project",
            value: props.selectedProject?.name ?? "Required",
          },
          {
            label: "Input type",
            value: inputTypeLabel,
          },
          {
            label: "Evidence file",
            value: props.importWizard.file?.name ?? "Next: upload evidence file",
          },
          {
            label: "Asset context",
            value: props.importWizard.assetContextFile?.name ?? "Not selected",
            muted: !props.importWizard.assetContextFile,
          },
          {
            label: "VEX",
            value: props.importWizard.vexFile?.name ?? "Not selected",
            muted: !props.importWizard.vexFile,
          },
          {
            label: "ATT&CK context",
            value:
              props.importWizard.attackSource &&
              props.importWizard.attackSource !== "none"
                ? "Reviewed defensive context configured"
                : "Not selected",
            muted:
              !props.importWizard.attackSource ||
              props.importWizard.attackSource === "none",
          },
          {
            label: "Provider data",
            value: props.importWizard.providerSnapshotFile
              ? props.importWizard.providerSnapshotFile
              : "Current provider data",
          },
          {
            label: "Deterministic replay",
            value: props.importWizard.lockedProviderData ? "Yes" : "No",
            muted: !props.importWizard.lockedProviderData,
          },
        ].map((item) => (
          <div
            className="border-b border-[var(--vpw-border-subtle)] py-3"
            key={item.label}
          >
            <dt className="vpw-label">{item.label}</dt>
            <dd
              className={cn(
                "mt-1 min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
                item.muted && "text-[var(--vpw-text-secondary)]",
              )}
            >
              {item.value}
            </dd>
          </div>
        ))}
        <div className="border-b border-[var(--vpw-border-subtle)] py-3">
          <dt className="vpw-label">Readiness</dt>
          <dd className="mt-2">
            <VpwBadge tone={readinessToneForStep(step, readiness, importFailed)}>
              {readinessCopyForStep(step, readiness, importFailed)}
            </VpwBadge>
          </dd>
        </div>
      </dl>
      <div className="flex flex-wrap gap-2 pt-1">
        {hasOptionalContext(props.importWizard)
          ? optionalContextLabels(props.importWizard).map((label) => (
              <MetaTag key={label} label={label} />
            ))
          : null}
      </div>
    </VpwPanel>
  )
}
