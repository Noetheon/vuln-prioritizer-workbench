import {
  VpwBadge,
  VpwGrid,
  VpwSection,
  VpwSelectionCard,
} from "@/components/vpw"
import {
  formatExpectedFields,
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"

export function SupportedFormats({
  importWizard,
  onInputTypeChange,
  supportedFormats,
}: Pick<
  ImportsWorkbenchProps,
  "importWizard" | "onInputTypeChange" | "supportedFormats"
>) {
  return (
    <VpwSection>
      <details className="rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-0)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 [&::-webkit-details-marker]:hidden">
          <span className="min-w-0">
            <span className="block text-base font-semibold text-[var(--vpw-text-primary)]">
              Supported input formats
            </span>
            <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
              Parser expectations are available here when you need exact field guidance.
            </span>
          </span>
          <VpwBadge tone="neutral">{supportedFormats.length} formats</VpwBadge>
        </summary>
        <div className="border-t border-[var(--vpw-border-default)] p-5">
          <VpwGrid columns={4}>
            {supportedFormats.map((format) => (
              <VpwSelectionCard
                checked={format.value === importWizard.inputType}
                key={format.value}
                meta={format.accept}
                onClick={() => onInputTypeChange(format.value)}
                title={format.label}
              >
                <div className="flex flex-col gap-2">
                  <p>{format.detail}</p>
                  <p className="text-xs">
                    Expected: {formatExpectedFields(format.value)}
                  </p>
                </div>
              </VpwSelectionCard>
            ))}
            <VpwSelectionCard
              checked={Boolean(importWizard.vexFile)}
              meta=".json, application/json"
              title="OpenVEX / VEX sidecar"
            >
              <div className="flex flex-col gap-2">
                <p>
                  Optional VEX JSON sidecar attached to occurrence or SBOM
                  imports.
                </p>
                <p className="text-xs">
                  Expected: OpenVEX statements or CycloneDX VEX vulnerability
                  status data.
                </p>
              </div>
            </VpwSelectionCard>
          </VpwGrid>
        </div>
      </details>
    </VpwSection>
  )
}
