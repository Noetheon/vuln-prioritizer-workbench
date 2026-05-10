import {
  VpwGrid,
  VpwSection,
  VpwSectionHeader,
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
      <VpwSectionHeader
        description="Supported source formats and parser expectations."
        title="Supported Input Formats"
      />
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
              Optional VEX JSON sidecar attached to occurrence or SBOM imports.
            </p>
            <p className="text-xs">
              Expected: OpenVEX statements or CycloneDX VEX vulnerability status
              data.
            </p>
          </div>
        </VpwSelectionCard>
      </VpwGrid>
    </VpwSection>
  )
}
