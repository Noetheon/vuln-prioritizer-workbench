import { VpwGrid, VpwImportStepCard } from "@/components/vpw"

import type {
  ImportWizardStateLike,
  SupportedImportFormat,
} from "./imports-workbench-model"
import { optionalContextLabels } from "./imports-workbench-model"

type ImportWizardStepsProps = {
  format: SupportedImportFormat | undefined
  importLoading: boolean
  importWizard: ImportWizardStateLike
  selectedProjectId: string
}

export function ImportWizardSteps({
  format,
  importLoading,
  importWizard,
  selectedProjectId,
}: ImportWizardStepsProps) {
  const optionalLabels = optionalContextLabels(importWizard)
  const readyForReview = Boolean(selectedProjectId && importWizard.file)
  const stepCards = [
    {
      title: "Choose input type",
      description: "Match parser behavior to the file format.",
      status: format?.label ?? "Required",
      statusTone: "info",
    },
    {
      title: "Select evidence file",
      description: "Attach the source file that should become findings.",
      status: importWizard.file ? "Ready" : "Required",
      statusTone: importWizard.file ? "success" : "warning",
    },
    {
      title: "Optional context overlays",
      description: "Add asset context, VEX, provider replay, or reviewed mappings.",
      status:
        optionalLabels.length > 0
          ? `${optionalLabels.length} selected`
          : "Optional",
      statusTone: optionalLabels.length > 0 ? "info" : "neutral",
    },
    {
      title: "Review settings",
      description: "Confirm project, input, source file, and overlays.",
      status: readyForReview ? "Ready" : "Required",
      statusTone: readyForReview ? "success" : "warning",
    },
    {
      title: "Import result",
      description: "Validate locally and record the import run.",
      status: importLoading ? "Running" : "Ready",
      statusTone: importLoading ? "info" : "neutral",
    },
  ] as const

  return (
    <VpwGrid columns={4}>
      {stepCards.map((step) => (
        <VpwImportStepCard
          description={step.description}
          key={step.title}
          status={step.status}
          statusTone={step.statusTone}
          title={step.title}
        />
      ))}
    </VpwGrid>
  )
}
