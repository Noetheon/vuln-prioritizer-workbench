import { VpwGrid, VpwImportStepCard } from "@/components/vpw"

import type {
  ImportWizardStateLike,
  SupportedImportFormat,
} from "./imports-workbench-model"

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
  const stepCards = [
    {
      title: "Select project",
      description: "Choose the workspace that owns the imported findings.",
      status: selectedProjectId ? "Ready" : "Required",
      statusTone: selectedProjectId ? "success" : "warning",
    },
    {
      title: "Select input type",
      description: "Match parser behavior to the file format.",
      status: format?.label ?? "Required",
      statusTone: "info",
    },
    {
      title: "Upload file",
      description: "Attach the source file that should become findings.",
      status: importWizard.file ? "Ready" : "Required",
      statusTone: importWizard.file ? "success" : "warning",
    },
    {
      title: "Validate and import",
      description:
        "The backend validates format, parses input, and records run evidence.",
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
