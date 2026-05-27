import {
  VpwBadge,
  VpwSectionHeader,
} from "@/components/vpw"
import {
  acceptedFileInputValue,
  type ParserPreview,
} from "@/lib/import-format-metadata"
import { FileUploadField } from "./ImportsWorkbenchFileUploadField"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"
import {
  AcceptedTypeChips,
  ParserPreviewPanel,
  uploadRequirementCopy,
} from "./NewImportUploadPreview"

export function UploadFileStep({
  format,
  importWizard,
  onFileChange,
  parserPreview,
  supportedFormats,
}: Pick<ImportsWorkbenchProps, "importWizard" | "onFileChange"> & {
  format: ImportsWorkbenchProps["supportedFormats"][number] | undefined
  parserPreview: ParserPreview
  supportedFormats: ImportsWorkbenchProps["supportedFormats"]
}) {
  const uploadRequirement = format
    ? uploadRequirementCopy(format)
    : "Attach the main evidence file."

  return (
    <section className="flex flex-col gap-4">
      <VpwSectionHeader
        description="Attach evidence for the selected import format before continuing."
        title="Upload file"
      />
      <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3">
        <div className="mb-3">
          <p className="text-base font-semibold text-[var(--vpw-text-primary)]">
            A. Evidence file
          </p>
          <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
            <span className="font-medium text-[var(--vpw-text-primary)]">
            {format?.label ?? "Input type not selected"}
          </span>
            {format ? ` - ${uploadRequirement}` : ""}
          </p>
        </div>
        <FileUploadField
          accept={acceptedFileInputValue(format)}
          description={undefined}
          file={importWizard.file}
          fieldClassName="[&_[data-slot=field-label]]:sr-only"
          id="import-file"
          label="Evidence file"
          name="importFile"
          onFileChange={onFileChange}
          required
          selectedTone={importWizard.file ? "accepted" : "default"}
          showAcceptedText={false}
          showSelectedFileDescription={false}
        />
        {!importWizard.file && format?.extensions.length ? (
          <AcceptedTypeChips extensions={format.extensions} />
        ) : null}
      </div>
      <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-base font-semibold text-[var(--vpw-text-primary)]">
              B. File check
            </p>
            <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
              Shallow validation runs locally before the import starts.
            </p>
          </div>
          {parserPreview.state === "passed" || parserPreview.state === "warning" ? (
            <VpwBadge tone={parserPreview.state === "warning" ? "warning" : "success"}>
              {parserPreview.state === "warning" ? "Warning" : "Passed"}
            </VpwBadge>
          ) : null}
        </div>
        <ParserPreviewPanel
          parserPreview={parserPreview}
          supportedFormats={supportedFormats}
        />
      </div>
    </section>
  )
}
