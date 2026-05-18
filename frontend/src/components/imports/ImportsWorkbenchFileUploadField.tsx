import { VpwField, VpwFileInput } from "@/components/vpw"
import type { ReactNode } from "react"
import { fileSizeLabel } from "./imports-workbench-model"

type FileUploadFieldProps = {
  accept: string | undefined
  acceptedLabel?: string
  description?: ReactNode
  emptyIcon?: ReactNode
  file: File | null
  fileIcon?: ReactNode
  fieldClassName?: string
  id: string
  label: string
  layout?: "default" | "centered"
  name: string
  onFileChange: (file: File | null) => void
  required?: boolean
  selectedDescription?: string
  selectedTone?: "default" | "accepted"
  showAcceptedText?: boolean
  showSelectedFileDescription?: boolean
}

export function FileUploadField({
  accept,
  acceptedLabel,
  description,
  emptyIcon,
  file,
  fileIcon,
  fieldClassName,
  id,
  label,
  layout = "default",
  name,
  onFileChange,
  required = false,
  selectedDescription,
  selectedTone = "default",
  showAcceptedText = true,
  showSelectedFileDescription = true,
}: FileUploadFieldProps) {
  const fieldDescription =
    description || showSelectedFileDescription ? (
      <span className="grid gap-1">
        {description ? <span>{description}</span> : null}
        {showSelectedFileDescription ? (
          <span className="font-medium text-[var(--vpw-text-secondary)]">
            {file ? `${file.name} · ${fileSizeLabel(file)}` : "No file selected"}
          </span>
        ) : null}
      </span>
    ) : undefined

  return (
    <VpwField
      className={fieldClassName}
      description={fieldDescription}
      htmlFor={id}
      label={label}
      required={required}
    >
      <VpwFileInput
        accept={accept}
        acceptedLabel={acceptedLabel}
        emptyIcon={emptyIcon}
        file={file}
        fileIcon={fileIcon}
        id={id}
        label={label}
        layout={layout}
        name={name}
        onFileChange={onFileChange}
        selectedDescription={selectedDescription}
        selectedTone={selectedTone}
        showAcceptedText={showAcceptedText}
        showSelectedFileActions
      />
    </VpwField>
  )
}
