import { VpwField, VpwFileInput } from "@/components/vpw"
import { fileSizeLabel } from "./imports-workbench-model"

type FileUploadFieldProps = {
  accept: string | undefined
  acceptedLabel?: string
  description: string
  file: File | null
  id: string
  label: string
  layout?: "default" | "centered"
  name: string
  onFileChange: (file: File | null) => void
  required?: boolean
}

export function FileUploadField({
  accept,
  acceptedLabel,
  description,
  file,
  id,
  label,
  layout = "default",
  name,
  onFileChange,
  required = false,
}: FileUploadFieldProps) {
  return (
    <VpwField
      description={
        <span className="grid gap-1">
          <span>{description}</span>
          <span className="font-medium text-[var(--vpw-text-secondary)]">
            {file ? `${file.name} · ${fileSizeLabel(file)}` : "No file selected"}
          </span>
        </span>
      }
      htmlFor={id}
      label={label}
      required={required}
    >
      <VpwFileInput
        accept={accept}
        acceptedLabel={acceptedLabel}
        file={file}
        id={id}
        label={label}
        layout={layout}
        name={name}
        onFileChange={onFileChange}
        showSelectedFileActions
      />
    </VpwField>
  )
}
