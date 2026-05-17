import { VpwField, VpwFileInput } from "@/components/vpw"
import { fileSizeLabel } from "./imports-workbench-model"

type FileUploadFieldProps = {
  accept: string | undefined
  description: string
  file: File | null
  id: string
  label: string
  name: string
  onFileChange: (file: File | null) => void
  required?: boolean
}

export function FileUploadField({
  accept,
  description,
  file,
  id,
  label,
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
        file={file}
        id={id}
        label={label}
        name={name}
        onFileChange={onFileChange}
        showSelectedFileActions
      />
    </VpwField>
  )
}
