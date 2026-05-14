import { FileCheck2, UploadCloud } from "lucide-react"
import type { ChangeEvent } from "react"

import { cn } from "@/lib/utils"

export type VpwFileInputProps = {
  id: string
  label: string
  accept?: string
  "aria-describedby"?: string
  "aria-errormessage"?: string
  "aria-invalid"?: boolean | "true" | "false"
  "aria-required"?: boolean | "true" | "false"
  className?: string
  disabled?: boolean
  file?: File | null
  name?: string
  onFileChange: (file: File | null) => void
}

export function VpwFileInput({
  accept,
  "aria-describedby": ariaDescribedBy,
  "aria-errormessage": ariaErrorMessage,
  "aria-invalid": ariaInvalid,
  "aria-required": ariaRequired,
  className,
  disabled = false,
  file,
  id,
  label,
  name,
  onFileChange,
}: VpwFileInputProps) {
  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    onFileChange(event.target.files?.[0] ?? null)
  }

  return (
    <div className={cn("grid gap-2", className)}>
      <input
        accept={accept}
        aria-describedby={ariaDescribedBy}
        aria-errormessage={ariaErrorMessage}
        aria-label={label}
        aria-invalid={ariaInvalid}
        className="sr-only"
        disabled={disabled}
        id={id}
        name={name}
        onChange={handleChange}
        required={ariaRequired === true || ariaRequired === "true"}
        type="file"
      />
      <label
        className={cn(
          "flex min-h-24 cursor-pointer items-center gap-3 rounded-[var(--vpw-radius-lg)] border border-dashed border-[var(--vpw-border-strong)] bg-[var(--vpw-bg-card)] px-4 py-3 text-sm transition-colors",
          "hover:border-[var(--vpw-blue)] hover:bg-[var(--vpw-bg-info)]",
          "focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-[var(--vpw-focus-ring)]",
          disabled &&
            "cursor-not-allowed border-[var(--vpw-border-disabled)] bg-[var(--vpw-bg-disabled)] text-[var(--vpw-text-disabled)]",
        )}
        htmlFor={id}
      >
        <span className="grid size-10 shrink-0 place-items-center rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] text-[var(--vpw-blue)]">
          {file ? (
            <FileCheck2 aria-hidden="true" className="size-5" />
          ) : (
            <UploadCloud aria-hidden="true" className="size-5" />
          )}
        </span>
        <span className="min-w-0">
          <span className="block font-semibold text-[var(--vpw-text-primary)]">
            {file ? file.name : "Choose or drop a file"}
          </span>
          <span className="mt-1 block text-xs leading-5 text-[var(--vpw-text-muted)]">
            {accept ? `Accepted: ${accept}` : "Supported workbench input"}
          </span>
        </span>
      </label>
    </div>
  )
}
