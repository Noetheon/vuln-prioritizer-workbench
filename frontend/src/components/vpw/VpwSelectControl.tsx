import type { ReactNode } from "react"

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { cn } from "@/lib/utils"

export type VpwSelectControlOption = {
  label: ReactNode
  value: string
}

export type VpwSelectControlProps = {
  options: readonly VpwSelectControlOption[]
  value: string
  "aria-describedby"?: string
  "aria-errormessage"?: string
  "aria-invalid"?: boolean | "true" | "false"
  ariaLabel?: string
  "aria-required"?: boolean | "true" | "false"
  className?: string
  disabled?: boolean
  id?: string
  onValueChange?: (value: string) => void
  placeholder?: string
}

export function VpwSelectControl({
  "aria-describedby": ariaDescribedBy,
  "aria-errormessage": ariaErrorMessage,
  "aria-invalid": ariaInvalid,
  "aria-required": ariaRequired,
  ariaLabel,
  className,
  disabled,
  id,
  onValueChange,
  options,
  placeholder = "Select",
  value,
}: VpwSelectControlProps) {
  return (
    <Select disabled={disabled} onValueChange={onValueChange} value={value}>
      <SelectTrigger
        aria-describedby={ariaDescribedBy}
        aria-errormessage={ariaErrorMessage}
        aria-invalid={ariaInvalid}
        aria-label={ariaLabel}
        aria-required={ariaRequired}
        className={cn("vpw-filter-control", className)}
        id={id}
      >
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
