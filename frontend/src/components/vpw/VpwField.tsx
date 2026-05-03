import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwFieldProps = {
  children: ReactNode
  label: string
  className?: string
  description?: ReactNode
  error?: ReactNode
  htmlFor?: string
  required?: boolean
}

export function VpwField({
  children,
  className,
  description,
  error,
  htmlFor,
  label,
  required = false,
}: VpwFieldProps) {
  const LabelElement = htmlFor ? "label" : "div"

  return (
    <div className={cn("grid gap-1.5", className)}>
      <LabelElement
        className="text-sm font-medium text-[var(--vpw-text-primary)]"
        htmlFor={htmlFor}
      >
        {label}
        {required ? (
          <span className="ml-1 text-[var(--vpw-red)]" aria-hidden="true">
            *
          </span>
        ) : null}
      </LabelElement>
      {children}
      {description ? (
        <p className="text-xs leading-5 text-[var(--vpw-text-muted)]">
          {description}
        </p>
      ) : null}
      {error ? (
        <p className="text-xs leading-5 text-[var(--vpw-red)]" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}
