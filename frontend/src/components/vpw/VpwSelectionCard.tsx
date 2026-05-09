import { CheckCircle2, Circle } from "lucide-react"
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwSelectionCardProps = {
  title: string
  as?: "button" | "span"
  checked?: boolean
  children?: ReactNode
  className?: string
  meta?: ReactNode
  onClick?: () => void
}

export function VpwSelectionCard({
  as = "button",
  checked = false,
  children,
  className,
  meta,
  onClick,
  title,
}: VpwSelectionCardProps) {
  const Icon = checked ? CheckCircle2 : Circle
  const cardClassName = cn(
    "block w-full rounded-[var(--vpw-radius-xl)] border bg-[var(--vpw-bg-card)] p-4 text-left shadow-[var(--vpw-shadow-1)] transition-colors",
    checked
      ? "border-[var(--vpw-blue)] ring-2 ring-[color-mix(in_srgb,var(--vpw-blue)_18%,transparent)]"
      : "border-[var(--vpw-border-default)] hover:bg-[var(--vpw-bg-panel)]",
    className,
  )
  const content = (
    <>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-semibold text-[var(--vpw-text-primary)]">
            {title}
          </p>
          {meta ? (
            <div className="mt-1 text-xs text-[var(--vpw-text-muted)]">
              {meta}
            </div>
          ) : null}
        </div>
        <Icon
          aria-hidden="true"
          className={cn(
            "h-5 w-5 shrink-0",
            checked ? "text-[var(--vpw-blue)]" : "text-[var(--vpw-text-muted)]",
          )}
        />
      </div>
      {children ? (
        <div className="mt-3 text-sm leading-5 text-[var(--vpw-text-secondary)]">
          {children}
        </div>
      ) : null}
    </>
  )

  if (as === "span") {
    return <span className={cardClassName}>{content}</span>
  }

  return (
    <button
      aria-pressed={checked}
      className={cardClassName}
      onClick={onClick}
      type="button"
    >
      {content}
    </button>
  )
}
