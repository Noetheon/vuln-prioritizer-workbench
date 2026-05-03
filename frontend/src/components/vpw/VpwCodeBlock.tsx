import { Check } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export type VpwCodeBlockProps = {
  code: string
  className?: string
  copyLabel?: string
  label?: string
  onCopy?: () => void
}

export function VpwCodeBlock({
  className,
  code,
  copyLabel = "Copy",
  label,
  onCopy,
}: VpwCodeBlockProps) {
  return (
    <div
      className={cn(
        "overflow-hidden rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-1)]",
        className,
      )}
    >
      {label || onCopy ? (
        <div className="flex items-center justify-between gap-3 border-b border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] px-3 py-2">
          {label ? <p className="vpw-label">{label}</p> : <span />}
          {onCopy ? (
            <Button onClick={onCopy} size="sm" type="button" variant="ghost">
              <Check aria-hidden="true" className="h-3.5 w-3.5" />
              {copyLabel}
            </Button>
          ) : null}
        </div>
      ) : null}
      <pre className="overflow-x-auto p-4 font-mono text-xs leading-5 text-[var(--vpw-text-primary)]">
        <code>{code}</code>
      </pre>
    </div>
  )
}
