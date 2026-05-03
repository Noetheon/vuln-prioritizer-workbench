import { cn } from "@/lib/utils"

export type VpwTokenSwatchProps = {
  name: string
  value: string
  className?: string
  usage?: string
}

export function VpwTokenSwatch({
  className,
  name,
  usage,
  value,
}: VpwTokenSwatchProps) {
  return (
    <div
      className={cn(
        "overflow-hidden rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-1)]",
        className,
      )}
    >
      <div
        aria-label={`${name} color preview`}
        className="h-14 border-b border-[var(--vpw-border-subtle)]"
        role="img"
        style={{ background: value }}
      />
      <div className="p-3">
        <p className="text-sm font-semibold text-[var(--vpw-text-primary)]">
          {name}
        </p>
        <p className="mt-0.5 font-mono text-xs text-[var(--vpw-text-muted)]">
          {value}
        </p>
        {usage ? (
          <p className="mt-2 text-xs leading-5 text-[var(--vpw-text-secondary)]">
            {usage}
          </p>
        ) : null}
      </div>
    </div>
  )
}
