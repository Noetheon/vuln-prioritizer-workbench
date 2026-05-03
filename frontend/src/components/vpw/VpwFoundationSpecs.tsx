import { cn } from "@/lib/utils"

export type VpwTypographySpecProps = {
  className?: string
}

export type VpwSpacingSpecProps = {
  className?: string
}

export type VpwElevationSpecProps = {
  className?: string
}

const typeRows = [
  ["H1", "Page title", "32 / 40 / 700"],
  ["H2", "Section title", "24 / 32 / 600"],
  ["H3", "Card title", "18 / 24 / 600"],
  ["Body", "Default evidence copy", "14 / 20 / 400"],
  ["Label", "UPPERCASE LABEL", "12 / 16 / 600"],
] as const

const spacingRows = [
  ["8px", "xs", "w-6"],
  ["16px", "compact", "w-12"],
  ["24px", "card", "w-18"],
  ["32px", "section", "w-24"],
  ["48px", "desktop", "w-36"],
] as const

const shadowRows = [
  ["Shadow 0", "flat", "var(--vpw-shadow-0)"],
  ["Shadow 1", "card", "var(--vpw-shadow-1)"],
  ["Shadow 2", "raised", "var(--vpw-shadow-2)"],
  ["Shadow 3", "overlay", "var(--vpw-shadow-3)"],
] as const

export function VpwTypographySpec({ className }: VpwTypographySpecProps) {
  return (
    <div className={cn("grid gap-3", className)}>
      {typeRows.map(([label, sample, meta]) => (
        <div
          className="grid grid-cols-[5rem_1fr_7rem] items-baseline gap-3 border-b border-[var(--vpw-border-subtle)] pb-2 last:border-b-0 last:pb-0"
          key={label}
        >
          <span className="text-xs font-semibold text-[var(--vpw-text-muted)]">
            {label}
          </span>
          <span
            className={cn(
              "text-[var(--vpw-text-primary)]",
              label === "H1" && "text-3xl font-bold",
              label === "H2" && "text-2xl font-semibold",
              label === "H3" && "text-lg font-semibold",
              label === "Body" && "text-sm",
              label === "Label" && "vpw-label",
            )}
          >
            {sample}
          </span>
          <span className="text-xs text-[var(--vpw-text-muted)]">{meta}</span>
        </div>
      ))}
    </div>
  )
}

export function VpwSpacingSpec({ className }: VpwSpacingSpecProps) {
  return (
    <div className={cn("grid gap-3", className)}>
      {spacingRows.map(([size, label, widthClass]) => (
        <div
          className="grid grid-cols-[4rem_1fr_5rem] items-center gap-3 text-sm"
          key={size}
        >
          <span className="font-semibold text-[var(--vpw-text-primary)]">
            {size}
          </span>
          <span
            className={cn(
              "h-2 rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-blue)]",
              widthClass,
            )}
          />
          <span className="text-xs text-[var(--vpw-text-muted)]">{label}</span>
        </div>
      ))}
    </div>
  )
}

export function VpwElevationSpec({ className }: VpwElevationSpecProps) {
  return (
    <div className={cn("grid gap-3", className)}>
      {shadowRows.map(([name, label, shadow]) => (
        <div
          className="grid grid-cols-[6rem_1fr_5rem] items-center gap-3 text-sm"
          key={name}
        >
          <span className="font-semibold text-[var(--vpw-text-primary)]">
            {name}
          </span>
          <span
            className="h-9 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)]"
            style={{ boxShadow: shadow }}
          />
          <span className="text-xs text-[var(--vpw-text-muted)]">{label}</span>
        </div>
      ))}
    </div>
  )
}
