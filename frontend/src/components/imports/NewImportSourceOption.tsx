import { CheckCircle2, Circle } from "lucide-react"
import { Button } from "@/components/ui/button"
import type { SupportedFormat } from "@/lib/import-format-metadata"
import { cn } from "@/lib/utils"
import { ImportSourceMark } from "./NewImportSourceGlyph"

export function FormatOptionCard({
  checked,
  format,
  onClick,
}: {
  checked: boolean
  format: SupportedFormat
  onClick: () => void
}) {
  const extensions = format.extensions.join(", ")

  return (
    <Button
      aria-pressed={checked}
      className={cn(
        "group flex h-auto min-h-[5.4rem] w-full items-center justify-between gap-4 whitespace-normal rounded-[var(--vpw-radius-lg)] border bg-[var(--vpw-bg-card)] p-4 text-left shadow-[var(--vpw-shadow-0)] transition-[background,border-color,box-shadow]",
        checked
          ? "border-[var(--vpw-green)] bg-[color-mix(in_srgb,var(--vpw-bg-success)_54%,var(--vpw-bg-card))] ring-1 ring-[color-mix(in_srgb,var(--vpw-green)_18%,transparent)]"
          : "border-[var(--vpw-border-default)] hover:border-[var(--vpw-border-strong)] hover:bg-[var(--vpw-bg-panel)]",
      )}
      onClick={onClick}
      type="button"
      variant="outline"
    >
      <span className="flex min-w-0 items-center gap-4">
        <ImportSourceMark checked={checked} inputType={format.inputType} />
        <span className="min-w-0">
          <span className="block font-semibold leading-5 text-[var(--vpw-text-primary)]">
            {format.label}
          </span>
          <span className="mt-1 block text-xs leading-4 text-[var(--vpw-text-muted)]">
            {extensions}
          </span>
          <span className="mt-1 block text-sm leading-5 text-[var(--vpw-text-secondary)]">
            {format.shortDescription}
          </span>
        </span>
      </span>
      {checked ? (
        <CheckCircle2
          aria-hidden="true"
          className="size-5 shrink-0 text-[var(--vpw-green)]"
        />
      ) : (
        <Circle
          aria-hidden="true"
          className="size-5 shrink-0 text-[var(--vpw-text-muted)]"
        />
      )}
    </Button>
  )
}
