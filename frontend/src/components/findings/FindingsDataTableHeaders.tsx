import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import type { FindingsDirection, QueueSort } from "./remediation-queue-model"
import { defaultSortDirections } from "./remediation-queue-model"

type SortHeaderProps = {
  currentDirection: FindingsDirection
  currentSort: QueueSort
  label: string
  onSort: (sort: QueueSort) => void
  sort: QueueSort
}

export function SortHeader({
  currentDirection,
  currentSort,
  label,
  onSort,
  sort,
}: SortHeaderProps) {
  const active = currentSort === sort
  const nextDirection: FindingsDirection = active
    ? currentDirection === "asc"
      ? "desc"
      : "asc"
    : defaultSortDirections[sort]
  const Icon = active
    ? currentDirection === "asc"
      ? ArrowUp
      : ArrowDown
    : ArrowUpDown

  return (
    <Button
      aria-label={`Sort by ${label} (${active ? `${currentDirection} active` : `${nextDirection} first`})`}
      aria-pressed={active}
      className={cn(
        "-ml-1 h-7 px-1.5 text-[0.72rem] font-extrabold uppercase",
        active
          ? "text-[var(--vpw-teal)]"
          : "text-[var(--vpw-text-muted)]",
      )}
      onClick={() => onSort(sort)}
      size="sm"
      type="button"
      variant="ghost"
    >
      <Icon
        aria-hidden="true"
        className={cn(
          "size-3.5 shrink-0",
          active ? "opacity-100" : "opacity-50",
        )}
      />
      <span className="text-left leading-tight">{label}</span>
    </Button>
  )
}

export function StaticHeader({
  align = "left",
  label,
}: {
  align?: "left" | "right"
  label: string
}) {
  return (
    <span
      className={cn(
        "inline-flex h-7 items-center text-[0.72rem] font-extrabold uppercase text-[var(--vpw-text-muted)]",
        align === "right" ? "justify-end" : "justify-start",
      )}
    >
      {label}
    </span>
  )
}
