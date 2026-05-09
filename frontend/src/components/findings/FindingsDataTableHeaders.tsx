import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react"

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
    <button
      aria-label={`Sort by ${label} (${active ? `${currentDirection} active` : `${nextDirection} first`})`}
      aria-pressed={active}
      className={cn(
        "-ml-1 inline-flex h-7 items-center gap-1 rounded-md px-1.5 text-[0.72rem] font-extrabold uppercase text-inherit transition hover:bg-slate-100 hover:text-slate-900",
        active ? "text-teal-700" : "text-slate-500",
      )}
      onClick={() => onSort(sort)}
      type="button"
    >
      <Icon
        aria-hidden="true"
        className={cn(
          "size-3.5 shrink-0",
          active ? "opacity-100" : "opacity-50",
        )}
      />
      <span className="text-left leading-tight">{label}</span>
    </button>
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
        "inline-flex h-7 items-center text-[0.72rem] font-extrabold uppercase text-slate-500",
        align === "right" ? "justify-end" : "justify-start",
      )}
    >
      {label}
    </span>
  )
}
