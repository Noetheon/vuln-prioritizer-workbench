import { AlertCircle } from "lucide-react"
import { VpwBadge } from "@/components/vpw"
import { cn } from "@/lib/utils"

export type DataQualityNoticeItem = {
  detail: string
  label: string
  message: string
}

type DataQualityNoticeProps = {
  items: readonly DataQualityNoticeItem[]
  className?: string
}

export function DataQualityNotice({
  items,
  className,
}: DataQualityNoticeProps) {
  if (items.length === 0) return null

  return (
    <ul className={cn("flex flex-col gap-2", className)}>
      {items.map((item) => (
        <li
          className="flex gap-3 rounded-[var(--vpw-radius-md)] border border-[color-mix(in_srgb,var(--vpw-amber)_38%,var(--vpw-bg-card))] bg-[var(--vpw-bg-warning)] px-3 py-2"
          key={`${item.label}:${item.detail}:${item.message}`}
        >
          <AlertCircle
            aria-hidden="true"
            className="mt-0.5 size-4 shrink-0 text-[var(--vpw-amber)]"
          />
          <div className="flex min-w-0 flex-col gap-0.5">
            <div className="flex items-center gap-2">
              <VpwBadge className="text-xs" tone="warning">
                {item.label}
              </VpwBadge>
              <span className="text-xs text-[var(--vpw-text-muted)]">
                {item.detail}
              </span>
            </div>
            <p className="text-xs leading-relaxed text-[var(--vpw-text-secondary)]">
              {item.message}
            </p>
          </div>
        </li>
      ))}
    </ul>
  )
}
