import { ShieldCheck } from "lucide-react"

import { cn } from "@/lib/utils"

import { VpwBadge } from "./VpwBadge"

export type VpwChecksumProps = {
  value: string
  className?: string
  demo?: boolean
  label?: string
  verified?: boolean
}

export function VpwChecksum({
  className,
  demo = false,
  label = "SHA256",
  value,
  verified = false,
}: VpwChecksumProps) {
  return (
    <div
      className={cn(
        "flex flex-col gap-2 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3 sm:flex-row sm:items-center sm:justify-between",
        className,
      )}
    >
      <div className="min-w-0">
        <p className="vpw-label">{label}</p>
        <p className="mt-1 truncate font-mono text-xs text-[var(--vpw-text-primary)]">
          {value}
        </p>
      </div>
      <VpwBadge tone={demo ? "warning" : verified ? "success" : "neutral"}>
        <ShieldCheck aria-hidden="true" className="h-3 w-3" />
        {demo ? "Demo" : verified ? "Verified" : "Recorded"}
      </VpwBadge>
    </div>
  )
}
