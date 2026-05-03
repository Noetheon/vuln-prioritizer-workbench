import { AlertTriangle } from "lucide-react"
import type { ReactNode } from "react"

export type VpwDemoBannerProps = {
  children: ReactNode
}

export function VpwDemoBanner({ children }: VpwDemoBannerProps) {
  return (
    <div className="vpw-demo-banner" role="status">
      <AlertTriangle
        className="h-4 w-4 shrink-0 text-[var(--vpw-amber)]"
        aria-hidden="true"
      />
      <div>{children}</div>
    </div>
  )
}
