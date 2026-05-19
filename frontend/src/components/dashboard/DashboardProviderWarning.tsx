import { AlertCircle } from "lucide-react"
import {
  VpwSurface,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"

export function DashboardProviderWarning() {
  return (
    <VpwSurface className="border-[var(--vpw-amber)] bg-[var(--vpw-bg-warning)]">
      <VpwSurfaceHeader className="py-3">
        <div className="flex items-center gap-2">
          <AlertCircle
            className="size-4 text-[var(--vpw-amber)]"
            aria-hidden="true"
          />
          <VpwSurfaceTitle className="text-sm text-[var(--vpw-text-primary)]">
            Provider data needs refresh
          </VpwSurfaceTitle>
        </div>
        <VpwSurfaceDescription className="text-xs text-[var(--vpw-text-secondary)]">
          Freshness is stale or partially degraded. Remediation priority remains
          functional, but evidence may not be fully current.
        </VpwSurfaceDescription>
      </VpwSurfaceHeader>
    </VpwSurface>
  )
}
