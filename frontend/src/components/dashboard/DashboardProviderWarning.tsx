import { AlertCircle } from "lucide-react"
import {
  VpwSurface,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { Link } from "@/lib/router"

export function DashboardProviderWarning({ detail }: { detail: string }) {
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
          {detail} Remediation priority remains functional, but evidence may not
          be fully current.{" "}
          <Link
            className="font-medium text-[var(--vpw-text-primary)] underline underline-offset-4"
            to="/providers"
          >
            Open Data Sources
          </Link>
        </VpwSurfaceDescription>
      </VpwSurfaceHeader>
    </VpwSurface>
  )
}
