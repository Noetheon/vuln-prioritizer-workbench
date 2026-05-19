import { Skeleton } from "@/components/ui/skeleton"
import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"

export function DashboardSignalOverviewFallback() {
  return (
    <VpwSurface aria-label="Signal Overview loading" className="gap-4 py-4">
      <VpwSurfaceHeader>
        <VpwSurfaceTitle>Signal Overview</VpwSurfaceTitle>
        <VpwSurfaceDescription>
          Signal concentration, service risk, and trend direction for executive
          review.
        </VpwSurfaceDescription>
      </VpwSurfaceHeader>
      <VpwSurfaceBody>
        <div
          aria-label="Loading Signal Overview charts"
          className="flex flex-col gap-4"
          role="status"
        >
          <div className="flex flex-wrap gap-2">
            <Skeleton className="h-8 w-36" />
            <Skeleton className="h-8 w-32" />
            <Skeleton className="h-8 w-28" />
            <Skeleton className="h-8 w-24" />
          </div>
          <Skeleton className="h-64 w-full" />
        </div>
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
