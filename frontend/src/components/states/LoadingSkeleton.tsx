import { Card, CardContent } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"

type LoadingSkeletonProps = {
  label: string
}

export function LoadingSkeleton({ label }: LoadingSkeletonProps) {
  return (
    <Card className="border-dashed" role="status" aria-label={label}>
      <CardContent className="space-y-3 p-6">
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-4 w-1/2" />
        <p className="text-sm text-[var(--vpw-text-muted)]">{label}</p>
      </CardContent>
    </Card>
  )
}
