import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

export type VpwSkeletonStackProps = {
  className?: string
  rows?: number
}

export function VpwSkeletonStack({
  className,
  rows = 4,
}: VpwSkeletonStackProps) {
  const rowKeys = Array.from(
    { length: rows },
    (_, index) => `skeleton-${index}`,
  )

  return (
    <div
      aria-label="Loading"
      className={cn("space-y-3", className)}
      role="status"
    >
      {rowKeys.map((key, index) => (
        <Skeleton
          className={cn(
            "h-4",
            index % 4 === 1 && "w-5/6",
            index % 4 === 2 && "w-2/3",
            index % 4 === 3 && "w-1/2",
          )}
          key={key}
        />
      ))}
    </div>
  )
}
