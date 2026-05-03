import { cn } from "@/lib/utils"

function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "animate-pulse rounded-[var(--vpw-radius-md)] bg-[var(--vpw-border-subtle)]",
        className,
      )}
      {...props}
    />
  )
}

export { Skeleton }
