import { cn } from "@/lib/utils"

interface PageHeaderProps {
  eyebrow?: string
  title: string
  description?: string
  className?: string
}

export function PageHeader({ eyebrow, title, description, className }: PageHeaderProps) {
  return (
    <div className={cn("space-y-2", className)}>
      {eyebrow && (
        <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          {eyebrow}
        </span>
      )}
      <h1 className="text-3xl font-bold tracking-tight text-foreground">{title}</h1>
      {description && (
        <p className="text-base text-muted-foreground max-w-2xl">{description}</p>
      )}
    </div>
  )
}
