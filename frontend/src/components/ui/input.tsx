import type * as React from "react"

import { cn } from "@/lib/utils"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "vpw-input-control h-9 w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-1 shadow-xs outline-none transition-[color,box-shadow] selection:bg-primary selection:text-primary-foreground file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50 dark:bg-input/30",
        "border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] text-[var(--vpw-text-primary)] shadow-none placeholder:text-[var(--vpw-text-muted)]",
        "focus-visible:border-[var(--vpw-blue)] focus-visible:ring-[3px] focus-visible:ring-[color-mix(in_srgb,var(--vpw-blue)_14%,transparent)]",
        "aria-invalid:border-[var(--vpw-red)] aria-invalid:ring-[color-mix(in_srgb,var(--vpw-red)_18%,transparent)]",
        className,
      )}
      {...props}
    />
  )
}

export { Input }
