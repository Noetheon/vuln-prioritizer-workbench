import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import type * as React from "react"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-[var(--vpw-radius-md)] text-sm font-medium outline-none transition-all focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default:
          "bg-[var(--vpw-blue)] text-primary-foreground shadow-[var(--vpw-shadow-1)] hover:bg-[var(--vpw-blue)]/90",
        destructive:
          "bg-[var(--vpw-red)] text-white hover:bg-[var(--vpw-red)]/90",
        outline:
          "border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-1)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]",
        secondary:
          "bg-[var(--vpw-bg-panel)] text-[var(--vpw-text-primary)] hover:bg-[var(--vpw-border-subtle)]",
        ghost:
          "text-[var(--vpw-text-secondary)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]",
        link: "text-[var(--vpw-blue)] underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 rounded-[var(--vpw-radius-md)] px-3",
        lg: "h-10 rounded-[var(--vpw-radius-md)] px-6",
        icon: "size-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
)

function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot : "button"

  return (
    <Comp
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
