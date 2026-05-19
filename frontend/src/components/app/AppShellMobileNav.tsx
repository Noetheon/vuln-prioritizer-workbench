import { Link } from "@/lib/router"
import { Menu } from "lucide-react"
import type { Dispatch, RefObject, SetStateAction } from "react"
import { cn } from "../../lib/utils"
import type {
  NavigationGroup,
  WorkbenchPath,
} from "../../lib/workbench-navigation"
import { Button } from "../ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "../ui/sheet"

type AppShellMobileNavProps = {
  activePath: WorkbenchPath | null
  mobileNavButtonRef: RefObject<HTMLButtonElement | null>
  mobileNavOpen: boolean
  navigationGroups: readonly NavigationGroup[]
  setMobileNavOpen: Dispatch<SetStateAction<boolean>>
  workspaceInitial: string
  workspaceLabel: string
}

export function AppShellMobileNav({
  activePath,
  mobileNavButtonRef,
  mobileNavOpen,
  navigationGroups,
  setMobileNavOpen,
  workspaceInitial,
  workspaceLabel,
}: AppShellMobileNavProps) {
  return (
    <Sheet open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
      <SheetTrigger asChild>
        <Button
          aria-label="Open navigation"
          className="mt-0.5 size-9 shrink-0 border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] text-[var(--vpw-text-secondary)] lg:hidden"
          ref={mobileNavButtonRef}
          size="icon"
          type="button"
          variant="outline"
        >
          <Menu aria-hidden="true" size={18} />
        </Button>
      </SheetTrigger>
      <SheetContent
        className="flex w-[min(22rem,calc(100vw-2rem))] flex-col overflow-y-auto bg-[var(--vpw-bg-page)] p-0 text-[var(--vpw-text-primary)]"
        onCloseAutoFocus={(event) => {
          event.preventDefault()
          mobileNavButtonRef.current?.focus({ preventScroll: true })
        }}
        side="left"
      >
        <SheetHeader className="border-b border-[var(--vpw-border-default)] px-4 py-4 text-left">
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-text-primary)] text-xs font-extrabold text-[var(--vpw-bg-card)]">
              VP
            </div>
            <div className="min-w-0">
              <SheetTitle className="truncate text-sm font-semibold text-[var(--vpw-text-primary)]">
                Vuln Prioritizer
              </SheetTitle>
              <SheetDescription className="truncate text-xs text-[var(--vpw-text-muted)]">
                Workbench
              </SheetDescription>
            </div>
          </div>
        </SheetHeader>
        <nav aria-label="Workbench mobile navigation" className="flex-1 p-2">
          <ul className="flex flex-col gap-3">
            {navigationGroups.map((group) => (
              <li key={group.label}>
                <p className="px-3 pb-1 text-[10px] font-bold uppercase text-[var(--vpw-text-muted)]">
                  {group.label}
                </p>
                <ul className="flex flex-col gap-1">
                  {group.items.map((entry) => {
                    const isActive = activePath === entry.to
                    return (
                      <li key={entry.label}>
                        <Link
                          aria-current={isActive ? "page" : undefined}
                          className={cn(
                            "flex min-h-11 items-center gap-3 rounded-[var(--vpw-radius-md)] px-3 text-sm font-medium transition-colors",
                            isActive
                              ? "bg-[var(--vpw-text-primary)] text-[var(--vpw-bg-card)]"
                              : "text-[var(--vpw-text-secondary)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]",
                          )}
                          onClick={() => setMobileNavOpen(false)}
                          to={entry.to}
                        >
                          <entry.icon
                            aria-hidden="true"
                            className="shrink-0"
                            size={17}
                          />
                          <span className="truncate">{entry.label}</span>
                        </Link>
                      </li>
                    )
                  })}
                </ul>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex shrink-0 items-center gap-2 border-t border-[var(--vpw-border-default)] p-3">
          <span className="flex size-8 shrink-0 items-center justify-center rounded-full border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] text-xs font-semibold text-[var(--vpw-text-secondary)]">
            {workspaceInitial}
          </span>
          <span className="min-w-0 flex-1 truncate text-left text-xs text-[var(--vpw-text-secondary)]">
            {workspaceLabel}
          </span>
        </div>
      </SheetContent>
    </Sheet>
  )
}
