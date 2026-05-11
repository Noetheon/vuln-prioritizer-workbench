import { Link } from "@tanstack/react-router"
import {
  LogOut,
  Menu,
  Sidebar,
} from "lucide-react"
import { type ReactNode, useEffect, useState } from "react"
import { cn } from "../../lib/utils"
import type { NavigationEntry, WorkbenchPath } from "../../lib/workbench-navigation"
import { Button } from "../ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "../ui/sheet"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "../ui/tooltip"

export type StatusSummaryItem = {
  label: string
  value: ReactNode
}

type PageHeaderProps = {
  eyebrow: string
  title: string
}

type AppShellProps = PageHeaderProps & {
  activePath: WorkbenchPath | null
  children: ReactNode
  currentUserLabel: string
  healthLabel: string
  hideStatusStrip?: boolean
  navigation: readonly NavigationEntry[]
  onSignOut: () => Promise<void> | void
  statusItems: readonly StatusSummaryItem[]
}

const sidebarStorageKey = "vpw-sidebar-collapsed"

function compactHealthLabel(healthLabel: string, isHealthy: boolean) {
  const normalizedHealthLabel = healthLabel.toLowerCase()
  if (isHealthy) return "Healthy"
  if (normalizedHealthLabel.includes("degraded")) return "Degraded"
  if (normalizedHealthLabel.includes("checking")) return "Checking"
  return "Issue"
}

export function AppShell({
  activePath,
  children,
  currentUserLabel,
  eyebrow,
  healthLabel,
  hideStatusStrip = false,
  navigation,
  onSignOut,
  statusItems,
  title,
}: AppShellProps) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (typeof window === "undefined") return false
    return window.localStorage.getItem(sidebarStorageKey) === "true"
  })

  useEffect(() => {
    window.localStorage.setItem(sidebarStorageKey, String(sidebarCollapsed))
  }, [sidebarCollapsed])

  const isHealthy =
    !healthLabel.toLowerCase().includes("unavailable") &&
    !healthLabel.toLowerCase().includes("error") &&
    !healthLabel.toLowerCase().includes("degraded")
  const mobileHealthLabel = compactHealthLabel(healthLabel, isHealthy)

  return (
    <TooltipProvider>
      <div className="vpw-app-shell flex h-dvh min-h-dvh overflow-hidden bg-[var(--vpw-bg-app)]">
        {/* Sidebar */}
        <aside
          aria-label="Workbench sidebar"
          className={cn(
            "hidden h-dvh max-h-dvh shrink-0 flex-col border-r border-[var(--vpw-border-default)] bg-[var(--vpw-bg-page)] transition-[width] duration-200 ease-out lg:flex",
            sidebarCollapsed ? "w-[72px]" : "w-[248px]",
          )}
        >
          {/* Brand */}
          <div
            className={cn(
              "flex h-16 shrink-0 items-center border-b border-[var(--vpw-border-default)]",
              sidebarCollapsed ? "justify-center px-0" : "gap-3 px-4",
            )}
          >
            <div
              className={cn(
                "flex shrink-0 items-center justify-center rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-text-primary)] font-extrabold text-[var(--vpw-bg-card)]",
                sidebarCollapsed ? "size-10 text-sm" : "size-9 text-xs",
              )}
            >
              VP
            </div>
            {!sidebarCollapsed ? (
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-[var(--vpw-text-primary)]">
                  Vuln Prioritizer
                </p>
                <p className="truncate text-xs text-[var(--vpw-text-muted)]">
                  Workbench
                </p>
              </div>
            ) : null}
            {!sidebarCollapsed ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    aria-label="Collapse sidebar"
                    aria-pressed={sidebarCollapsed}
                    className="ml-auto flex size-9 items-center justify-center rounded-[var(--vpw-radius-md)] text-[var(--vpw-text-muted)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]"
                    onClick={() =>
                      setSidebarCollapsed((collapsed) => !collapsed)
                    }
                    size="icon"
                    type="button"
                    variant="ghost"
                  >
                    <Sidebar aria-hidden="true" size={16} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent align="end" side="bottom" sideOffset={8}>
                  Collapse sidebar
                </TooltipContent>
              </Tooltip>
            ) : null}
          </div>

          {/* Nav */}
          <nav
            aria-label="Workbench navigation"
            className="min-h-0 flex-1 overflow-y-auto p-2"
          >
            <ul className="flex flex-col gap-1">
              {sidebarCollapsed ? (
                <li>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        aria-label="Expand sidebar"
                        aria-pressed={sidebarCollapsed}
                        className="mx-auto flex size-10 items-center justify-center rounded-[var(--vpw-radius-md)] text-[var(--vpw-text-muted)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]"
                        onClick={() =>
                          setSidebarCollapsed((collapsed) => !collapsed)
                        }
                        size="icon"
                        type="button"
                        variant="ghost"
                      >
                        <Sidebar aria-hidden="true" size={16} />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent side="right">Expand sidebar</TooltipContent>
                  </Tooltip>
                </li>
              ) : null}
              {navigation.map((entry) => {
                const isActive = activePath === entry.to
                const navLink = (
                  <Link
                    aria-current={isActive ? "page" : undefined}
                    aria-label={sidebarCollapsed ? entry.label : undefined}
                    className={cn(
                      "flex items-center gap-2.5 rounded-[var(--vpw-radius-md)] text-sm font-medium transition-colors",
                      sidebarCollapsed
                        ? "mx-auto size-10 justify-center p-0"
                        : "min-h-10 w-full px-3",
                      isActive
                        ? "bg-[var(--vpw-text-primary)] text-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-1)]"
                        : "text-[var(--vpw-text-secondary)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]",
                    )}
                    to={entry.to}
                  >
                    <entry.icon
                      aria-hidden="true"
                      className="shrink-0"
                      size={16}
                    />
                    {!sidebarCollapsed ? (
                      <span className="truncate">{entry.label}</span>
                    ) : null}
                  </Link>
                )

                return (
                  <li key={entry.label}>
                    {sidebarCollapsed ? (
                      <Tooltip>
                        <TooltipTrigger asChild>{navLink}</TooltipTrigger>
                        <TooltipContent side="right">
                          {entry.label}
                        </TooltipContent>
                      </Tooltip>
                    ) : (
                      navLink
                    )}
                  </li>
                )
              })}
            </ul>
          </nav>

          {/* Footer */}
          <div
            className={cn(
              "flex shrink-0 items-center gap-2 border-t border-[var(--vpw-border-default)]",
              sidebarCollapsed ? "flex-col justify-center p-2" : "p-3",
            )}
          >
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  aria-label="Account menu"
                  className={cn(
                    "h-auto min-h-10 justify-start rounded-[var(--vpw-radius-md)] text-[var(--vpw-text-secondary)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]",
                    sidebarCollapsed
                      ? "size-10 justify-center p-0"
                      : "w-full px-2",
                  )}
                  type="button"
                  variant="ghost"
                >
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-full border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] text-xs font-semibold text-[var(--vpw-text-secondary)]">
                    {currentUserLabel.charAt(0).toUpperCase()}
                  </span>
                  {!sidebarCollapsed ? (
                    <span className="min-w-0 flex-1 truncate text-left text-xs">
                      {currentUserLabel}
                    </span>
                  ) : null}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="end"
                className="w-56"
                collisionPadding={16}
                side="right"
                sideOffset={8}
              >
                <DropdownMenuLabel>
                  <span className="block text-sm">Account</span>
                  <span className="block truncate text-muted-foreground text-xs font-normal">
                    {currentUserLabel}
                  </span>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuGroup>
                  <DropdownMenuItem onSelect={() => void onSignOut()}>
                    <LogOut aria-hidden="true" size={14} />
                    Sign out
                  </DropdownMenuItem>
                </DropdownMenuGroup>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </aside>

        {/* Main area */}
        <main className="flex h-dvh min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          {/* Topbar */}
          <header className="flex min-h-14 shrink-0 items-center justify-between gap-3 border-b border-[var(--vpw-border-default)] bg-[var(--vpw-bg-page)] px-4 py-3 lg:h-14 lg:px-6 lg:py-0">
            <div className="flex min-w-0 items-center gap-3">
              <Sheet open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
                <SheetTrigger asChild>
                  <Button
                    aria-label="Open navigation"
                    className="size-9 border-[var(--vpw-border-default)] text-[var(--vpw-text-secondary)] lg:hidden"
                    size="icon"
                    type="button"
                    variant="outline"
                  >
                    <Menu aria-hidden="true" size={18} />
                  </Button>
                </SheetTrigger>
                <SheetContent
                  className="flex w-[min(22rem,calc(100vw-2rem))] flex-col overflow-y-auto bg-[var(--vpw-bg-page)] p-0 text-[var(--vpw-text-primary)]"
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
                  <nav
                    aria-label="Workbench mobile navigation"
                    className="flex-1 p-2"
                  >
                    <ul className="flex flex-col gap-1">
                      {navigation.map((entry) => {
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
                  </nav>
                  <div className="flex shrink-0 items-center gap-2 border-t border-[var(--vpw-border-default)] p-3">
                    <span className="flex size-8 shrink-0 items-center justify-center rounded-full border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] text-xs font-semibold text-[var(--vpw-text-secondary)]">
                      {currentUserLabel.charAt(0).toUpperCase()}
                    </span>
                    <span className="min-w-0 flex-1 truncate text-left text-xs text-[var(--vpw-text-secondary)]">
                      {currentUserLabel}
                    </span>
                    <Button
                      aria-label="Sign out"
                      className="size-9 shrink-0 text-[var(--vpw-text-secondary)] hover:bg-[var(--vpw-bg-panel)] hover:text-[var(--vpw-text-primary)]"
                      onClick={() => void onSignOut()}
                      size="icon"
                      type="button"
                      variant="ghost"
                    >
                      <LogOut aria-hidden="true" size={15} />
                    </Button>
                  </div>
                </SheetContent>
              </Sheet>
              <div className="min-w-0">
                <p className="text-[10px] font-bold uppercase text-[var(--vpw-text-muted)]">
                  {eyebrow}
                </p>
                <h1 className="truncate text-base font-bold leading-tight text-[var(--vpw-text-primary)]">
                  {title}
                </h1>
              </div>
            </div>
            <div
              aria-label={`Workspace health: ${healthLabel}`}
              className="flex min-w-0 shrink-0 items-center gap-1.5"
              role="status"
            >
              <div
                className={cn(
                  "size-2 rounded-full",
                  isHealthy ? "bg-[var(--vpw-green)]" : "bg-[var(--vpw-amber)]",
                )}
              />
              <span className="text-sm text-[var(--vpw-text-muted)] sm:hidden">
                {mobileHealthLabel}
              </span>
              <span className="hidden text-sm text-[var(--vpw-text-muted)] sm:inline">
                {healthLabel}
              </span>
            </div>
          </header>

          {/* Status strip */}
          {!hideStatusStrip && statusItems.length > 0 && (
            <section
              aria-label="Workbench status summary"
              className="shrink-0 border-b border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-page)]"
            >
              <div className="grid grid-cols-2 items-stretch lg:flex lg:min-w-0">
                {statusItems.map((item, index) => (
                  <div
                    className={cn(
                      "flex min-w-0 flex-col justify-center px-4 py-2 lg:min-w-0 lg:px-6",
                      index % 2 === 1 &&
                        "border-l border-[var(--vpw-border-subtle)]",
                      index > 1 &&
                        "border-t border-[var(--vpw-border-subtle)] lg:border-t-0",
                      index > 0 &&
                        "lg:border-l lg:border-[var(--vpw-border-subtle)]",
                    )}
                    key={typeof item.label === "string" ? item.label : index}
                  >
                    <span className="text-[10px] font-bold uppercase text-[var(--vpw-text-muted)]">
                      {item.label}
                    </span>
                    <span className="mt-0.5 truncate text-sm font-semibold text-[var(--vpw-text-primary)]">
                      {item.value}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Scrollable content */}
          <section
            aria-label="Workbench page content"
            className="min-h-0 min-w-0 flex-1 overflow-y-auto"
            // biome-ignore lint/a11y/noNoninteractiveTabindex: Axe requires keyboard focus for the app's internal scroll region.
            tabIndex={0}
          >
            <div className="vpw-page-container py-6">{children}</div>
          </section>
        </main>
      </div>
    </TooltipProvider>
  )
}
