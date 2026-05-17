import { Link } from "@/lib/router"
import { Menu, Sidebar } from "lucide-react"
import { type ReactNode, useEffect, useRef, useState } from "react"
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
  description: string
  eyebrow: string
  title: string
}

type AppShellProps = PageHeaderProps & {
  activePath: WorkbenchPath | null
  children: ReactNode
  healthLabel: string
  hideStatusStrip?: boolean
  navigationGroups: readonly NavigationGroup[]
  navigationKey: string
  statusItems: readonly StatusSummaryItem[]
  workspaceLabel: string
}

const sidebarStorageKey = "vpw-sidebar-collapsed"

function compactHealthLabel(healthLabel: string, isHealthy: boolean) {
  const normalizedHealthLabel = healthLabel.toLowerCase()
  if (isHealthy) return "Healthy"
  if (normalizedHealthLabel.includes("degraded")) return "Degraded"
  if (normalizedHealthLabel.includes("checking")) return "Checking"
  return "Issue"
}

function readSidebarCollapsed() {
  if (typeof window === "undefined") return false
  try {
    return window.localStorage.getItem(sidebarStorageKey) === "true"
  } catch {
    return false
  }
}

function writeSidebarCollapsed(collapsed: boolean) {
  if (typeof window === "undefined") return
  try {
    window.localStorage.setItem(sidebarStorageKey, String(collapsed))
  } catch {
    // Ignore blocked storage; the in-memory state still controls this session.
  }
}

export function AppShell({
  activePath,
  children,
  description,
  eyebrow,
  healthLabel,
  hideStatusStrip = false,
  navigationGroups,
  navigationKey,
  statusItems,
  title,
  workspaceLabel,
}: AppShellProps) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(readSidebarCollapsed)
  const contentRef = useRef<HTMLElement | null>(null)
  const lastNavigationKeyRef = useRef<string | null>(null)
  const mobileNavButtonRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    writeSidebarCollapsed(sidebarCollapsed)
  }, [sidebarCollapsed])

  useEffect(() => {
    if (lastNavigationKeyRef.current === null) {
      lastNavigationKeyRef.current = navigationKey
      return
    }
    if (lastNavigationKeyRef.current === navigationKey) return
    lastNavigationKeyRef.current = navigationKey
    if (navigationKey.length === 0) return
    const content = contentRef.current
    if (!content) return
    content.scrollTop = 0
    content.scrollLeft = 0
    if (typeof document === "undefined") return
    const activeElement = document.activeElement
    if (activeElement && activeElement !== document.body) {
      content.focus({ preventScroll: true })
    }
  }, [navigationKey])

  const isHealthy =
    !healthLabel.toLowerCase().includes("unavailable") &&
    !healthLabel.toLowerCase().includes("error") &&
    !healthLabel.toLowerCase().includes("degraded")
  const mobileHealthLabel = compactHealthLabel(healthLabel, isHealthy)
  const workspaceInitial = workspaceLabel.charAt(0).toUpperCase()

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
              {navigationGroups.map((group) => (
                <li key={group.label}>
                  {!sidebarCollapsed ? (
                    <p className="px-3 pb-1 pt-3 text-[10px] font-bold uppercase text-[var(--vpw-text-muted)]">
                      {group.label}
                    </p>
                  ) : null}
                  <ul className="flex flex-col gap-1">
                    {group.items.map((entry) => {
                      const isActive = activePath === entry.to
                      const navLink = (
                        <Link
                          aria-current={isActive ? "page" : undefined}
                          aria-label={
                            sidebarCollapsed ? entry.label : undefined
                          }
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
                </li>
              ))}
            </ul>
          </nav>

          {/* Footer */}
          <div
            className={cn(
              "flex shrink-0 items-center gap-2 border-t border-[var(--vpw-border-default)]",
              sidebarCollapsed ? "flex-col justify-center p-2" : "p-3",
            )}
          >
            <div
              aria-label="Local workspace status"
              className={cn(
                "flex h-auto min-h-10 items-center justify-start rounded-[var(--vpw-radius-md)] px-2 text-[var(--vpw-text-secondary)]",
                sidebarCollapsed ? "size-10 justify-center p-0" : "w-full",
              )}
              role="status"
            >
              <span className="flex size-8 shrink-0 items-center justify-center rounded-full border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] text-xs font-semibold text-[var(--vpw-text-secondary)]">
                {workspaceInitial}
              </span>
              {!sidebarCollapsed ? (
                <span className="min-w-0 flex-1 truncate pl-2 text-left text-xs">
                  {workspaceLabel}
                </span>
              ) : null}
            </div>
          </div>
        </aside>

        {/* Main area */}
        <main className="flex h-dvh min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          {/* Page header */}
          <header className="shrink-0 bg-[var(--vpw-bg-app)] pt-5 pb-3 sm:pt-6 sm:pb-4">
            <div className="vpw-page-container flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex min-w-0 items-start gap-3 sm:flex-1">
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
                      mobileNavButtonRef.current?.focus({
                        preventScroll: true,
                      })
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
                    <nav
                      aria-label="Workbench mobile navigation"
                      className="flex-1 p-2"
                    >
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
                                      aria-current={
                                        isActive ? "page" : undefined
                                      }
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
                                      <span className="truncate">
                                        {entry.label}
                                      </span>
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
                <div className="min-w-0">
                  <p className="sr-only">{eyebrow}</p>
                  <h1 className="text-2xl font-semibold leading-tight text-[var(--vpw-text-primary)] sm:text-[1.625rem]">
                    {title}
                  </h1>
                  <p className="mt-1 max-w-[52rem] text-sm leading-5 text-[var(--vpw-text-muted)] sm:leading-6">
                    {description}
                  </p>
                </div>
              </div>
              <div
                aria-label={`Workspace health: ${healthLabel}`}
                className="flex min-w-0 shrink-0 items-center gap-1.5 sm:mt-1"
                role="status"
              >
                <div
                  className={cn(
                    "size-2 rounded-full",
                    isHealthy
                      ? "bg-[var(--vpw-green)]"
                      : "bg-[var(--vpw-amber)]",
                  )}
                />
                <span className="text-sm text-[var(--vpw-text-muted)] sm:hidden">
                  {mobileHealthLabel}
                </span>
                <span className="hidden text-sm text-[var(--vpw-text-muted)] sm:inline">
                  {healthLabel}
                </span>
              </div>
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
            ref={contentRef}
            // biome-ignore lint/a11y/noNoninteractiveTabindex: This is the app's keyboard-scroll owner.
            tabIndex={0}
          >
            <div className="vpw-page-container pt-2 pb-6">{children}</div>
          </section>
        </main>
      </div>
    </TooltipProvider>
  )
}
