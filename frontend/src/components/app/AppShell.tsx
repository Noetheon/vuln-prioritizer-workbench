import { type ReactNode, useEffect, useRef, useState } from "react"
import { cn } from "../../lib/utils"
import type {
  NavigationGroup,
  WorkbenchPath,
} from "../../lib/workbench-navigation"
import { TooltipProvider } from "../ui/tooltip"
import { AppShellMobileNav } from "./AppShellMobileNav"
import { AppShellSidebar } from "./AppShellSidebar"
import { AppShellStatusStrip } from "./AppShellStatusStrip"
import { useWorkbenchScrollOwner } from "./useWorkbenchScrollOwner"

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
  const scrollOwnerHandlers = useWorkbenchScrollOwner(contentRef)

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
      <div
        className="vpw-app-shell flex h-dvh min-h-dvh overflow-hidden bg-[var(--vpw-bg-app)]"
        {...scrollOwnerHandlers}
      >
        <AppShellSidebar
          activePath={activePath}
          navigationGroups={navigationGroups}
          setSidebarCollapsed={setSidebarCollapsed}
          sidebarCollapsed={sidebarCollapsed}
          workspaceInitial={workspaceInitial}
          workspaceLabel={workspaceLabel}
        />

        <main className="flex h-dvh min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          <header className="shrink-0 bg-[var(--vpw-bg-app)] pt-5 pb-3 sm:pt-6 sm:pb-4">
            <div className="vpw-page-container flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex min-w-0 items-start gap-3 sm:flex-1">
                <AppShellMobileNav
                  activePath={activePath}
                  mobileNavButtonRef={mobileNavButtonRef}
                  mobileNavOpen={mobileNavOpen}
                  navigationGroups={navigationGroups}
                  setMobileNavOpen={setMobileNavOpen}
                  workspaceInitial={workspaceInitial}
                  workspaceLabel={workspaceLabel}
                />
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

          <AppShellStatusStrip
            hideStatusStrip={hideStatusStrip}
            statusItems={statusItems}
          />

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
