import { Link, useNavigate } from "@tanstack/react-router"
import {
  Database,
  FileArchive,
  FileCheck2,
  FileInput,
  FolderKanban,
  LayoutDashboard,
  ListChecks,
  LogOut,
  type LucideIcon,
  Menu,
  Settings,
  ShieldCheck,
  Sidebar,
} from "lucide-react"
import { type ReactNode, useEffect, useState } from "react"
import {
  LoginService,
  type ProviderStatusPublic,
  type UserPublic,
  type WorkbenchStatus,
} from "../../api-client"
import { clearAccessToken } from "../../auth"
import {
  dataServicesSummary,
  workspaceHealthLabel,
} from "../../lib/provider-format"
import { cn } from "../../lib/utils"
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

export type WorkbenchPath =
  | "/"
  | "/projects"
  | "/imports"
  | "/findings"
  | "/waivers"
  | "/assets"
  | "/providers"
  | "/reports"
  | "/settings"

export type NavigationEntry = {
  icon: LucideIcon
  label: string
  to: WorkbenchPath
}

export type StatusSummaryItem = {
  label: string
  value: ReactNode
}

type PageHeaderProps = {
  eyebrow: string
  title: string
}

type AppShellProps = PageHeaderProps & {
  activePath: WorkbenchPath
  children: ReactNode
  currentUserLabel: string
  healthLabel: string
  hideStatusStrip?: boolean
  navigation: readonly NavigationEntry[]
  onSignOut: () => Promise<void> | void
  statusItems: readonly StatusSummaryItem[]
}

type ProductAppShellProps = PageHeaderProps & {
  activePath: WorkbenchPath
  children: ReactNode
  currentUser: UserPublic | null
  hideStatusStrip?: boolean
  providerStatus: ProviderStatusPublic | null
  status: WorkbenchStatus | null
  statusError: string
}

const sidebarStorageKey = "vpw-sidebar-collapsed"

export const workbenchNavigation: readonly NavigationEntry[] = [
  { label: "Dashboard", icon: LayoutDashboard, to: "/" },
  { label: "Projects", icon: FolderKanban, to: "/projects" },
  { label: "Imports", icon: FileInput, to: "/imports" },
  { label: "Findings", icon: ListChecks, to: "/findings" },
  { label: "Waivers", icon: FileCheck2, to: "/waivers" },
  { label: "Assets", icon: ShieldCheck, to: "/assets" },
  { label: "Providers", icon: Database, to: "/providers" },
  { label: "Reports", icon: FileArchive, to: "/reports" },
  { label: "Settings", icon: Settings, to: "/settings" },
]

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

  return (
    <TooltipProvider>
      <div className="flex min-h-dvh overflow-x-hidden bg-[var(--vpw-bg-app)]">
        {/* ── Sidebar ── */}
        <aside
          aria-label="Workbench sidebar"
          className={cn(
            "sticky top-0 hidden h-dvh max-h-dvh shrink-0 flex-col border-r border-slate-800/80 bg-[var(--vpw-navy)] transition-[width] duration-200 ease-out lg:flex",
            sidebarCollapsed ? "w-[72px]" : "w-[248px]",
          )}
        >
          {/* Brand */}
          <div
            className={cn(
              "flex h-16 shrink-0 items-center border-b border-slate-800/80",
              sidebarCollapsed ? "justify-center px-0" : "gap-3 px-4",
            )}
          >
            <div
              className={cn(
                "flex shrink-0 items-center justify-center rounded-lg bg-amber-500 font-extrabold text-slate-950",
                sidebarCollapsed ? "size-10 text-sm" : "size-9 text-xs",
              )}
            >
              VP
            </div>
            {!sidebarCollapsed ? (
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-white">
                  Vuln Prioritizer
                </p>
                <p className="truncate text-xs text-slate-300">Workbench</p>
              </div>
            ) : null}
            {!sidebarCollapsed ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    aria-label="Collapse sidebar"
                    aria-pressed={sidebarCollapsed}
                    className="ml-auto flex size-9 items-center justify-center rounded-md text-slate-400 hover:bg-white/5 hover:text-slate-200"
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
                <TooltipContent side="right">Collapse sidebar</TooltipContent>
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
                        className="mx-auto flex size-10 items-center justify-center rounded-md text-slate-400 hover:bg-white/5 hover:text-slate-200"
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
                      "flex items-center gap-2.5 rounded-md text-sm font-medium transition-colors",
                      sidebarCollapsed
                        ? "mx-auto size-10 justify-center p-0"
                        : "min-h-10 w-full px-3",
                      isActive
                        ? "bg-white/10 text-white"
                        : "text-slate-400 hover:bg-white/5 hover:text-slate-200",
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
              "flex shrink-0 items-center gap-2 border-t border-slate-800/80",
              sidebarCollapsed ? "flex-col justify-center p-2" : "p-3",
            )}
          >
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  aria-label="Account menu"
                  className={cn(
                    "h-auto min-h-10 justify-start rounded-md text-slate-400 hover:bg-white/5 hover:text-slate-200",
                    sidebarCollapsed
                      ? "size-10 justify-center p-0"
                      : "w-full px-2",
                  )}
                  type="button"
                  variant="ghost"
                >
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-slate-700 text-xs font-semibold text-slate-300">
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

        {/* ── Main area ── */}
        <main className="flex min-h-dvh min-w-0 flex-1 flex-col">
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
                  className="flex w-[min(22rem,calc(100vw-2rem))] flex-col overflow-y-auto bg-[var(--vpw-navy)] p-0 text-white"
                  side="left"
                >
                  <SheetHeader className="border-b border-slate-800/80 px-4 py-4 text-left">
                    <div className="flex items-center gap-3">
                      <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-amber-500 text-xs font-extrabold text-slate-950">
                        VP
                      </div>
                      <div className="min-w-0">
                        <SheetTitle className="truncate text-sm font-semibold text-white">
                          Vuln Prioritizer
                        </SheetTitle>
                        <SheetDescription className="truncate text-xs text-slate-400">
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
                                "flex min-h-11 items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors",
                                isActive
                                  ? "bg-white/10 text-white"
                                  : "text-slate-300 hover:bg-white/5 hover:text-white",
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
                  <div className="flex shrink-0 items-center gap-2 border-t border-slate-800/80 p-3">
                    <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-slate-700 text-xs font-semibold text-slate-300">
                      {currentUserLabel.charAt(0).toUpperCase()}
                    </span>
                    <span className="min-w-0 flex-1 truncate text-left text-xs text-slate-300">
                      {currentUserLabel}
                    </span>
                    <Button
                      aria-label="Sign out"
                      className="size-9 shrink-0 text-slate-300 hover:bg-white/5 hover:text-white"
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
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-600">
                  {eyebrow}
                </p>
                <h1 className="truncate text-base font-bold leading-tight text-slate-900">
                  {title}
                </h1>
              </div>
            </div>
            <div className="flex min-w-0 shrink-0 items-center gap-1.5">
              <div
                className={cn(
                  "size-2 rounded-full",
                  isHealthy ? "bg-green-500" : "bg-amber-500",
                )}
              />
              <span className="max-w-[8.5rem] truncate text-sm text-slate-600 sm:max-w-none">
                {healthLabel}
              </span>
            </div>
          </header>

          {/* Status strip */}
          {!hideStatusStrip && statusItems.length > 0 && (
            <div className="shrink-0 overflow-x-auto border-b border-[var(--vpw-border-subtle)] bg-white/80">
              <div className="flex min-w-max items-stretch lg:min-w-0">
                {statusItems.map((item, index) => (
                  <div
                    className={cn(
                      "flex min-w-36 flex-col justify-center px-4 py-2 lg:min-w-0 lg:px-6",
                      index > 0 && "border-l border-slate-100",
                    )}
                    key={typeof item.label === "string" ? item.label : index}
                  >
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-600">
                      {item.label}
                    </span>
                    <span className="mt-0.5 truncate text-sm font-semibold text-slate-800">
                      {item.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scrollable content */}
          <section
            aria-label="Workbench page content"
            className="min-w-0 flex-1"
          >
            <div className="vpw-page-container py-6">{children}</div>
          </section>
        </main>
      </div>
    </TooltipProvider>
  )
}

export function ProductAppShell({
  activePath,
  children,
  currentUser,
  eyebrow,
  hideStatusStrip = false,
  providerStatus,
  status,
  statusError,
  title,
}: ProductAppShellProps) {
  const navigate = useNavigate()

  async function signOut() {
    try {
      await LoginService.logoutCurrentToken()
    } catch {
      // Local logout should complete even if the server session already expired.
    } finally {
      clearAccessToken()
      if (typeof window !== "undefined") {
        window.location.assign("/login")
      } else {
        await navigate({ replace: true, search: {} as never, to: "/login" })
      }
    }
  }

  return (
    <AppShell
      activePath={activePath}
      currentUserLabel={currentUserLabel(currentUser)}
      eyebrow={eyebrow}
      healthLabel={workspaceHealthLabel(status, statusError)}
      hideStatusStrip={hideStatusStrip}
      navigation={workbenchNavigation}
      onSignOut={signOut}
      statusItems={dataServicesSummary(status, providerStatus)}
      title={title}
    >
      {children}
    </AppShell>
  )
}

function currentUserLabel(user: UserPublic | null) {
  return user?.email ?? "Local workspace"
}
